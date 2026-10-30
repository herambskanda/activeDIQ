package audit

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Job kinds of the audit trail (ADR-0005 rule 11).
const (
	// JobCheckpoint signs the tenant's chain head on cadence, under a lease.
	JobCheckpoint = "audit.checkpoint"
	// JobForward ships a tenant's events and checkpoints to one SIEM sink.
	JobForward = "audit.forward"
)

// Cadence defaults (ADR-0005 rule 11: every 1,000 events or 5 minutes, if anything new was appended).
const (
	DefaultCheckpointEvents = 1000
	DefaultCheckpointMaxAge = 5 * time.Minute
	DefaultCheckpointTick   = 30 * time.Second
	DefaultForwardTick      = 15 * time.Second
	forwardBatch            = 500
	leaseTTL                = 2 * time.Minute
	forwardMaxAttempts      = 6
)

// Failure codes stored on a failed job. A code, never text: a sink's reply can echo a credential.
const (
	CodeCheckpointFailed = "checkpoint_failed"
	CodeSinkUnavailable  = "sink_unavailable"
	CodeForwardFailed    = "forward_failed"
	CodeBadArgs          = "bad_args"
)

var sinkPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// RecordKind says what a forwarded Record carries.
type RecordKind string

const (
	// RecordEvent is a chained event; key events (audit.key.created / retired) are events.
	RecordEvent RecordKind = "event"
	// RecordCheckpoint is a signed checkpoint, sent as its own message (it is an external anchor).
	RecordCheckpoint RecordKind = "checkpoint"
)

// Record is one message for a sink. Exactly the field named by Kind is set.
type Record struct {
	Kind       RecordKind
	Seq        uint64
	Event      chain.StoredEvent
	Checkpoint chain.Checkpoint
}

// ForwardSink is an EP-9 sink as audit.forward sees it. Deliver sends a batch in chain order and returns
// nil only when the sink has acknowledged all of it; the cursor advances on nil and on nothing else.
// Delivery is at least once, so a sink de-duplicates by Seq (events and checkpoints have separate
// sequences: a checkpoint's Seq is the head it signed). An error must not carry the sink's reply.
type ForwardSink interface {
	Deliver(ctx context.Context, id tenant.ID, batch []Record) error
}

// SinkResolver finds the configured sink for a tenant. ok is false when the sink is gone: the cadence
// of that tenant and sink then ends (re-configuring the sink schedules it again).
type SinkResolver func(id tenant.ID, sink string) (ForwardSink, bool)

// JobsConfig wires the audit jobs.
type JobsConfig struct {
	DB           *store.DB
	Checkpointer *Checkpointer
	// Registry is the one the kinds are registered in; the jobs use it to schedule their next run.
	Registry *jobs.Registry
	// Holder names this process in leases (letters, digits and ._:@-).
	Holder string
	// Sinks resolves forward sinks; nil registers audit.forward with no sink, so it ends at once.
	Sinks SinkResolver
	// Zero values take the defaults above.
	CheckpointEvents uint64
	CheckpointMaxAge time.Duration
	CheckpointTick   time.Duration
	ForwardTick      time.Duration
}

// Jobs holds the audit job bodies.
type Jobs struct{ cfg JobsConfig }

// RegisterJobs registers audit.checkpoint and audit.forward (EP-5) and returns the Jobs for scheduling.
func RegisterJobs(cfg JobsConfig) (*Jobs, error) {
	if cfg.DB == nil || cfg.Checkpointer == nil || cfg.Registry == nil || cfg.Holder == "" {
		return nil, errors.New("audit: jobs need a store, a checkpointer, a registry and a holder")
	}
	if cfg.CheckpointEvents == 0 {
		cfg.CheckpointEvents = DefaultCheckpointEvents
	}
	if cfg.CheckpointMaxAge == 0 {
		cfg.CheckpointMaxAge = DefaultCheckpointMaxAge
	}
	if cfg.CheckpointTick == 0 {
		cfg.CheckpointTick = DefaultCheckpointTick
	}
	if cfg.ForwardTick == 0 {
		cfg.ForwardTick = DefaultForwardTick
	}
	j := &Jobs{cfg: cfg}
	kinds := []jobs.Kind{
		{Name: JobCheckpoint, Timeout: 2 * time.Minute, Mode: jobs.ModeManagedTx,
			ValidateArgs: func(a jsontext.Value) error { _, err := decodeJobArgs(a); return err },
			RunManaged:   j.runCheckpoint},
		{Name: JobForward, Timeout: 5 * time.Minute, Mode: jobs.ModeManagedTx,
			ValidateArgs: func(a jsontext.Value) error {
				v, err := decodeJobArgs(a)
				if err == nil && !sinkPattern.MatchString(v.Sink) {
					err = errors.New("args name no valid sink")
				}
				return err
			},
			RunManaged: j.runForward},
	}
	for _, k := range kinds {
		if err := cfg.Registry.Register(k); err != nil {
			return nil, fmt.Errorf("audit: registering job kind: %w", err)
		}
	}
	return j, nil
}

type jobArgs struct {
	Sink string `json:"sink,omitempty"`
}

// decodeJobArgs decodes typed references and refuses unknown fields.
func decodeJobArgs(raw jsontext.Value) (jobArgs, error) {
	var m map[string]jsontext.Value
	if err := json.Unmarshal(raw, &m); err != nil {
		return jobArgs{}, errors.New("args are not an object")
	}
	delete(m, "tenant_id") // recorded by Enqueue
	b, _ := json.Marshal(m)
	var a jobArgs
	if err := json.Unmarshal(b, &a, json.RejectUnknownMembers(true)); err != nil {
		return jobArgs{}, errors.New("args do not match the kind")
	}
	return a, nil
}

// ScheduleCheckpoint starts the tenant's checkpoint cadence, in the caller's tenant transaction (the
// tenant initialiser, or a repair). It is idempotent: a cadence already queued for the current interval
// is left alone, and the job's own successor lands in the same buckets, so a second start converges.
func (j *Jobs) ScheduleCheckpoint(ctx context.Context, tx store.Tx, id tenant.ID) error {
	return j.enqueue(ctx, tx, id, JobCheckpoint, "", j.cfg.CheckpointTick, 0, time.Now())
}

// ScheduleForward starts the cadence of one sink for the tenant; call it when the sink is configured.
func (j *Jobs) ScheduleForward(ctx context.Context, tx store.Tx, id tenant.ID, sink string) error {
	if !sinkPattern.MatchString(sink) {
		return fmt.Errorf("%w: sink id", jobs.ErrInvalid)
	}
	return j.enqueue(ctx, tx, id, JobForward, sink, j.cfg.ForwardTick, forwardMaxAttempts, time.Now())
}

// enqueue queues the run for the interval bucket containing at. A run is keyed by its bucket, so the
// cadence cannot pile up, a retried run that schedules its successor again finds it already queued, and
// two cadences started by mistake collapse into one.
func (j *Jobs) enqueue(ctx context.Context, tx store.Tx, id tenant.ID, kind, sink string, every time.Duration, attempts int, at time.Time) error {
	bucket := at.UnixNano() / int64(every)
	job := jobs.Job{Kind: kind, Tenant: id, MaxAttempts: attempts,
		UniqueKey: fmt.Sprintf("%s:t%d", sink, bucket)}
	if sink != "" {
		job.Args = jobArgs{Sink: sink}
	}
	if !at.Before(time.Now().Add(every / 2)) { // a successor, not the seed: wait for its bucket to open
		job.RunAt = time.Unix(0, bucket*int64(every))
	}
	_, err := j.cfg.Registry.Enqueue(ctx, tx, job)
	return err
}

// next queues the following run (bucket after now), through the job's fenced runner.
func (j *Jobs) next(ctx context.Context, run jobs.TenantTx, id tenant.ID, kind, sink string, every time.Duration, attempts int) error {
	return run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		return j.enqueue(ctx, tx, id, kind, sink, every, attempts, time.Now().Add(every))
	})
}

func leaseName(kind string, id tenant.ID, sink string) string {
	n := kind + "." + strings.ReplaceAll(id.String(), "-", "")
	if sink != "" {
		n += "." + sink
	}
	return n
}

// withLease runs fn under the named platform lease; ran is false when another worker holds it.
func (j *Jobs) withLease(ctx context.Context, name string, fn func(ctx context.Context, renew func() error) error) (ran bool, err error) {
	l, ok, err := jobs.AcquireLease(ctx, j.cfg.DB, name, j.cfg.Holder, leaseTTL)
	if err != nil || !ok {
		return false, err
	}
	renew := func() error {
		var e error
		l, e = jobs.RenewLease(ctx, j.cfg.DB, l, leaseTTL)
		return e
	}
	err = fn(ctx, renew)
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if rerr := jobs.ReleaseLease(rctx, j.cfg.DB, l); rerr != nil && !errors.Is(rerr, jobs.ErrLeaseLost) && err == nil {
		err = rerr
	}
	return true, err
}

func (j *Jobs) runCheckpoint(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
	if _, err := decodeJobArgs(c.Args); err != nil {
		return &jobs.Failure{Code: CodeBadArgs, Permanent: true, Err: err}
	}
	// The next run is queued first, so a failure below cannot stop the cadence.
	if err := j.next(ctx, run, c.Tenant, JobCheckpoint, "", j.cfg.CheckpointTick, 0); err != nil {
		return &jobs.Failure{Code: CodeCheckpointFailed, Err: err}
	}
	_, err := j.withLease(ctx, leaseName(JobCheckpoint, c.Tenant, ""), func(ctx context.Context, _ func() error) error {
		_, _, err := j.cfg.Checkpointer.sign(ctx, j.cfg.DB, c.Tenant, j.due)
		if errors.Is(err, ErrAnchor) {
			return nil // recorded; audit.forward re-sends the checkpoint by seq
		}
		return err
	})
	if err != nil {
		return &jobs.Failure{Code: CodeCheckpointFailed, Err: err}
	}
	return nil
}

func (j *Jobs) due(newEvents uint64, since time.Duration) bool {
	return newEvents >= j.cfg.CheckpointEvents || since >= j.cfg.CheckpointMaxAge
}

func (j *Jobs) runForward(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
	a, err := decodeJobArgs(c.Args)
	if err != nil || !sinkPattern.MatchString(a.Sink) {
		return &jobs.Failure{Code: CodeBadArgs, Permanent: true, Err: errors.New("bad args")}
	}
	var sink ForwardSink
	if j.cfg.Sinks != nil {
		if s, ok := j.cfg.Sinks(c.Tenant, a.Sink); ok {
			sink = s
		}
	}
	if sink == nil {
		return nil // the sink was removed: the cadence ends here
	}
	if err := j.next(ctx, run, c.Tenant, JobForward, a.Sink, j.cfg.ForwardTick, forwardMaxAttempts); err != nil {
		return &jobs.Failure{Code: CodeForwardFailed, Err: err}
	}
	_, err = j.withLease(ctx, leaseName(JobForward, c.Tenant, a.Sink), func(ctx context.Context, renew func() error) error {
		return j.forward(ctx, run, c.Tenant, a.Sink, sink, renew)
	})
	return err
}

// forward drains the cursor to the head: events first, then the checkpoints they cover. The cursor moves
// only after Deliver returned nil.
func (j *Jobs) forward(ctx context.Context, run jobs.TenantTx, id tenant.ID, sinkID string, sink ForwardSink, renew func() error) error {
	for {
		var cur forwardCursor
		var events []Record
		var cps []Record
		err := run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
			var e error
			if cur, e = loadCursor(ctx, tx, id, sinkID); e != nil {
				return e
			}
			if events, e = readEvents(ctx, tx, id, cur.eventSeq, forwardBatch); e != nil {
				return e
			}
			if len(events) == 0 {
				cps, e = readCheckpointRecords(ctx, tx, id, cur.checkpointSeq, cur.eventSeq, forwardBatch)
			}
			return e
		})
		if err != nil {
			return &jobs.Failure{Code: CodeForwardFailed, Err: err}
		}
		batch := events
		if len(batch) == 0 {
			batch = cps
		}
		if len(batch) == 0 {
			return nil // caught up
		}
		if err := renew(); err != nil {
			if errors.Is(err, jobs.ErrLeaseLost) {
				return nil // another worker owns this sink now; it resumes from the cursor
			}
			return &jobs.Failure{Code: CodeForwardFailed, Err: err}
		}
		if derr := sink.Deliver(ctx, id, batch); derr != nil {
			_ = run.Run(context.WithoutCancel(ctx), func(ctx context.Context, tx store.Tx) error {
				return recordFailure(ctx, tx, id, sinkID, CodeSinkUnavailable)
			})
			return &jobs.Failure{Code: CodeSinkUnavailable, Err: derr}
		}
		last := batch[len(batch)-1].Seq
		err = run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
			return advanceCursor(ctx, tx, id, sinkID, batch[0].Kind, last)
		})
		if err != nil {
			return &jobs.Failure{Code: CodeForwardFailed, Err: err}
		}
	}
}

type forwardCursor struct{ eventSeq, checkpointSeq uint64 }

func loadCursor(ctx context.Context, tx store.Tx, id tenant.ID, sink string) (forwardCursor, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO audit_forward_cursor (tenant_id, sink_id) VALUES ($1::uuid, $2) ON CONFLICT DO NOTHING`, id.String(), sink); err != nil {
		return forwardCursor{}, fmt.Errorf("audit: create forward cursor: %w", err)
	}
	var c forwardCursor
	if err := tx.QueryRow(ctx, `SELECT event_seq, checkpoint_seq FROM audit_forward_cursor WHERE tenant_id = $1::uuid AND sink_id = $2`, id.String(), sink).Scan(&c.eventSeq, &c.checkpointSeq); err != nil {
		return forwardCursor{}, fmt.Errorf("audit: read forward cursor: %w", err)
	}
	return c, nil
}

func readEvents(ctx context.Context, tx store.Tx, id tenant.ID, after uint64, limit int) ([]Record, error) {
	rows, err := tx.Query(ctx, `SELECT seq, envelope, prev_hash, hash FROM audit_event WHERE tenant_id = $1::uuid AND seq > $2 ORDER BY seq LIMIT $3`, id.String(), after, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: read events to forward: %w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r := Record{Kind: RecordEvent}
		var ph, h []byte
		if err := rows.Scan(&r.Event.Seq, &r.Event.Envelope, &ph, &h); err != nil {
			return nil, fmt.Errorf("audit: read event: %w", err)
		}
		copy(r.Event.PrevHash[:], ph)
		copy(r.Event.Hash[:], h)
		r.Seq = r.Event.Seq
		out = append(out, r)
	}
	return out, rows.Err()
}

func readCheckpointRecords(ctx context.Context, tx store.Tx, id tenant.ID, after, upTo uint64, limit int) ([]Record, error) {
	if upTo == 0 {
		return nil, nil
	}
	cps, err := ListCheckpoints(ctx, tx, id, after, upTo, limit, false)
	if err != nil {
		return nil, err
	}
	out := make([]Record, len(cps))
	for i, cp := range cps {
		out[i] = Record{Kind: RecordCheckpoint, Seq: cp.Seq, Checkpoint: cp}
	}
	return out, nil
}

const advanceEvents = `UPDATE audit_forward_cursor SET event_seq = GREATEST(event_seq, $3), consecutive_failures = 0,
  last_failure_code = NULL, last_failure_at = NULL, last_delivered_at = now(), updated_at = now()
WHERE tenant_id = $1::uuid AND sink_id = $2`

const advanceCheckpoints = `UPDATE audit_forward_cursor SET checkpoint_seq = GREATEST(checkpoint_seq, $3), consecutive_failures = 0,
  last_failure_code = NULL, last_failure_at = NULL, last_delivered_at = now(), updated_at = now()
WHERE tenant_id = $1::uuid AND sink_id = $2`

func advanceCursor(ctx context.Context, tx store.Tx, id tenant.ID, sink string, kind RecordKind, seq uint64) error {
	var err error
	if kind == RecordCheckpoint {
		_, err = tx.Exec(ctx, advanceCheckpoints, id.String(), sink, seq)
	} else {
		_, err = tx.Exec(ctx, advanceEvents, id.String(), sink, seq)
	}
	if err != nil {
		return fmt.Errorf("audit: advance forward cursor: %w", err)
	}
	return nil
}

func recordFailure(ctx context.Context, tx store.Tx, id tenant.ID, sink, code string) error {
	_, err := tx.Exec(ctx, `UPDATE audit_forward_cursor SET consecutive_failures = consecutive_failures + 1, last_failure_code = $3,
  last_failure_at = now(), updated_at = now() WHERE tenant_id = $1::uuid AND sink_id = $2`, id.String(), sink, code)
	if err != nil {
		return fmt.Errorf("audit: record forward failure: %w", err)
	}
	return nil
}

// ForwardStatus is what the console and alerting read about one sink (lag, repeated failure).
type ForwardStatus struct {
	EventSeq, CheckpointSeq uint64
	// Head is the chain head; Head - EventSeq is the number of events the sink has not acknowledged.
	Head                uint64
	ConsecutiveFailures int
	LastFailureCode     string
	LastFailureAt       *time.Time
	LastDeliveredAt     *time.Time
}

// GetForwardStatus reads a sink's cursor in the caller's tenant transaction. A sink never forwarded to
// has a zero cursor.
func GetForwardStatus(ctx context.Context, tx store.Tx, id tenant.ID, sink string) (ForwardStatus, error) {
	var s ForwardStatus
	if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT seq FROM audit_head WHERE tenant_id = $1::uuid), 0)`, id.String()).Scan(&s.Head); err != nil {
		return s, fmt.Errorf("audit: read head: %w", err)
	}
	var code *string
	err := tx.QueryRow(ctx, `SELECT event_seq, checkpoint_seq, consecutive_failures, last_failure_code, last_failure_at, last_delivered_at
		FROM audit_forward_cursor WHERE tenant_id = $1::uuid AND sink_id = $2`, id.String(), sink).
		Scan(&s.EventSeq, &s.CheckpointSeq, &s.ConsecutiveFailures, &code, &s.LastFailureAt, &s.LastDeliveredAt)
	if err != nil && !store.IsNoRows(err) {
		return s, fmt.Errorf("audit: read forward status: %w", err)
	}
	if code != nil {
		s.LastFailureCode = *code
	}
	return s, nil
}
