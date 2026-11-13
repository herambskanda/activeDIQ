package sync

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// JobFull is the job kind of the full read of one AD connection (blueprint §5.2, EP-5 job kinds). It is
// tenant-carrying and ModeManagedTx: the body holds no transaction across a directory call. One job reads
// one connection; its partitions are the connection's managed domain naming contexts, each guarded by the
// platform lease LeaseName(connection, nc) (ADR-0002 rule 6, DM-19.I2: one reader per partition).
const JobFull = "sync.full"

// Defaults of the job.
const (
	// DefaultLeaseTTL is how long a lease outlives a holder that died: another node takes the partition over
	// after this. The running job renews every TTL/3, so a live holder never lapses.
	DefaultLeaseTTL = 2 * time.Minute
	// fullTimeout bounds one run. A 20,000-account domain reads in minutes; the bound only catches a hang.
	fullTimeout = 4 * time.Hour
	// fullAttempts is how often a failed run is retried with the platform backoff (jobs.Backoff).
	fullAttempts = 5
	// leaseReleaseTimeout bounds giving the leases up after the body, even when its context was cancelled.
	leaseReleaseTimeout = 10 * time.Second
)

// Failure codes of the job. Fixed vocabulary; no directory text is ever stored (jobs.Failure).
const (
	CodeBadArgs        = "bad_args"
	CodeRefused        = "refused"        // the connection may not be read (not active, retired, not AD, no identity)
	CodeNotConfigured  = "not_configured" // the engine or the managed set is unusable
	CodePaused         = "paused"         // the partition is paused; a resume and resync restart it
	CodeLeaseLost      = "lease_lost"     // the lease lapsed or was taken over mid-run
	CodeStaleCookie    = "stale_cookie"   // the connector says the position is unusable (FAILED_PRECONDITION)
	CodeUnreachable    = "unreachable"    // the connector or its DC could not be reached
	CodeInsufficient   = "insufficient"   // the connector refused the identity's rights: retrying cannot help
	CodeIncomplete     = "incomplete"     // the stream was cut off
	CodeSourceFailed   = "source_failed"  // a port (registry, managed set, connector source) failed
	CodeCycleFailed    = "cycle_failed"   // any other failure of a domain's read
	codeNoDomainsFound = "no_managed_domains"
)

// ErrLeaseHeld: another node holds a partition's lease, so this run reads nothing. It is not a failure.
var ErrLeaseHeld = errors.New("sync: the partition's lease is held by another node")

// Cycler is the engine's full read (*Engine).
type Cycler interface {
	FullCycle(ctx context.Context, tid tenant.ID, id connection.ID, lease LeaseFunc) (Report, error)
}

// PassMarker records a naming context's feed state in the freshness watermark (inventory.Writer).
type PassMarker interface {
	MarkNC(ctx context.Context, tx store.Tx, connection inventory.ConnectionID, nc inventory.GUID, state inventory.PassState) error
}

// JobConfig is what the job needs.
type JobConfig struct {
	// DB holds the platform leases (public.platform_leases).
	DB     *store.DB
	Cycle  Cycler
	Passes PassMarker
	// Holder names this node on its leases (the install's instance id).
	Holder string
	// LeaseTTL is the lease length; zero is DefaultLeaseTTL. Tests shorten it.
	LeaseTTL time.Duration
	// Log receives the job's summary lines: counts and fixed codes, never a directory value. Nil discards.
	Log *slog.Logger
}

// Jobs registers and enqueues sync.full.
type Jobs struct {
	reg *jobs.Registry
	cfg JobConfig
}

// RegisterJobs registers sync.full in reg.
func RegisterJobs(reg *jobs.Registry, cfg JobConfig) (*Jobs, error) {
	if reg == nil || cfg.DB == nil || cfg.Cycle == nil || cfg.Passes == nil || cfg.Holder == "" {
		return nil, fmt.Errorf("%w: the sync job needs a registry, a database, an engine, a pass marker and a holder", ErrNotConfigured)
	}
	if cfg.LeaseTTL == 0 {
		cfg.LeaseTTL = DefaultLeaseTTL
	}
	if cfg.LeaseTTL < 3*time.Millisecond || cfg.LeaseTTL > time.Hour {
		return nil, fmt.Errorf("%w: lease ttl", ErrNotConfigured)
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	j := &Jobs{reg: reg, cfg: cfg}
	err := reg.Register(jobs.Kind{Name: JobFull, Timeout: fullTimeout, Mode: jobs.ModeManagedTx, ValidateArgs: fullArgs, RunManaged: j.run})
	if err != nil {
		return nil, fmt.Errorf("sync: registering job kind: %w", err)
	}
	return j, nil
}

type fullJobArgs struct {
	Connection string `json:"connection"`
}

// fullArgs: the job carries the connection and the tenant (which Enqueue records) and nothing else.
func fullArgs(raw jsontext.Value) error {
	var m map[string]jsontext.Value
	if err := json.Unmarshal(raw, &m); err != nil {
		return errors.New("args are not an object")
	}
	delete(m, "tenant_id")
	conn, ok := m["connection"]
	delete(m, "connection")
	if !ok || len(m) != 0 {
		return errors.New("args do not match the kind")
	}
	var s string
	if err := json.Unmarshal(conn, &s); err != nil || !guidTextRE.MatchString(s) || s == nilGUID {
		return errors.New("connection is not a canonical lower-case GUID")
	}
	return nil
}

// Enqueue queues a full read of the connection in the caller's tenant transaction. It is de-duplicated on
// the connection while a job for it is queued or running, so the boot pass, the activation and the interval
// can all call it: the surplus is dropped (jobs.Enqueued.Duplicate), and the lease allows one reader per
// partition even if two nodes race here.
func (j *Jobs) Enqueue(ctx context.Context, tx store.Tx, tid tenant.ID, id connection.ID) (jobs.Enqueued, error) {
	return j.reg.Enqueue(ctx, tx, jobs.Job{Kind: JobFull, Tenant: tid, Args: fullJobArgs{Connection: string(id)},
		UniqueKey: string(id), MaxAttempts: fullAttempts})
}

// ConnectionActivated implements connection.ActivationHook: an AD connection that just became active gets
// its first full read, queued in the activation's transaction.
func (j *Jobs) ConnectionActivated(ctx context.Context, tx store.Tx, tid tenant.ID, c connection.Connection) error {
	if c.Kind != connection.KindADForest {
		return nil
	}
	_, err := j.Enqueue(ctx, tx, tid, c.ID)
	return err
}

func (j *Jobs) run(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
	if err := fullArgs(c.Args); err != nil {
		return &jobs.Failure{Code: CodeBadArgs, Permanent: true, Err: err}
	}
	var args fullJobArgs
	if err := json.Unmarshal(c.Args, &args); err != nil {
		return &jobs.Failure{Code: CodeBadArgs, Permanent: true, Err: err}
	}
	id := connection.ID(args.Connection)

	ls := &leaseSet{db: j.cfg.DB, holder: j.cfg.Holder, ttl: j.cfg.LeaseTTL, held: map[string]jobs.Lease{}, log: j.cfg.Log}
	bctx, cancel := context.WithCancelCause(ctx)
	renewed := make(chan struct{})
	go func() { defer close(renewed); ls.keepAlive(bctx, cancel) }()

	rep, err := j.cfg.Cycle.FullCycle(bctx, c.Tenant, id, ls.get)

	cancel(nil)
	<-renewed
	lost := errors.Is(context.Cause(bctx), jobs.ErrLeaseLost) || ls.wasLost()
	ls.releaseAll(ctx)

	return j.outcome(ctx, run, c, id, rep, err, lost)
}

// outcome maps what FullCycle returned to the job's result.
func (j *Jobs) outcome(ctx context.Context, run jobs.TenantTx, c jobs.Claimed, id connection.ID, rep Report, err error, lost bool) error {
	log := j.cfg.Log.With("tenant", c.Tenant.String(), "connection", string(id), "job", c.ID, "attempt", c.Attempt)
	switch {
	case err == nil:
		done, skipped, entries := 0, 0, 0
		for _, d := range rep.Domains {
			entries += d.Entries
			if d.Completed {
				done++
			}
			if d.Skipped {
				skipped++
			}
		}
		log.Info("sync: full read finished", "domains", len(rep.Domains), "completed", done, "skipped", skipped, "entries", entries)
		return nil
	case ctx.Err() != nil:
		return ctx.Err() // the worker is stopping: the claim is left to lapse and is rescued
	case lost || errors.Is(err, ErrFenced) || errors.Is(err, jobs.ErrLeaseLost):
		log.Warn("sync: full read aborted: the lease was lost")
		return &jobs.Failure{Code: CodeLeaseLost, Err: err}
	case errors.Is(err, ErrLeaseHeld):
		log.Info("sync: lease held by another node; nothing read")
		return nil
	}

	var refusal *Refusal
	switch {
	case errors.As(err, &refusal):
		log.Warn("sync: connection may not be read", "reason", string(refusal.Reason))
		return &jobs.Failure{Code: CodeRefused, Permanent: true, Err: err}
	case errors.Is(err, ErrRefused):
		return &jobs.Failure{Code: CodeRefused, Permanent: true, Err: err}
	case errors.Is(err, ErrNoManagedDomains), errors.Is(err, ErrNotDomainNC):
		log.Warn("sync: the connection has no readable managed domain")
		return &jobs.Failure{Code: codeNoDomainsFound, Permanent: true, Err: err}
	case errors.Is(err, ErrNotConfigured):
		return &jobs.Failure{Code: CodeNotConfigured, Permanent: true, Err: err}
	case errors.Is(err, ErrPaused):
		log.Info("sync: the partition is paused; a resume and resync restart it")
		return &jobs.Failure{Code: CodePaused, Permanent: true, Err: err}
	}

	code, permanent := j.classify(ctx, run, id, err, log)
	return &jobs.Failure{Code: code, Permanent: permanent, Err: err}
}

// classify turns the failed domains of a cycle into one failure code and, for a domain whose connector says
// the position is unusable, records the stale cause in the freshness watermark so reports show it.
func (j *Jobs) classify(ctx context.Context, run jobs.TenantTx, id connection.ID, err error, log *slog.Logger) (code string, permanent bool) {
	code = CodeCycleFailed
	rank := map[string]int{CodeCycleFailed: 0, CodeSourceFailed: 1, CodeIncomplete: 2, CodeUnreachable: 3, CodeStaleCookie: 4}
	set := func(c string) {
		if rank[c] > rank[code] {
			code = c
		}
	}
	insufficient := false
	for _, one := range flatten(err) {
		var ce *ConnectorError
		var de *DomainError
		cls := CodeCycleFailed
		switch {
		case errors.As(one, &ce):
			switch ce.Code {
			case codes.FailedPrecondition:
				cls = CodeStaleCookie
			case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted, codes.Aborted:
				cls = CodeUnreachable
			case codes.PermissionDenied, codes.Unauthenticated:
				insufficient = true
			}
		case errors.Is(one, ErrIncomplete):
			cls = CodeIncomplete
		case errors.Is(one, ErrSource):
			cls = CodeSourceFailed
		}
		set(cls)
		if cls == CodeStaleCookie && errors.As(one, &de) {
			if merr := run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
				return j.cfg.Passes.MarkNC(ctx, tx, inventory.ConnectionID(id), de.NC, inventory.PassResyncRequired)
			}); merr != nil {
				log.Warn("sync: recording the stale cause failed", "nc", string(de.NC))
			}
		}
		phase, class := errClass(one)
		log.Warn("sync: a domain read failed", "phase", phase, "class", class)
	}
	if insufficient {
		// A rights refusal does not heal by retrying; it waits for an admin and the next interval.
		return CodeInsufficient, true
	}
	return code, false
}

// flatten returns the leaves of an errors.Join tree.
func flatten(err error) []error {
	if u, ok := err.(interface{ Unwrap() []error }); ok {
		var out []error
		for _, e := range u.Unwrap() {
			out = append(out, flatten(e)...)
		}
		return out
	}
	return []error{err}
}

// leaseSet holds the platform leases one run took, renews them while the run works, and gives them up when
// it ends.
type leaseSet struct {
	db     *store.DB
	holder string
	ttl    time.Duration
	log    *slog.Logger

	mu     sync.Mutex
	held   map[string]jobs.Lease
	lostOn bool
}

// get is the engine's LeaseFunc: it takes the named lease, or says another node has it.
func (s *leaseSet) get(ctx context.Context, name string) (jobs.Lease, error) {
	s.mu.Lock()
	l, ok := s.held[name]
	s.mu.Unlock()
	if ok {
		return l, nil
	}
	l, ok, err := jobs.AcquireLease(ctx, s.db, name, s.holder, s.ttl)
	if err != nil {
		return jobs.Lease{}, err
	}
	if !ok {
		return jobs.Lease{}, ErrLeaseHeld
	}
	s.mu.Lock()
	s.held[name] = l
	s.mu.Unlock()
	return l, nil
}

// keepAlive renews every held lease each TTL/3 until ctx ends. A lease that cannot be renewed because it
// lapsed or was taken over stops the run: cancel is called with jobs.ErrLeaseLost.
func (s *leaseSet) keepAlive(ctx context.Context, cancel context.CancelCauseFunc) {
	t := time.NewTicker(s.ttl / 3)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		snap := make([]jobs.Lease, 0, len(s.held))
		for _, l := range s.held {
			snap = append(snap, l)
		}
		s.mu.Unlock()
		for _, l := range snap {
			nl, err := jobs.RenewLease(ctx, s.db, l, s.ttl)
			switch {
			case err == nil:
				s.mu.Lock()
				s.held[l.Name] = nl
				s.mu.Unlock()
			case errors.Is(err, jobs.ErrLeaseLost):
				s.mu.Lock()
				s.lostOn = true
				s.mu.Unlock()
				cancel(jobs.ErrLeaseLost)
				return
			case ctx.Err() != nil:
				return
			default:
				// A database hiccup: the next tick tries again; if the lease lapses meanwhile, the renewal
				// after it is ErrLeaseLost and stops the run.
				s.log.Warn("sync: renewing a lease failed; will retry")
			}
		}
	}
}

func (s *leaseSet) wasLost() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lostOn
}

// releaseAll gives the leases up so another node can take them at once. It runs even when ctx was
// cancelled; a lease already lost is not an error.
func (s *leaseSet) releaseAll(ctx context.Context) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), leaseReleaseTimeout)
	defer cancel()
	s.mu.Lock()
	snap := make([]jobs.Lease, 0, len(s.held))
	for _, l := range s.held {
		snap = append(snap, l)
	}
	clear(s.held)
	s.mu.Unlock()
	for _, l := range snap {
		if err := jobs.ReleaseLease(rctx, s.db, l); err != nil && !errors.Is(err, jobs.ErrLeaseLost) {
			s.log.Warn("sync: releasing a lease failed; it expires on its own")
		}
	}
}
