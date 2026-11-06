// Package alertjob is the transport side of the AN-8 owner alert (T-1544, RULING AN8-A1): the AlertSink
// that turns an outbox row into one notify Delivery per tenant-owner, the Renderer that makes the message
// at send time, and the two jobs (authn.an8alert.drain, authn.an8alert.watch) that run authn.AlertDrain.
// It sits above authn, notify/delivery and jobs because authn may import none of them (ADR-0005 rule 13);
// compose/server registers it.
package alertjob

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	// Purpose names the Renderer of the alert; SourceKind is the Delivery source of an outbox row.
	Purpose    = "authn.an8.owner_alert"
	SourceKind = "authn_an8_alert"

	JobDrain = "authn.an8alert.drain"
	JobWatch = "authn.an8alert.watch"

	DrainInterval = time.Minute
	WatchInterval = 5 * time.Minute

	CodeFailed  = "an8alert_failed"
	CodeBadArgs = "bad_args"
)

// Sink is authn.AlertSink over notify/delivery.
type Sink struct{ Deliveries *delivery.Deliveries }

var _ authn.AlertSink = Sink{}

var by = authority.Chain{Requester: authority.Principal{ID: "authn-an8-alert", Kind: authority.System}}

// Enqueue queues the Delivery of notice to recipient; the dedup key makes a repeated fan-out harmless.
func (s Sink) Enqueue(ctx context.Context, tx store.Tx, d authn.AlertDelivery) error {
	_, err := s.Deliveries.Enqueue(ctx, tx, delivery.NewDelivery{
		DedupKey: d.Notice + ":" + d.Recipient, Purpose: Purpose, TemplateVersion: 1,
		Variables: map[string]string{"notice": d.Notice},
		Recipient: delivery.Recipient{Account: d.Recipient}, Source: delivery.SourceRef{Kind: SourceKind, ID: d.Notice},
	}, by)
	return err
}

// Given counts the Deliveries of notice and those given up.
func (s Sink) Given(ctx context.Context, tx store.Tx, notice string) (int, int, error) {
	return s.Deliveries.SourceCounts(ctx, tx, delivery.SourceRef{Kind: SourceKind, ID: notice})
}

// Renderer makes the alert text at send time from the outbox row. The body carries the event, time, source
// address and the break-glass account's display name; never a password, token, session id or submitted name.
type Renderer struct{ Tenant func() (tenant.ID, bool) }

func (r Renderer) Render(ctx context.Context, tx store.Tx, d delivery.Delivery) (delivery.Content, error) {
	t, ok := r.Tenant()
	if !ok {
		return delivery.Content{}, errors.New("alertjob: the install's tenant is not ready")
	}
	m, err := authn.LoadAlertMessage(ctx, tx, t, d.Variables["notice"])
	if err != nil {
		return delivery.Content{}, err
	}
	src := m.Source
	if src == "" {
		src = "unknown"
	}
	at := m.At.UTC().Format(time.RFC3339)
	switch m.Event {
	case authn.EventBreakGlassUsed:
		who := m.Account
		if who == "" {
			who = "the break-glass account"
		}
		return delivery.Content{
			Subject: "activeDIQ: break-glass sign-in used",
			Text:    fmt.Sprintf("The break-glass sign-in was used.\n\nAccount: %s\nTime: %s\nSource address: %s\n\nIf this was not you or a colleague, review the audit trail now.\n", who, at, src),
		}, nil
	default:
		return delivery.Content{
			Subject: "activeDIQ: repeated failed break-glass sign-ins",
			Text:    fmt.Sprintf("There were %d failed break-glass sign-in attempts within one hour.\n\nLatest attempt: %s\nSource address: %s\n\nReview the audit trail.\n", m.FailureCount, at, src),
		}, nil
	}
}

// Jobs registers and schedules the drain and the watchdog.
type Jobs struct {
	reg   *jobs.Registry
	drain *authn.AlertDrain
}

// Register registers both kinds in reg.
func Register(reg *jobs.Registry, drain *authn.AlertDrain) (*Jobs, error) {
	if reg == nil || drain == nil {
		return nil, errors.New("alertjob: needs a job registry and the alert drain")
	}
	j := &Jobs{reg: reg, drain: drain}
	for _, k := range []string{JobDrain, JobWatch} {
		if err := reg.Register(jobs.Kind{Name: k, Timeout: 2 * time.Minute, Mode: jobs.ModeManagedTx,
			ValidateArgs: noArgs, RunManaged: j.run}); err != nil {
			return nil, fmt.Errorf("alertjob: registering %s: %w", k, err)
		}
	}
	return j, nil
}

func noArgs(raw jsontext.Value) error {
	var m map[string]jsontext.Value
	if err := json.Unmarshal(raw, &m); err != nil {
		return errors.New("args are not an object")
	}
	delete(m, "tenant_id")
	if len(m) != 0 {
		return errors.New("args do not match the kind")
	}
	return nil
}

func every(kind string) time.Duration {
	if kind == JobWatch {
		return WatchInterval
	}
	return DrainInterval
}

// Schedule starts both cadences in the caller's tenant transaction; idempotent per interval bucket.
func (j *Jobs) Schedule(ctx context.Context, tx store.Tx, id tenant.ID) error {
	for _, k := range []string{JobDrain, JobWatch} {
		if err := j.enqueue(ctx, tx, k, id, time.Now(), true); err != nil {
			return err
		}
	}
	return nil
}

func (j *Jobs) enqueue(ctx context.Context, tx store.Tx, kind string, id tenant.ID, at time.Time, seed bool) error {
	e := every(kind)
	bucket := at.UnixNano() / int64(e)
	job := jobs.Job{Kind: kind, Tenant: id, MaxAttempts: 1, UniqueKey: fmt.Sprintf("t%d", bucket)}
	if !seed {
		job.RunAt = time.Unix(0, bucket*int64(e))
	}
	_, err := j.reg.Enqueue(ctx, tx, job)
	return err
}

func (j *Jobs) run(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
	if err := noArgs(c.Args); err != nil {
		return &jobs.Failure{Code: CodeBadArgs, Permanent: true, Err: err}
	}
	// The successor is queued first, so nothing below can stop the cadence.
	if err := run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		return j.enqueue(ctx, tx, c.Kind, c.Tenant, time.Now().Add(every(c.Kind)), false)
	}); err != nil {
		return &jobs.Failure{Code: CodeFailed, Err: err}
	}
	var err error
	if c.Kind == JobWatch {
		var n int
		if n, err = j.drain.Watch(ctx, c.Tenant); n > 0 {
			slog.Warn("authn: break-glass alerts pending over the threshold", "tenant", c.Tenant.String(), "rows", n)
		}
	} else {
		_, err = j.drain.Drain(ctx, c.Tenant)
	}
	if err != nil {
		return &jobs.Failure{Code: CodeFailed, Err: err}
	}
	return nil
}
