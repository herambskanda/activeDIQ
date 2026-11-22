package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// The fleet Enroller of the server role (T-0716). It shares the tenant data-encryption-key source with
// the console (one keys.Store over the boot-unlocked KEK provider), raises installation alerts through a
// queue into the audit trail, and is built only after the install's tenant exists, so a key source that
// cannot serve that tenant stops startup instead of failing the first enrolment.

const alertQueueSize = 256

// alertAuditTimeout bounds one queued alert's audit write.
const alertAuditTimeout = 10 * time.Second

// queueAlerter implements fleetsql.Alerter. Raise never blocks the caller (it is called inside an
// enrolment transaction): it puts the alert on a bounded queue, and one goroutine records it as an audit
// event in the alert's tenant. When the queue is full the alert is dropped and counted in the log; the
// enrolment is refused anyway. The record holds the alert kind, tenant and component GUID only.
type queueAlerter struct {
	db   *store.DB
	sink audit.Sink
	log  *slog.Logger
	now  func() time.Time
	q    chan fleetsql.Alert
	done chan struct{}
	once sync.Once
}

var _ fleetsql.Alerter = (*queueAlerter)(nil)

func newQueueAlerter(db *store.DB, sink audit.Sink, log *slog.Logger) (*queueAlerter, error) {
	if db == nil || sink == nil {
		return nil, errors.New("server: fleet alerter needs the store and the audit sink")
	}
	if log == nil {
		log = slog.Default()
	}
	return &queueAlerter{db: db, sink: sink, log: log, now: time.Now,
		q: make(chan fleetsql.Alert, alertQueueSize), done: make(chan struct{})}, nil
}

// Raise queues a; it never blocks and never fails the caller.
func (a *queueAlerter) Raise(_ context.Context, al fleetsql.Alert) {
	select {
	case a.q <- al:
	default:
		a.log.Error("server: fleet alert queue full, alert dropped", "kind", string(al.Kind), "tenant_id", al.Tenant.String())
	}
}

// Run records queued alerts until ctx is done, then drains what is queued.
func (a *queueAlerter) Run(ctx context.Context) {
	defer a.once.Do(func() { close(a.done) })
	for {
		select {
		case al := <-a.q:
			a.record(ctx, al)
		case <-ctx.Done():
			for {
				select {
				case al := <-a.q:
					a.record(context.WithoutCancel(ctx), al)
				default:
					return
				}
			}
		}
	}
}

// Wait returns once Run has drained and returned.
func (a *queueAlerter) Wait() { <-a.done }

func (a *queueAlerter) record(ctx context.Context, al fleetsql.Alert) {
	if al.Tenant.IsZero() {
		a.log.Error("server: fleet alert without a tenant", "kind", string(al.Kind))
		return
	}
	at := a.now()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), alertAuditTimeout)
	defer cancel()
	comp := al.Component
	target := authority.TargetRef{Class: "tenant", GUID: al.Tenant.String()}
	details := []chain.Detail{{Key: "alert", Value: string(al.Kind)}}
	if comp != "" {
		target = authority.TargetRef{Class: "component", GUID: comp}
		details = []chain.Detail{{Key: "alert", Value: string(al.Kind)}, {Key: "component", Value: comp}}
	}
	err := a.db.WithTenant(ctx, al.Tenant, func(ctx context.Context, tx store.Tx) error {
		return a.sink.Append(ctx, tx, audit.Event{
			ID:        fmt.Sprintf("%s.%s.%d", al.Kind, al.Tenant.String(), at.UnixNano()),
			Kind:      audit.Kind(al.Kind),
			At:        at,
			Actor:     authority.Chain{Requester: authority.Principal{ID: "fleet-alert", Kind: authority.System}},
			Target:    target,
			Component: "fleet",
			Outcome:   audit.Failure,
			Reason:    string(al.Kind),
			Details:   details,
		})
	})
	if err != nil {
		a.log.Error("server: fleet alert could not be recorded", "kind", string(al.Kind), "tenant_id", al.Tenant.String(), "err", err)
	}
}

// fleetEnrollerDeps is what buildEnroller composes.
type fleetEnrollerDeps struct {
	DB        *store.DB
	Audit     audit.Sink
	Keys      fleetsql.KeySource // the same source the console uses
	Authz     apihost.Authorizer
	StepUp    apihost.StepUpChecker
	Alerts    fleetsql.Alerter
	Endpoints []fleetsql.Endpoint
}

// ErrNoFleetKeys is returned when the Enroller's key source cannot serve the install's tenant.
var ErrNoFleetKeys = errors.New("server: fleet enroller: the tenant data-encryption key is unavailable")

// buildEnroller builds the fleet Enroller over the real key source and proves, for the install's tenant,
// that the source can serve its active key. A missing piece, or a source that fails, stops startup.
func buildEnroller(ctx context.Context, d fleetEnrollerDeps, tid tenant.ID) (*fleetsql.Enroller, error) {
	switch {
	case d.DB == nil || d.Audit == nil:
		return nil, errors.New("server: fleet enroller needs the store and the audit sink")
	case d.Keys == nil:
		return nil, fmt.Errorf("%w: no key source", ErrNoFleetKeys)
	case d.Authz == nil || d.StepUp == nil || d.Alerts == nil:
		return nil, errors.New("server: fleet enroller needs the authorizer, the step-up check and the alerter")
	case tid.IsZero():
		return nil, errors.New("server: fleet enroller needs the install's tenant")
	}
	err := d.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		dek, err := d.Keys.DEK(ctx, tx, tid, 0)
		if err != nil {
			return err
		}
		dek.Destroy()
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoFleetKeys, err) // the source's own text is "keys: <Code>" only
	}
	return &fleetsql.Enroller{
		Enrollment: &fleetsql.Enrollment{DB: d.DB, Authz: d.Authz, StepUp: d.StepUp, Limiter: fleetsql.NewMemoryLimiter(fleetsql.MemoryLimiterConfig{})},
		Keys:       d.Keys,
		Alerts:     d.Alerts,
		Audit:      d.Audit,
		Endpoints:  d.Endpoints,
	}, nil
}
