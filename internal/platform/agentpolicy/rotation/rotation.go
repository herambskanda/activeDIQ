// Package rotation is the keyset rotation job (ADR-0007 decision 6, ticket T-0556). One job per tenant
// runs daily: it rotates the active policy key when it is older than signer.RotationInterval, and drops
// retiring keys whose overlap window has ended. Both publish a new keyset signed by a key the agents
// already hold, so a healthy fleet follows the chain without operator action; the audit trail records
// each publication.
//
// A key that is compromised rotates on demand through Rotate, which is the same signer call the
// scheduled run uses. The job never retries a failed signing: a sealed key that fails to open is
// ErrIntegrity, which pages the operator rather than looping.
package rotation

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy/signer"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// JobKeysetMaintenance is the job kind.
const JobKeysetMaintenance = "agentfleet.keyset_maintenance"

// Interval is the cadence of the maintenance run.
const Interval = 24 * time.Hour

// Failure codes.
const (
	CodeBadArgs   = "bad_args"
	CodeMaintFail = "maintenance_failed"
	CodeIntegrity = "key_integrity"
)

// Outcome says what a run did.
type Outcome struct {
	Rotated bool
	Dropped bool
}

// Jobs registers and schedules the maintenance job.
type Jobs struct {
	reg    *jobs.Registry
	signer *signer.Signer
	clock  func() time.Time
}

// RegisterJobs registers the kind in reg. clock may be nil.
func RegisterJobs(reg *jobs.Registry, sg *signer.Signer, clock func() time.Time) (*Jobs, error) {
	if reg == nil || sg == nil {
		return nil, errors.New("rotation: needs a job registry and a signer")
	}
	if clock == nil {
		clock = time.Now
	}
	j := &Jobs{reg: reg, signer: sg, clock: clock}
	// Timeout: one tenant, a handful of rows and at most two signatures.
	if err := reg.Register(jobs.Kind{Name: JobKeysetMaintenance, Timeout: 5 * time.Minute, Mode: jobs.ModeManagedTx,
		ValidateArgs: args, RunManaged: j.run}); err != nil {
		return nil, fmt.Errorf("rotation: registering job kind: %w", err)
	}
	return j, nil
}

func args(raw jsontext.Value) error {
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

// Actor is the principal of scheduled maintenance in the audit trail.
var Actor = authority.Chain{Requester: authority.Principal{ID: "system:agentfleet", Kind: authority.System}}

// EnsureAndSchedule returns the tenant's keyset, creating the first key if there is none, and starts
// the tenant's maintenance cadence. Both are idempotent. The first authenticated call of an addc agent
// after enrolment goes through here.
func (j *Jobs) EnsureAndSchedule(ctx context.Context, tx store.Tx, tid tenant.ID) (agentpolicy.SignedKeyset, error) {
	sk, err := j.signer.EnsureKeyset(ctx, tx, tid, Actor)
	if err != nil {
		return agentpolicy.SignedKeyset{}, err
	}
	return sk, j.enqueue(ctx, tx, tid, j.clock().Add(Interval))
}

func (j *Jobs) enqueue(ctx context.Context, tx store.Tx, tid tenant.ID, at time.Time) error {
	bucket := at.UnixNano() / int64(Interval)
	_, err := j.reg.Enqueue(ctx, tx, jobs.Job{
		Kind: JobKeysetMaintenance, Tenant: tid, MaxAttempts: 1,
		UniqueKey: fmt.Sprintf("t%d", bucket),
		RunAt:     time.Unix(0, bucket*int64(Interval)),
	})
	return err
}

// Maintain does one run's work in the caller's tenant transaction.
func (j *Jobs) Maintain(ctx context.Context, tx store.Tx, tid tenant.ID) (Outcome, error) {
	var out Outcome
	rotate, drop, err := j.signer.PendingMaintenance(ctx, tx)
	if err != nil {
		return out, err
	}
	// Drop first: it frees a slot in the keyset, so the rotation below cannot be refused for room.
	if drop {
		_, ok, err := j.signer.DropExpired(ctx, tx, tid, Actor)
		if err != nil {
			return out, err
		}
		out.Dropped = ok
	}
	if rotate {
		if _, err := j.signer.Rotate(ctx, tx, tid, Actor, "scheduled"); err != nil {
			return out, err
		}
		out.Rotated = true
	}
	return out, nil
}

func (j *Jobs) run(ctx context.Context, run jobs.TenantTx, c jobs.Claimed) error {
	if err := args(c.Args); err != nil {
		return &jobs.Failure{Code: CodeBadArgs, Permanent: true, Err: err}
	}
	// The successor is queued first, so a failing run cannot stop the cadence.
	err := run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		return j.enqueue(ctx, tx, c.Tenant, j.clock().Add(Interval))
	})
	if err != nil {
		return &jobs.Failure{Code: CodeMaintFail, Err: err}
	}
	err = run.Run(ctx, func(ctx context.Context, tx store.Tx) error {
		_, err := j.Maintain(ctx, tx, c.Tenant)
		return err
	})
	switch {
	case errors.Is(err, signer.ErrIntegrity):
		return &jobs.Failure{Code: CodeIntegrity, Permanent: true, Err: err}
	case errors.Is(err, signer.ErrNoKeyset):
		return nil // the tenant has no addc key (yet); nothing to maintain
	case err != nil:
		return &jobs.Failure{Code: CodeMaintFail, Err: err}
	}
	return nil
}
