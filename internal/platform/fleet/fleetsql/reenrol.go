package fleetsql

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Emergency policy-key rotation, re-enrolment half (ADR-0007 §7, TM-D16). A policy key believed
// stolen can sign a keyset, so the keyset chain cannot recover on its own: the only way to replace
// an agent's anchor is a new enrolment (ADR-0007 §5). ReenrolAddc revokes every enrolled or active
// DC agent of a tenant and gives each a pending successor with a fresh single-use token; when the
// administrator redeems the token on the DC, the agent re-anchors on the keyset delivered on its
// first authenticated call. Generating the new key is the policy signer's job (not this package);
// the runbook fixes the order: new key first, then this sweep.

// Reasons for a sweep: a closed vocabulary, recorded in the audit trail (never free text).
const (
	ReasonKeyExposure   = "suspected_key_exposure"
	ReasonBackupRestore = "backup_restored_to_new_host"
)

// Errors of the sweep.
var (
	ErrReenrolForbidden = errors.New("fleetsql: the principal may not run the emergency re-enrolment")
	ErrReenrolReason    = errors.New("fleetsql: the re-enrolment reason is not one of the allowed codes")
	ErrReenrolCutoff    = errors.New("fleetsql: the re-enrolment cutoff is missing or in the future")
)

// Reenroller runs the emergency sweep. It needs both the revoke and the issue permission (least
// privilege: no new, broader right) and a fresh multi-factor check, because it issues credentials.
type Reenroller struct {
	DB      *store.DB
	Authz   apihost.Authorizer
	StepUp  apihost.StepUpChecker
	Audit   audit.Sink
	Streams StreamCloser     // may be nil; open streams then end at their next re-check
	Clock   func() time.Time // tests only
}

// ReenrolRequest is the sweep's input.
type ReenrolRequest struct {
	Reason string // ReasonKeyExposure or ReasonBackupRestore
	// EnrolledBefore is required: the moment the new policy key became the one the server delivers.
	// Only agents created before it are swept, so agents that already re-anchored on the new key
	// (and a concurrent or repeated sweep) are never revoked again. Zero or future values are refused.
	EnrolledBefore time.Time
	TTL            time.Duration // lifetime of each new token; 0 means DefaultTTL
}

// ReenrolItem is the per-agent outcome. Token is the only copy of the plaintext; it is empty when
// Err is set.
type ReenrolItem struct {
	OldComponentID string
	NewComponentID string
	Name           string
	Token          Token
	ExpiresAt      time.Time
	StreamsClosed  int
	Err            error // nil on success; typed, never carries a token or SQL
}

// ReenrolResult is "n of m succeeded, the rest failed with reasons".
type ReenrolResult struct {
	SweepID string
	Items   []ReenrolItem
}

// Succeeded counts the agents that now await re-enrolment.
func (r ReenrolResult) Succeeded() int {
	n := 0
	for _, it := range r.Items {
		if it.Err == nil {
			n++
		}
	}
	return n
}

func (r *Reenroller) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

// ReenrolAddc revokes every enrolled or active addc component of the tenant and issues its
// successor. Each agent is one transaction (revoke, successor, token, audit), so a crash or a
// cancellation leaves every agent either untouched or fully swapped, and re-running the sweep
// only handles agents created before the required cutoff and still enrolled: it is idempotent
// and resumable, and never revokes a successor that has redeemed its token. Authorisation and step-up are
// checked before anything is written. A failing agent does not stop the others; its error is in
// the result. Cancelling ctx stops before the next agent and returns what was done.
func (r *Reenroller) ReenrolAddc(ctx context.Context, tid tenant.ID, p apihost.Principal, req ReenrolRequest) (ReenrolResult, error) {
	if r == nil || r.DB == nil || r.Authz == nil || r.StepUp == nil || r.Audit == nil {
		return ReenrolResult{}, ErrNotConfigured
	}
	if req.Reason != ReasonKeyExposure && req.Reason != ReasonBackupRestore {
		return ReenrolResult{}, ErrReenrolReason
	}
	ttl, err := NewComponent{Kind: KindADDC, Name: "x", TTL: req.TTL}.validate()
	if err != nil {
		return ReenrolResult{}, err
	}
	cutoff := req.EnrolledBefore.UTC()
	if req.EnrolledBefore.IsZero() || cutoff.After(r.now()) {
		return ReenrolResult{}, ErrReenrolCutoff
	}
	if tid.IsZero() || p.ID == "" || utf8.RuneCountInString(p.ID) > 200 {
		return ReenrolResult{}, ErrReenrolForbidden
	}
	// Permissions are evaluated in the principal's own tenant: tid must be that tenant (platform refused).
	if pt, perr := tenantref.TenantFromText(p.Tenant); perr != nil || pt != tid {
		return ReenrolResult{}, ErrReenrolForbidden
	}
	for _, perm := range []string{PermissionRevoke, PermissionIssue} {
		ok, err := r.Authz.Allow(ctx, p, perm, "tenant")
		if err != nil {
			return ReenrolResult{}, fmt.Errorf("fleetsql: authorize: %w", err)
		}
		if !ok {
			return ReenrolResult{}, ErrReenrolForbidden
		}
	}
	fresh, err := r.StepUp.Fresh(ctx, p)
	if err != nil {
		return ReenrolResult{}, fmt.Errorf("fleetsql: step-up check: %w", err)
	}
	if !fresh {
		return ReenrolResult{}, ErrStepUpRequired
	}

	var sweep [8]byte
	if _, err := rand.Read(sweep[:]); err != nil {
		return ReenrolResult{}, fmt.Errorf("fleetsql: no entropy: %w", err)
	}
	res := ReenrolResult{SweepID: hex.EncodeToString(sweep[:])}

	type target struct{ id, name string }
	var targets []target
	err = r.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, name FROM public.components
			WHERE kind = $1 AND state IN ('enrolled', 'active') AND created_at < $2
			ORDER BY created_at, id`, string(KindADDC), cutoff)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t target
			if err := rows.Scan(&t.id, &t.name); err != nil {
				return err
			}
			targets = append(targets, t)
		}
		return rows.Err()
	})
	if err != nil {
		return res, fmt.Errorf("fleetsql: list addc components: %w", err)
	}

	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		it := r.one(ctx, tid, p, req.Reason, res.SweepID, ttl, cutoff, t.id, t.name)
		res.Items = append(res.Items, it)
	}

	// The summary is one more audit event; it is written even if some agents failed, so the trail
	// shows the sweep was run and how it ended. Cancelled contexts still get their record.
	sctx := context.WithoutCancel(ctx)
	outcome := audit.Success
	if res.Succeeded() != len(targets) {
		outcome = audit.Failure
	}
	err = r.DB.WithTenant(sctx, tid, func(ctx context.Context, tx store.Tx) error {
		return r.Audit.Append(ctx, tx, audit.Event{
			ID:        "fleet.agents.reenrol-sweep." + res.SweepID,
			Kind:      "fleet.agents.reenrol_sweep",
			At:        r.now(),
			Actor:     humanActor(p),
			Target:    authority.TargetRef{GUID: tid.String(), Class: "tenant"},
			Component: "fleet",
			Outcome:   outcome,
			Reason:    req.Reason,
			Details: []chain.Detail{
				{Key: "agents_failed", Value: fmt.Sprint(len(targets) - res.Succeeded())},
				{Key: "agents_found", Value: fmt.Sprint(len(targets))},
				{Key: "agents_reenrolling", Value: fmt.Sprint(res.Succeeded())},
				{Key: "enrolled_before", Value: cutoff.Format(time.RFC3339Nano)},
				{Key: "sweep_id", Value: res.SweepID},
			},
		})
	})
	if err != nil {
		return res, fmt.Errorf("fleetsql: audit sweep summary: %w", err)
	}
	return res, nil
}

func (r *Reenroller) one(ctx context.Context, tid tenant.ID, p apihost.Principal, reason, sweepID string, ttl time.Duration, cutoff time.Time, oldID, name string) ReenrolItem {
	it := ReenrolItem{OldComponentID: oldID, Name: name}
	tok, h, err := newToken(tid)
	if err != nil {
		it.Err = err
		return it
	}
	err = r.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		var serial string
		err := tx.QueryRow(ctx, `UPDATE public.components SET state = 'revoked', updated_at = now()
			WHERE id = $1::uuid AND kind = $2 AND state IN ('enrolled', 'active') AND created_at < $3
			RETURNING COALESCE(cert_serial, '')`, oldID, string(KindADDC), cutoff).Scan(&serial)
		if store.IsNoRows(err) {
			return ErrNotRevocable // changed since the listing: another sweep or a manual revoke got it
		}
		if err != nil {
			return fmt.Errorf("fleetsql: revoke component: %w", err)
		}
		if err := tx.QueryRow(ctx, `INSERT INTO public.components (tenant_id, kind, name)
			VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1, $2) RETURNING id::text`,
			string(KindADDC), name).Scan(&it.NewComponentID); err != nil {
			return fmt.Errorf("fleetsql: create successor: %w", err)
		}
		if err := tx.QueryRow(ctx, `INSERT INTO public.enrollment_tokens (tenant_id, component_id, token_hash, issued_by, expires_at)
			VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3, now() + make_interval(secs => $4::float8))
			RETURNING expires_at`, it.NewComponentID, h[:], p.ID, ttl.Seconds()).Scan(&it.ExpiresAt); err != nil {
			return fmt.Errorf("fleetsql: store token: %w", err)
		}
		return r.Audit.Append(ctx, tx, audit.Event{
			ID:        "fleet.component.reenrol." + oldID,
			Kind:      "fleet.component.revoked",
			At:        r.now(),
			Actor:     humanActor(p),
			Target:    authority.TargetRef{GUID: oldID, Class: "component"},
			Component: "fleet",
			Outcome:   audit.Success,
			Reason:    reason,
			Details: []chain.Detail{
				{Key: "cert_serial", Value: serial},
				{Key: "component_kind", Value: string(KindADDC)},
				{Key: "new_component_id", Value: it.NewComponentID},
				{Key: "sweep_id", Value: sweepID},
			},
		})
	})
	if err != nil {
		it.NewComponentID, it.ExpiresAt = "", time.Time{}
		it.Err = err
		return it
	}
	it.Token = tok
	if r.Streams != nil {
		it.StreamsClosed = r.Streams.CloseComponent(tid, oldID)
	}
	return it
}
