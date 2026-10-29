package fleetsql

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// PermissionCAWithdraw is the fleet-CA-admin right: it may withdraw a tenant's installation CA on the
// compromise path (fleet-contract 'CA key rollover' step 5). It is a tenant permission.
const PermissionCAWithdraw = "fleet.ca.withdraw"

// maxWithdrawReason bounds the free-text reason recorded in the audit trail.
const maxWithdrawReason = 200

// Withdraw errors. None carries key material, stored bytes or SQL.
var (
	ErrWithdrawForbidden = errors.New("fleetsql: the principal may not withdraw the fleet CA")
	// ErrWithdrawRefused: no such CA in the tenant, or it is already withdrawn (terminal, TM-D29).
	ErrWithdrawRefused = errors.New("fleetsql: CA cannot be withdrawn")
	// ErrWithdrawReason: the reason is empty, too long or contains control characters.
	ErrWithdrawReason = errors.New("fleetsql: a withdrawal needs a short plain-text reason")
)

// PoolInvalidator asks the gateway's client-CA pool to refresh now. *gateway.PoolProvider implements it.
type PoolInvalidator interface {
	Invalidate()
}

// TenantCloser closes every open stream of a tenant. *gateway.Gateway implements it.
type TenantCloser interface {
	CloseTenant(tid tenant.ID) int
}

// CAAdmin commits fleet CA withdrawals. It is the committing process that the gateway's F-POOL-8 bound
// (fleet-contract 'Gateway client-CA pool') names: after the commit it invalidates the pool and closes
// the tenant's open streams in the same step. Both ports are required, so a process that can commit a
// withdrawal cannot forget either; other gateway nodes drop the tenant's streams at their next re-check.
type CAAdmin struct {
	DB      *store.DB
	Authz   apihost.Authorizer
	Keys    KeySource // seals the replacement CA's key (TM-D7)
	Audit   audit.Sink
	StepUp  apihost.StepUpChecker
	Pool    PoolInvalidator
	Streams TenantCloser
	Clock   func() time.Time // tests only
}

// Withdrawn describes a committed withdrawal.
type Withdrawn struct {
	// ClosedStreams is how many open streams this process closed.
	ClosedStreams int
	// Replaced is true when the withdrawn CA was the active one and a new active CA took its place.
	Replaced bool
}

func (a *CAAdmin) now() time.Time {
	if a.Clock != nil {
		return a.Clock()
	}
	return time.Now()
}

// Withdraw moves the tenant's CA caID (an active or retired row) to the terminal withdrawn state and
// destroys its sealed key; when that CA was the active one, a replacement active CA is inserted in the
// same transaction (the commit-time guard of migration 0055 refuses a bare withdrawal of the active CA).
// A withdrawn retired CA needs no replacement: the tenant's active CA stays. The audit event is
// appended in that transaction, so no withdrawal exists without its record. Only after the commit does
// it call PoolProvider.Invalidate and Gateway.CloseTenant. The permission is checked server-side before
// any write.
func (a *CAAdmin) Withdraw(ctx context.Context, tid tenant.ID, p apihost.Principal, caID, reason string) (Withdrawn, error) {
	if a == nil || a.DB == nil || a.Authz == nil || a.Keys == nil || a.Audit == nil || a.StepUp == nil || a.Pool == nil || a.Streams == nil {
		return Withdrawn{}, ErrNotConfigured
	}
	if p.ID == "" || utf8.RuneCountInString(p.ID) > 200 {
		return Withdrawn{}, ErrWithdrawForbidden
	}
	// The permission is evaluated in the principal's own tenant, so the target tenant must be exactly
	// that tenant: no cross-tenant withdrawal, and a platform principal (empty Tenant) is refused too.
	if pt, perr := tenant.Parse(p.Tenant); perr != nil || pt != tid {
		return Withdrawn{}, ErrWithdrawForbidden
	}
	ok, err := a.Authz.Allow(ctx, p, PermissionCAWithdraw, "tenant")
	if err != nil {
		return Withdrawn{}, fmt.Errorf("fleetsql: authorize: %w", err)
	}
	if !ok {
		return Withdrawn{}, ErrWithdrawForbidden
	}
	// Destroying a tenant's fleet trust is Tier-0: a fresh step-up, never satisfied by an API token.
	fresh, err := a.StepUp.Fresh(ctx, p)
	if err != nil {
		return Withdrawn{}, fmt.Errorf("fleetsql: step-up check: %w", err)
	}
	if !fresh {
		return Withdrawn{}, ErrStepUpRequired
	}
	if !validReason(reason) {
		return Withdrawn{}, ErrWithdrawReason
	}
	if tid.IsZero() || !fleet.IsComponentID(caID) { // same canonical lower-case UUID shape
		return Withdrawn{}, ErrWithdrawRefused
	}
	var out Withdrawn
	err = a.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		var (
			state string
			der   []byte
		)
		err := tx.QueryRow(ctx, `SELECT state, cert_der FROM public.fleet_ca
			WHERE id = $1::uuid AND state IN ('active', 'retired') FOR UPDATE`, caID).Scan(&state, &der)
		if store.IsNoRows(err) {
			return ErrWithdrawRefused
		}
		if err != nil {
			return fmt.Errorf("fleetsql: read CA: %w", err)
		}
		old, _, perr := parseStoredCert(der)
		if perr != nil {
			return errCAIntegrity
		}
		// The terminal state and the destroyed key are one statement (fleet_ca_guard).
		if _, err := tx.Exec(ctx, `UPDATE public.fleet_ca SET state = 'withdrawn', sealed_key = NULL
			WHERE id = $1::uuid`, caID); err != nil {
			return fmt.Errorf("fleetsql: withdraw CA: %w", err)
		}
		details := []chain.Detail{
			{Key: "tenant", Value: tid.String()},
			{Key: "ca_serial", Value: old.SerialNumber.Text(16)},
			{Key: "ca_spki", Value: PinOf(old)},
			{Key: "previous_state", Value: state},
			{Key: "reason", Value: reason},
		}
		if state == "active" {
			nc, err := createCA(ctx, tx, a.Keys, tid, a.now())
			if err != nil {
				return err
			}
			out.Replaced = true
			details = append(details, chain.Detail{Key: "replacement_spki", Value: PinOf(nc)})
		}
		return a.Audit.Append(ctx, tx, audit.Event{
			ID:        "fleet.ca.withdrawn." + caID,
			Kind:      "fleet.ca.withdrawn",
			At:        a.now(),
			Actor:     humanActor(p),
			Target:    authority.TargetRef{GUID: caID, Class: "fleet_ca"},
			Component: "fleet",
			Outcome:   audit.Success,
			Details:   details,
		})
	})
	if err != nil {
		if store.SQLState(err) == "AD403" { // the commit-time guard: no usable replacement
			return Withdrawn{}, ErrWithdrawRefused
		}
		return Withdrawn{}, err
	}
	// Committed. Same step (F-POOL-8): the pool refreshes now, and this process's streams of the tenant end.
	a.Pool.Invalidate()
	out.ClosedStreams = a.Streams.CloseTenant(tid)
	return out, nil
}

func validReason(s string) bool {
	n := utf8.RuneCountInString(s)
	if n == 0 || n > maxWithdrawReason || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) { // Cf (RLO, ZWSP) would spoof the audit display
			return false
		}
	}
	return true
}
