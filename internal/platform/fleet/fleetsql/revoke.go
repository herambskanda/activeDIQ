package fleetsql

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/gateway"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// PermissionRevoke is the permission that may revoke a component (DM-12 lifecycle). It is a tenant
// permission. Revoking is the emergency action, so it asks for no fresh multi-factor check.
const PermissionRevoke = "fleet.component.revoke"

// Revoke errors.
var (
	ErrRevokeForbidden = errors.New("fleetsql: the principal may not revoke components")
	// ErrNotRevocable: no such component in the tenant, or it is not enrolled or active (a pending
	// component has no certificate to revoke; a revoked or removed one already has none that works).
	ErrNotRevocable = errors.New("fleetsql: component cannot be revoked")
)

// StreamCloser closes the open streams of a component. *gateway.Gateway implements it.
type StreamCloser interface {
	CloseComponent(tid tenant.ID, componentID string) int
}

// Lifecycle is the component lifecycle after enrolment: revocation (TM-TB6-T9) and the state check
// the gateway makes on every RPC. Revoking an unused enrollment token is Enrollment's business.
type Lifecycle struct {
	DB      *store.DB
	Authz   apihost.Authorizer
	Audit   audit.Sink
	Streams StreamCloser     // may be nil where no gateway runs in the process; streams then end at their next re-check
	Clock   func() time.Time // tests only
}

var _ gateway.ComponentStatus = (*Lifecycle)(nil)

func (l *Lifecycle) now() time.Time {
	if l.Clock != nil {
		return l.Clock()
	}
	return time.Now()
}

// Revoke moves an enrolled or active component to revoked, records who did it in the same
// transaction, and then closes its open streams. The permission is checked server-side before any
// write. After the commit no RPC of the component passes the gateway (Usable is false), whatever its
// certificate's validity. It returns how many open streams this process closed; streams held by other
// server instances end at their next re-check.
func (l *Lifecycle) Revoke(ctx context.Context, tid tenant.ID, p apihost.Principal, componentID string) (int, error) {
	if l == nil || l.DB == nil || l.Authz == nil || l.Audit == nil {
		return 0, ErrNotConfigured
	}
	if p.ID == "" || utf8.RuneCountInString(p.ID) > 200 {
		return 0, ErrRevokeForbidden
	}
	if tid.IsZero() || !fleet.IsComponentID(componentID) {
		return 0, ErrNotRevocable
	}
	// The permission is evaluated in the principal's own tenant, so tid must be exactly that tenant;
	// a platform principal (empty Tenant) is refused too. Fails closed before any write.
	if pt, perr := tenant.Parse(p.Tenant); perr != nil || pt != tid {
		return 0, ErrRevokeForbidden
	}
	ok, err := l.Authz.Allow(ctx, p, PermissionRevoke, "tenant")
	if err != nil {
		return 0, fmt.Errorf("fleetsql: authorize: %w", err)
	}
	if !ok {
		return 0, ErrRevokeForbidden
	}
	err = l.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		var kind, serial string
		err := tx.QueryRow(ctx, `UPDATE public.components SET state = 'revoked', updated_at = now()
			WHERE id = $1::uuid AND state IN ('enrolled', 'active')
			RETURNING kind, COALESCE(cert_serial, '')`, componentID).Scan(&kind, &serial)
		if store.IsNoRows(err) {
			return ErrNotRevocable
		}
		if err != nil {
			return fmt.Errorf("fleetsql: revoke component: %w", err)
		}
		return l.Audit.Append(ctx, tx, audit.Event{
			ID:        "fleet.component.revoked." + componentID,
			Kind:      "fleet.component.revoked",
			At:        l.now(),
			Actor:     humanActor(p),
			Target:    authority.TargetRef{GUID: componentID, Class: "component"},
			Component: "fleet",
			Outcome:   audit.Success,
			Details:   []chain.Detail{{Key: "cert_serial", Value: serial}, {Key: "component_kind", Value: kind}},
		})
	})
	if err != nil {
		return 0, err
	}
	if l.Streams == nil {
		return 0, nil
	}
	return l.Streams.CloseComponent(tid, componentID), nil
}

func humanActor(p apihost.Principal) authority.Chain {
	kind := authority.Human
	if p.Kind == apihost.KindToken {
		kind = authority.APIToken
	}
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(p.ID), Kind: kind}}
}

// Usable reports whether the identified component may use the fleet listener: it exists in the
// tenant its certificate names and is enrolled or active. The certificate's serial is not compared:
// this is the open-stream re-check, and a rotation must not drop the stream it was made on. Use
// Current at establishment.
func (l *Lifecycle) Usable(ctx context.Context, id fleet.Identity) (bool, error) {
	return l.status(ctx, id, false)
}

// Current is Usable and requires id.Serial to equal the component's current cert_serial, so a
// certificate superseded by Rotate is refused until it expires (TM-TB6-T14). An empty serial never
// matches.
func (l *Lifecycle) Current(ctx context.Context, id fleet.Identity) (bool, error) {
	if id.Serial == "" {
		if l == nil || l.DB == nil {
			return false, ErrNotConfigured
		}
		return false, nil
	}
	return l.status(ctx, id, true)
}

func (l *Lifecycle) status(ctx context.Context, id fleet.Identity, bySerial bool) (bool, error) {
	if l == nil || l.DB == nil {
		return false, ErrNotConfigured
	}
	if id.Tenant.IsZero() || !fleet.IsComponentID(id.ComponentID) {
		return false, nil
	}
	var usable bool
	err := l.DB.WithTenant(ctx, id.Tenant, func(ctx context.Context, tx store.Tx) error {
		err := tx.QueryRow(ctx, `SELECT state IN ('enrolled', 'active') AND kind = $2
			AND (NOT $3::boolean OR cert_serial = $4)
			FROM public.components WHERE id = $1::uuid`, id.ComponentID, id.Kind, bySerial, id.Serial).Scan(&usable)
		if store.IsNoRows(err) {
			usable = false
			return nil
		}
		return err
	})
	if err != nil {
		return false, fmt.Errorf("fleetsql: component status: %w", err)
	}
	return usable, nil
}
