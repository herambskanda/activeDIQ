package fleetsql

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// KindTunnelProtocolError is the audit kind of a tunnel closed for a protocol violation (TM-D24 B5).
const KindTunnelProtocolError audit.Kind = "fleet.tunnel.protocol_error"

// ErrReporterNotConfigured is returned by TunnelReporter when it lacks its database or audit sink.
var ErrReporterNotConfigured = errors.New("fleetsql: tunnel reporter is not configured")

// TunnelReporter implements fleet.Reporter over the audit port. The event names the component (its
// GUID, kind and certificate serial) and carries the fixed violation code only: nothing the peer sent
// is copied into it (TM-D24 C2).
type TunnelReporter struct {
	DB    *store.DB
	Audit audit.Sink
	Clock func() time.Time // tests only
}

var _ fleet.Reporter = (*TunnelReporter)(nil)

// ProtocolError appends one audit event in the component's tenant.
func (r *TunnelReporter) ProtocolError(ctx context.Context, id fleet.Identity, v fleet.Violation) error {
	if r == nil || r.DB == nil || r.Audit == nil {
		return ErrReporterNotConfigured
	}
	if id.Tenant.IsZero() {
		return fmt.Errorf("fleetsql: tunnel report without a tenant")
	}
	now := time.Now
	if r.Clock != nil {
		now = r.Clock
	}
	at := now()
	return r.DB.WithTenant(ctx, id.Tenant, func(ctx context.Context, tx store.Tx) error {
		return r.Audit.Append(ctx, tx, audit.Event{
			// Unique per occurrence: a component that keeps misbehaving is recorded each time.
			ID:        fmt.Sprintf("%s.%s.%d", KindTunnelProtocolError, id.ComponentID, at.UnixNano()),
			Kind:      KindTunnelProtocolError,
			At:        at,
			Actor:     componentActor(id.ComponentID),
			Target:    authority.TargetRef{GUID: id.ComponentID, Class: "component"},
			Component: "fleet",
			Outcome:   audit.Denied,
			Reason:    string(v),
			Details: []chain.Detail{
				{Key: "cert_serial", Value: id.Serial},
				{Key: "component_kind", Value: id.Kind},
				{Key: "violation", Value: string(v)},
			},
		})
	})
}
