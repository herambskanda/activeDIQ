package fleetsql

import (
	"context"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/gateway"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// KindSupersededCertificate is the audit kind of a superseded certificate presented to the gateway
// (TM-TB6-T14).
const KindSupersededCertificate audit.Kind = "fleet.component.superseded_certificate"

// SupersededReporter implements gateway.SupersededReporter: one fleet alert (same channel as
// AlertCAMaterial) and one audit event naming the component, the presented serial and the serial that
// is current. The response to either reading (stale component or thief who rotated first) is Revoke.
// Rate limiting is the gateway's, not this type's.
type SupersededReporter struct {
	DB     *store.DB
	Audit  audit.Sink
	Alerts Alerter
	Clock  func() time.Time // tests only
}

var _ gateway.SupersededReporter = (*SupersededReporter)(nil)

// Superseded appends the audit event in the component's tenant and raises the alert. The alert is
// raised even if the audit append fails, and the append error is returned.
func (r *SupersededReporter) Superseded(ctx context.Context, id fleet.Identity) error {
	if r == nil || r.DB == nil || r.Audit == nil || r.Alerts == nil {
		return ErrReporterNotConfigured
	}
	if id.Tenant.IsZero() || !fleet.IsComponentID(id.ComponentID) {
		return fmt.Errorf("fleetsql: superseded report without a component")
	}
	now := time.Now
	if r.Clock != nil {
		now = r.Clock
	}
	at := now()
	r.Alerts.Raise(ctx, Alert{Kind: AlertSupersededCert, Tenant: id.Tenant, Component: id.ComponentID})
	return r.DB.WithTenant(ctx, id.Tenant, func(ctx context.Context, tx store.Tx) error {
		var current string
		err := tx.QueryRow(ctx, `SELECT COALESCE(cert_serial, '') FROM public.components WHERE id = $1::uuid`,
			id.ComponentID).Scan(&current)
		if err != nil && !store.IsNoRows(err) {
			return fmt.Errorf("fleetsql: superseded report: %w", err)
		}
		return r.Audit.Append(ctx, tx, audit.Event{
			ID:        fmt.Sprintf("%s.%s.%s.%d", KindSupersededCertificate, id.ComponentID, id.Serial, at.UnixNano()),
			Kind:      KindSupersededCertificate,
			At:        at,
			Actor:     componentActor(id.ComponentID),
			Target:    authority.TargetRef{GUID: id.ComponentID, Class: "component"},
			Component: "fleet",
			Outcome:   audit.Denied,
			Reason:    "superseded_certificate",
			Details: []chain.Detail{
				{Key: "component_kind", Value: id.Kind},
				{Key: "current_serial", Value: current},
				{Key: "presented_serial", Value: id.Serial},
			},
		})
	})
}
