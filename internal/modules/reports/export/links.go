package export

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// SourceKind is the DM-84 source kind of a delivery whose source is an export: ("report_export", export id).
// The fire job writes it and DeliveryLinks reads it, so the two cannot drift.
const SourceKind = "report_export"

// DeliveryLinks is the LinkAuthority over notify's DM-84 Delivery row and the account store (reports.md 7.2).
type DeliveryLinks struct {
	Deliveries *delivery.Deliveries
	Owners     rbac.OwnerStatus
}

var _ LinkAuthority = DeliveryLinks{}

// SentTo implements LinkAuthority: a Delivery of this export to this account exists (ForSource answers false
// for another account, an address recipient, another tenant's row and a given-up delivery).
func (l DeliveryLinks) SentTo(ctx context.Context, tx store.Tx, id ID, account string) (bool, error) {
	if l.Deliveries == nil {
		return false, nil
	}
	_, ok, err := l.Deliveries.ForSource(ctx, tx, delivery.SourceRef{Kind: SourceKind, ID: id.String()}, delivery.Recipient{Account: account})
	return ok, err
}

// Active implements LinkAuthority.
func (l DeliveryLinks) Active(ctx context.Context, tx store.Tx, tid tenant.ID, account string) (bool, error) {
	if l.Owners == nil {
		return false, errors.New("export: no account status")
	}
	return l.Owners.Active(ctx, tx, tid, account)
}
