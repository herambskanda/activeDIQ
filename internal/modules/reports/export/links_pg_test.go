package export_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// perAccount is an Authorizer and account store that differ by account.
type perAccount struct {
	mu       sync.Mutex
	noExport map[string]bool
	disabled map[string]bool
}

func (p *perAccount) Allow(_ context.Context, _ tenant.ID, c authority.Chain, perm authz.Permission) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !(perm == export.ExportPerm && p.noExport[string(c.Requester.ID)]), nil
}

func (p *perAccount) Active(_ context.Context, _ store.Tx, _ tenant.ID, a string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.disabled[a], nil
}

const carol = "00000000-0000-4000-8000-0000000000c3"

// Test_delivery_link_authorised_by_delivery_row is RP10 (reports.md 7.2, AC-47): a non-creator reads an export
// only if a DM-84 Delivery row names this export and this account, and still holds reports.export.
func Test_delivery_link_authorised_by_delivery_row(t *testing.T) {
	storetest.EachVersion(t, rp10)
}

func rp10(t *testing.T, s *storetest.Server) {
	e := setup(t, s)
	ctx := context.Background()
	pa := &perAccount{noExport: map[string]bool{}, disabled: map[string]bool{}}
	dl, err := delivery.New(e.sink)
	if err != nil {
		t.Fatal(err)
	}
	e.exp.Authz = pa
	e.exp.Links = export.DeliveryLinks{Deliveries: dl, Owners: ownerFunc(pa.Active)}

	// alice owns the schedule and so the export; bob is sent it, carol is not.
	x := e.export(alice, e.finishedRun(alice).ID, export.CSV)
	want, _, err := e.download(alice, x.ID)
	if err != nil {
		t.Fatal(err)
	}
	send := func(to string) {
		t.Helper()
		if err := e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) error {
			_, err := dl.Enqueue(ctx, tx, delivery.NewDelivery{DedupKey: "fire1:" + to, Purpose: "reports.schedule.delivery", TemplateVersion: 1,
				Variables: map[string]string{}, Recipient: delivery.Recipient{Account: to}, Source: delivery.SourceRef{Kind: export.SourceKind, ID: x.ID.String()}}, chainOf(alice))
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	denied := func() int { return len(e.sink.of(export.KindDownloadDenied)) }
	refused := func(who string, check string) {
		t.Helper()
		before := denied()
		if _, _, err := e.download(who, x.ID); !errors.Is(err, export.ErrExportNotFound) {
			t.Fatalf("%s: err = %v, want not found", who[len(who)-2:], err)
		}
		evs := e.sink.of(export.KindDownloadDenied)
		if len(evs) != before+1 || detail(evs[len(evs)-1], "check") != check {
			t.Fatalf("download_denied after refusal = %d events, last check %q, want check %q", len(evs)-before, detail(evs[len(evs)-1], "check"), check)
		}
	}

	send(bob)
	got, _, err := e.download(bob, x.ID)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("the named recipient: err %v, bytes equal %v", err, bytes.Equal(got, want))
	}
	if n := len(e.sink.of(export.KindDownloaded)); n < 2 {
		t.Fatalf("downloaded events = %d, want the recipient's audited too", n)
	}
	refused(carol, "delivery") // holds reports.export, was never sent the file

	pa.noExport[bob] = true // lost reports.export
	refused(bob, "permission")
	delete(pa.noExport, bob)

	pa.disabled[bob] = true
	refused(bob, "account")
	delete(pa.disabled, bob)

	// Removal from the schedule changes no Delivery row: the earlier fire's file is still theirs.
	if got, _, err = e.download(bob, x.ID); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("recipient after schedule removal: %v", err)
	}

	// An export ID of nothing (another tenant's is invisible under RLS the same way) is not found.
	if _, _, err := e.download(bob, export.NewID()); !errors.Is(err, export.ErrExportNotFound) {
		t.Fatalf("unknown export: %v", err)
	}

	// No Links port: every non-creator is refused, the path fails closed.
	e.exp.Links = nil
	refused(bob, "delivery")
}

type ownerFunc func(context.Context, store.Tx, tenant.ID, string) (bool, error)

func (f ownerFunc) Active(ctx context.Context, tx store.Tx, t tenant.ID, a string) (bool, error) {
	return f(ctx, tx, t, a)
}
