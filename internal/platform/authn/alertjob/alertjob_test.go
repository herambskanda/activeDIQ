package alertjob

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

type nopSink struct{}

func (nopSink) Append(context.Context, store.Tx, audit.Event) error { return nil }

const (
	owner   = "0b3f2f9e-6a1c-4c53-9a53-3a7a3f5f1c01"
	account = "0b3f2f9e-6a1c-4c53-9a53-3a7a3f5f1c02"
)

// The Sink makes one Delivery per (notice, owner) once, counts them by source, and the Renderer's text names
// the account, time and source address and nothing else.
func TestSinkAndRendererOverRealDeliveries(t *testing.T) {
	d := storetest.One(t).NewDatabase(t)
	d.Migrate(t)
	ten := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ds, err := delivery.New(nopSink{})
	if err != nil {
		t.Fatal(err)
	}
	s := Sink{Deliveries: ds}
	ctx := context.Background()
	at := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	var notice string
	err = db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO public.authn_accounts (tenant_id, id, kind, display_name, created_by) VALUES ($1::uuid, $2::uuid, 'local', 'Break Glass', 'system')`, ten.String(), account); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO public.authn_authority_notices (tenant_id, subject_id, event, created_at, source_ip)
VALUES ($1::uuid, $2::uuid, 'break_glass_used', $3, '198.51.100.7') RETURNING id::text`, ten.String(), account, at).Scan(&notice); err != nil {
			return err
		}
		for i := 0; i < 2; i++ { // a repeated fan-out is harmless
			if err := s.Enqueue(ctx, tx, authnDelivery(notice, owner)); err != nil {
				return err
			}
		}
		total, given, err := s.Given(ctx, tx, notice)
		if err != nil || total != 1 || given != 0 {
			t.Errorf("counts = %d/%d, %v; want 1 delivery, none given up", total, given, err)
		}
		dl, ok, err := ds.ForSource(ctx, tx, delivery.SourceRef{Kind: SourceKind, ID: notice}, delivery.Recipient{Account: owner})
		if err != nil || !ok {
			t.Fatalf("delivery for source: %v, %v", ok, err)
		}
		c, err := Renderer{Tenant: func() (tenant.ID, bool) { return ten, true }}.Render(ctx, tx, dl)
		if err != nil {
			return err
		}
		for _, want := range []string{"Break Glass", "198.51.100.7", "2026-11-06T09:00:00Z"} {
			if !strings.Contains(c.Text, want) {
				t.Errorf("body lacks %q:\n%s", want, c.Text)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func authnDelivery(notice, recipient string) authn.AlertDelivery {
	return authn.AlertDelivery{Notice: notice, Recipient: recipient}
}

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }
