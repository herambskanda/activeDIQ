package inventory_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func TestFakeKeepsTheReaderContract(t *testing.T) {
	f := inventory.NewFake()
	a, b := tenant.New(), tenant.New()
	ad := inventory.Ref{Connection: "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa", Object: adG1}
	en := inventory.Ref{Connection: "eeeeeeee-1111-4111-8111-eeeeeeeeeeee", Object: enG1}
	f.AddLink(a, inventory.Link{Self: ad, Peer: en, PeerKind: "entra_tenant", State: inventory.StateBroken, PeerTier0: true, PeerBases: []inventory.Basis{"E1"}})
	f.AddLink(a, inventory.Link{Self: ad, Peer: inventory.Ref{Connection: en.Connection, Object: enG2}, PeerKind: "entra_tenant", State: inventory.StateRemoved})
	ctx := context.Background()
	got, err := f.CorrelationsFor(ctx, a, ad)
	if err != nil || len(got) != 1 || got[0].State != inventory.StateBroken || !got[0].PeerTier0 {
		t.Fatalf("%v %+v", err, got)
	}
	got, err = f.CorrelationsFor(ctx, a, en)
	if err != nil || len(got) != 1 || got[0].Peer != ad || got[0].SelfTier0 != true || got[0].PeerKind != "ad_forest" {
		t.Fatalf("mirror: %v %+v", err, got)
	}
	if got, _ := f.CorrelationsFor(ctx, b, ad); len(got) != 0 {
		t.Fatalf("tenant scope: %+v", got)
	}
	f.Err = errors.New("down")
	if got, err := f.CorrelationsFor(ctx, a, ad); err == nil || got != nil {
		t.Fatalf("error must not be empty: %v %v", got, err)
	}
	f.Err = nil
	f.Designate(a, ad.Connection, adG2)
	f.AddMembership(a, ad.Connection, adG1, adG2)
	d, err := f.DesignationsFor(ctx, a, ad.Connection, []inventory.GUID{adG1})
	if err != nil || !reflect.DeepEqual(d, []inventory.GUID{adG2}) {
		t.Fatalf("%v %v", err, d)
	}
	if d, _ := f.DesignationsFor(ctx, b, ad.Connection, []inventory.GUID{adG1}); len(d) != 0 {
		t.Fatalf("tenant scope: %v", d)
	}
}
