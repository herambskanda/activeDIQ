package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	t0Conn = "11111111-1111-4111-8111-111111111111"
	t0Obj  = "22222222-2222-4222-8222-222222222222"
)

type t0Conns struct{ seen []tenant.ID }

func (c *t0Conns) Get(_ context.Context, tid tenant.ID, id connection.ID) (connection.Connection, error) {
	c.seen = append(c.seen, tid)
	return connection.Connection{ID: id, Kind: connection.KindADForest}, nil
}
func (*t0Conns) Confirmed(context.Context, tenant.ID, connection.ID, connection.NCGUID, connection.ID) (bool, error) {
	return false, nil
}
func (*t0Conns) HasHybridLink(context.Context, tenant.ID, connection.ID) (bool, error) {
	return false, nil
}
func (*t0Conns) Tier0OverrideInForce(context.Context, tenant.ID, connection.ID) (*connection.Tier0Override, error) {
	return nil, nil
}

type t0Rev struct{}

func (t0Rev) Tier0Revision(context.Context, tenant.ID) (uint64, error) { return 7, nil }

func t0Sources(c *t0Conns, inv *inventory.Fake) tier0Sources {
	return tier0Sources{Connections: c, Correlations: inv, Designations: inv, HybridLinks: c, Overrides: c, Revision: t0Rev{}}
}

func t0Op() client.WriteOp {
	return client.WriteOp{DigestKind: "x", Target: authority.TargetRef{Connection: t0Conn, GUID: t0Obj}}
}

// Both stages carry a built, non-nil Tier0Context, for the tenant on the request's context.
func TestTenantTier0BuildsPlanAndApplyContext(t *testing.T) {
	tid, other := tenant.New(), tenant.New()
	inv, c := inventory.NewFake(), &t0Conns{}
	for _, x := range []tenant.ID{tid, other} {
		inv.SetEvaluated(x, t0Conn, time.Now())
	}
	b, err := newTenantTier0(t0Sources(c, inv))
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range []client.Stage{client.StagePlan, client.StageApply} {
		got, err := b.Build(authority.WithTenant(context.Background(), tid.String()), st, t0Op())
		if err != nil || got.Context == nil {
			t.Fatalf("%s: ctx=%v err=%v", st, got.Context, err)
		}
		if got.Context.Tier0Revision != 7 || len(got.Context.Statements) != 1 {
			t.Fatalf("%s: context not built from sources: %+v", st, got.Context)
		}
	}
	if _, err := b.Build(authority.WithTenant(context.Background(), other.String()), client.StagePlan, t0Op()); err != nil {
		t.Fatal(err)
	}
	if c.seen[0] != tid || c.seen[len(c.seen)-1] != other {
		t.Fatalf("builders not scoped per tenant: %v", c.seen)
	}
	if len(b.per) != 2 {
		t.Fatalf("want one cached builder per tenant, got %d", len(b.per))
	}
}

func TestTenantTier0RefusesWithoutTenant(t *testing.T) {
	b, _ := newTenantTier0(t0Sources(&t0Conns{}, inventory.NewFake()))
	for _, ctx := range []context.Context{context.Background(), authority.WithTenant(context.Background(), "nope")} {
		if _, err := b.Build(ctx, client.StagePlan, t0Op()); !errors.Is(err, ErrNoTier0Tenant) {
			t.Fatalf("want ErrNoTier0Tenant, got %v", err)
		}
	}
}

// A missing required source fails composition; it never yields a nil builder.
func TestNewTenantTier0MissingSourceFailsStartup(t *testing.T) {
	full := func() tier0Sources { return t0Sources(&t0Conns{}, inventory.NewFake()) }
	cases := map[string]func(*tier0Sources){
		"connections":  func(s *tier0Sources) { s.Connections = nil },
		"correlations": func(s *tier0Sources) { s.Correlations = nil },
		"designations": func(s *tier0Sources) { s.Designations = nil },
		"hybrid links": func(s *tier0Sources) { s.HybridLinks = nil },
		"overrides":    func(s *tier0Sources) { s.Overrides = nil },
		"revision":     func(s *tier0Sources) { s.Revision = nil },
	}
	for name, drop := range cases {
		s := full()
		drop(&s)
		if b, err := newTenantTier0(s); err == nil || b != nil {
			t.Errorf("%s: want startup failure, got builder=%v err=%v", name, b, err)
		}
	}
	if _, err := newTenantTier0(full()); err != nil { // the optional refresher may be absent
		t.Fatal(err)
	}
	if b, err := buildTier0(nil, nil); err == nil || b != nil {
		t.Fatal("no store must fail composition")
	}
}

// The directory client composed with the builder passes its own no-builder guard.
func TestDirectoryFactsCarriesTier0Builder(t *testing.T) {
	b, _ := newTenantTier0(t0Sources(&t0Conns{}, inventory.NewFake()))
	var _ client.Tier0Builder = b
	if directoryFacts(nil, client.WithTier0Builder(b)) == nil {
		t.Fatal("nil client")
	}
}
