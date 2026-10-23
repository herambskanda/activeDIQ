package fleetsql_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type revokeAuthz struct{ allow bool }

func (a revokeAuthz) Allow(_ context.Context, _ apihost.Principal, perm, scope string) (bool, error) {
	return a.allow && perm == fleetsql.PermissionRevoke && scope == "tenant", nil
}

type closer struct{ calls []string }

func (c *closer) CloseComponent(tid tenant.ID, id string) int {
	c.calls = append(c.calls, tid.String()+"/"+id)
	return 2
}

func (e *enrollEnv) enrolled(t *testing.T, tid tenant.ID, kind fleetsql.Kind) fleet.Identity {
	t.Helper()
	iss := e.issue(t, tid, kind)
	csr, _ := csrFor(t, nil)
	got, err := e.enr.Enroll(context.Background(), peerIP, iss.Token.String(), csr)
	if err != nil {
		t.Fatal(err)
	}
	return got.Identity
}

func TestRevokeAndUsable(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		e := setupEnroll(t, s)
		cl := &closer{}
		lc := &fleetsql.Lifecycle{DB: e.db, Authz: revokeAuthz{true}, Audit: e.sink, Streams: cl}
		victim := e.enrolled(t, e.a, fleetsql.KindConnector)
		sibling := e.enrolled(t, e.a, fleetsql.KindAgent)
		foreign := e.enrolled(t, e.b, fleetsql.KindConnector)
		for _, id := range []fleet.Identity{victim, sibling, foreign} {
			if ok, err := lc.Usable(ctx, id); err != nil || !ok {
				t.Fatalf("enrolled component not usable: %v %v", ok, err)
			}
		}

		// AC4 + AC1: the actor and the component are recorded, state is revoked, streams are closed.
		before := len(e.sink.evs)
		n, err := lc.Revoke(ctx, e.a, admin, victim.ComponentID)
		if err != nil || n != 2 {
			t.Fatalf("revoke: n=%d err=%v", n, err)
		}
		if st, _ := e.state(t, e.a, victim.ComponentID); st != "revoked" {
			t.Fatalf("state = %s", st)
		}
		if len(cl.calls) != 1 || cl.calls[0] != e.a.String()+"/"+victim.ComponentID {
			t.Fatalf("closer calls: %v", cl.calls)
		}
		if len(e.sink.evs) != before+1 {
			t.Fatalf("audit events: %d", len(e.sink.evs)-before)
		}
		ev := e.sink.evs[before]
		if ev.Kind != "fleet.component.revoked" || ev.Actor.Requester.ID != "human-1" || ev.Target.GUID != victim.ComponentID {
			t.Fatalf("audit event: %+v", ev)
		}

		// AC2: its (still valid) certificate no longer passes the gateway's check; and it cannot
		// rotate either. AC3: nobody else is affected.
		if ok, err := lc.Usable(ctx, victim); err != nil || ok {
			t.Fatalf("revoked component usable: %v %v", ok, err)
		}
		for _, id := range []fleet.Identity{sibling, foreign} {
			if ok, _ := lc.Usable(ctx, id); !ok {
				t.Fatal("other component affected by the revocation")
			}
		}
		// A tenant cannot reach another tenant's component.
		if _, err := lc.Revoke(ctx, e.a, admin, foreign.ComponentID); !errors.Is(err, fleetsql.ErrNotRevocable) {
			t.Fatalf("cross-tenant revoke: %v", err)
		}
		if ok, _ := lc.Usable(ctx, fleet.Identity{Tenant: e.a, Kind: foreign.Kind, ComponentID: foreign.ComponentID}); ok {
			t.Fatal("component usable under another tenant")
		}
		// Revoking twice is refused and records nothing more.
		before = len(e.sink.evs)
		if _, err := lc.Revoke(ctx, e.a, admin, victim.ComponentID); !errors.Is(err, fleetsql.ErrNotRevocable) {
			t.Fatalf("second revoke: %v", err)
		}
		if len(e.sink.evs) != before || len(cl.calls) != 1 {
			t.Fatal("a refused revoke left a record or closed streams")
		}
	})
}

func TestRevokeRefusals(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		e := setupEnroll(t, s)
		iss := e.issue(t, e.a, fleetsql.KindConnector)
		csr, _ := csrFor(t, nil)
		first, err := e.enr.Enroll(ctx, peerIP, iss.Token.String(), csr)
		if err != nil {
			t.Fatal(err)
		}
		victim := first.Identity
		deny := &fleetsql.Lifecycle{DB: e.db, Authz: revokeAuthz{false}, Audit: e.sink}
		if _, err := deny.Revoke(ctx, e.a, admin, victim.ComponentID); !errors.Is(err, fleetsql.ErrRevokeForbidden) {
			t.Fatalf("no permission: %v", err)
		}
		if st, _ := e.state(t, e.a, victim.ComponentID); st != "enrolled" {
			t.Fatalf("state changed without permission: %s", st)
		}
		// A pending component has nothing to revoke.
		pending := e.issue(t, e.a, fleetsql.KindAgent)
		lc := &fleetsql.Lifecycle{DB: e.db, Authz: revokeAuthz{true}, Audit: e.sink}
		if _, err := lc.Revoke(ctx, e.a, admin, pending.ComponentID); !errors.Is(err, fleetsql.ErrNotRevocable) {
			t.Fatalf("pending: %v", err)
		}
		if _, err := lc.Revoke(ctx, e.a, admin, "not-a-uuid"); !errors.Is(err, fleetsql.ErrNotRevocable) {
			t.Fatalf("malformed id: %v", err)
		}
		if _, err := (&fleetsql.Lifecycle{}).Revoke(ctx, e.a, admin, victim.ComponentID); !errors.Is(err, fleetsql.ErrNotConfigured) {
			t.Fatalf("unconfigured: %v", err)
		}
		// A revoked component cannot rotate its certificate either.
		if _, err := lc.Revoke(ctx, e.a, admin, victim.ComponentID); err != nil {
			t.Fatal(err)
		}
		cur, err := x509.ParseCertificate(first.LeafDER)
		if err != nil {
			t.Fatal(err)
		}
		csr2, _ := csrFor(t, nil)
		if _, err := e.enr.Rotate(ctx, cur, csr2); !errors.Is(err, fleetsql.ErrRotateRefused) {
			t.Fatalf("revoked component rotated its certificate: %v", err)
		}
	})
}
