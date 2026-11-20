package delegation_test

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/modules/delegation"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type activeOwner struct{}

func (activeOwner) Active(context.Context, store.Tx, tenant.ID, string) (bool, error) {
	return true, nil
}

const (
	ouA   = "cccccccc-0000-4000-8000-00000000000a"
	ouB   = "cccccccc-0000-4000-8000-00000000000b"
	ouC   = "cccccccc-0000-4000-8000-00000000000c"
	conn2 = "bbbbbbbb-0000-4000-8000-000000000009"
	ouD   = "cccccccc-0000-4000-8000-00000000000d"
)

func oid(t *testing.T, s string) authz.ObjectID {
	t.Helper()
	o, err := authz.ParseObjectID(s)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func termSet(ts []authz.ScopeTerm) map[authz.ScopeTerm]bool {
	m := map[authz.ScopeTerm]bool{}
	for _, t := range ts {
		m[t] = true
	}
	return m
}

// T-1599 acceptance 1 and 3: scope terms authored on delegation.assignment.grant come back from the one
// producer, rbac.ReadScopes, as exactly those terms (include and exclude, subtree and one level), and a
// cross-domain assignment is one row with a term per connection, each evaluated on its own.
func TestGrantedScopeTermsReachTheReadScopeProducer(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s, true)
		ctx := context.Background()
		if err := e.run(t, owner, nil, delegation.RoleCreateID, delegation.RoleCreateInput{
			RoleID: id(7), Name: "report-viewer", Tier: 2, Permissions: []string{"reports.run"},
		}); err != nil {
			t.Fatal(err)
		}
		roots := []delegation.RootInput{
			{Kind: "ou_subtree", ConnectionID: conn, GUID: ouA},
			{Kind: "ou_subtree", ConnectionID: conn, GUID: ouB, Exclude: true},
			{Kind: "ou_one_level", ConnectionID: conn, GUID: ouC},
			{Kind: "ou_subtree", ConnectionID: conn2, GUID: ouD}, // a second domain, same assignment
		}
		if err := e.run(t, owner, nil, delegation.GrantID, delegation.GrantInput{
			AssignmentID: id(8), RoleID: id(7), Subject: delegation.SubjectInput{Kind: "account", AccountID: admin}, Roots: roots,
		}); err != nil {
			t.Fatalf("grant scoped assignment: %v", err)
		}
		c, err := moduletest.Register(delegation.New(platform.Deps{}, directory.Services{}))
		if err != nil {
			t.Fatal(err)
		}
		rs, err := rbac.NewReadScopes(e.az, c, activeOwner{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var scope authz.ReadScope
		if err := e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) error {
			var err error
			scope, err = rs.For(ctx, tx, e.tid, authority.Chain{Requester: authority.Principal{ID: admin, Kind: authority.Human}}, "reports.run")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		grants := scope.Terms()
		if len(grants) != 1 {
			t.Fatalf("want one grant (one assignment), got %d", len(grants))
		}
		g := grants[0]
		wantInc := []authz.ScopeTerm{
			{Kind: authz.TermSubtree, Connection: oid(t, conn), Root: oid(t, ouA)},
			{Kind: authz.TermOneLevel, Connection: oid(t, conn), Root: oid(t, ouC)},
			{Kind: authz.TermSubtree, Connection: oid(t, conn2), Root: oid(t, ouD)},
		}
		wantExc := []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: oid(t, conn), Root: oid(t, ouB)}}
		if got := termSet(g.Include); len(got) != len(wantInc) || len(g.Include) != len(wantInc) {
			t.Fatalf("include = %v, want %v", g.Include, wantInc)
		}
		for _, w := range wantInc {
			if !termSet(g.Include)[w] {
				t.Errorf("include lacks %v", w)
			}
		}
		if len(g.Exclude) != 1 || !termSet(g.Exclude)[wantExc[0]] {
			t.Errorf("exclude = %v, want %v", g.Exclude, wantExc)
		}
		if len(scope.Reasons()) != 0 {
			t.Errorf("reasons = %v", scope.Reasons())
		}
		conns := scope.Connections()
		if len(conns) != 2 {
			t.Errorf("connections = %v, want both domains", conns)
		}
	})
}
