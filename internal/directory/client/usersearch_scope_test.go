package client_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/client/clienttest"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The fake domain:
//
//	H  naming context head
//	├─ A  ── ua (user)
//	│   └─ A1 ── ua1
//	│       └─ X ── ux
//	└─ B  ── ub
//	      uh (directly under H)
const (
	connUUID = "c0c0c0c0-0000-4000-8000-000000000001"
	gH       = "11111111-0000-4000-8000-000000000001"
	gA       = "11111111-0000-4000-8000-00000000000a"
	gB       = "11111111-0000-4000-8000-00000000000b"
	gA1      = "11111111-0000-4000-8000-00000000000c"
	gX       = "11111111-0000-4000-8000-00000000000d"
)

func user(g, parent, name string) clienttest.Node {
	return clienttest.Node{GUID: g, Parent: parent, User: true, Display: name, Sam: name}
}

func domain() *clienttest.Directory {
	return clienttest.New(
		clienttest.Node{GUID: gH}, clienttest.Node{GUID: gA, Parent: gH}, clienttest.Node{GUID: gB, Parent: gH},
		clienttest.Node{GUID: gA1, Parent: gA}, clienttest.Node{GUID: gX, Parent: gA1},
		user("22222222-0000-4000-8000-00000000000a", gA, "pat.ua"),
		user("22222222-0000-4000-8000-00000000000b", gB, "pat.ub"),
		user("22222222-0000-4000-8000-00000000000c", gA1, "pat.ua1"),
		user("22222222-0000-4000-8000-00000000000d", gX, "pat.ux"),
		user("22222222-0000-4000-8000-00000000000e", gH, "pat.uh"),
	)
}

type conns struct{}

func (conns) Get(context.Context, tenant.ID, connection.ID) (connection.Connection, error) {
	return connection.Connection{ID: connUUID, Kind: connection.KindADForest, State: connection.StateActive, DirectoryIdentity: gH}, nil
}

func oid(t *testing.T, s string) authz.ObjectID {
	t.Helper()
	id, err := authz.ParseObjectID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func termOf(t *testing.T, k authz.TermKind, root string) authz.ScopeTerm {
	return authz.ScopeTerm{Kind: k, Connection: oid(t, connUUID), Root: oid(t, root)}
}

func grant(inc []authz.ScopeTerm, exc ...authz.ScopeTerm) authz.ScopeGrant {
	return authz.ScopeGrant{Include: inc, Exclude: exc}
}

func search(t *testing.T, d *clienttest.Directory, text string, limit int, scope authz.ReadScope) (client.UserSearchResult, error) {
	t.Helper()
	us, err := client.NewUserSearch(conns{}, d, d)
	if err != nil {
		t.Fatal(err)
	}
	return us.Users(context.Background(), tenant.ID{}, connUUID, text, limit, scope)
}

func sams(r client.UserSearchResult) []string {
	var out []string
	for _, u := range r.Users {
		out = append(out, u.SAMAccountName)
	}
	return out
}

// T-0875 acceptance 1: a technician scoped to OU A searches for a user who lives in OU B: nothing
// comes back, and nothing about the answer reveals the user (no count, no truncation mark).
func TestSearchScopedToAFindsNobodyInB(t *testing.T) {
	d := domain()
	scope := authztest.ReadScope(grant([]authz.ScopeTerm{termOf(t, authz.TermSubtree, gA)}))
	for _, q := range []string{"pat.ub", "ub"} {
		res, err := search(t, d, q, 25, scope)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Users) != 0 || res.Truncated {
			t.Fatalf("search %q answered %+v, want nothing", q, res)
		}
	}
	// The directory itself was only asked about OU A: B is never read.
	for _, roots := range d.Searches {
		if !slices.Equal(roots, []string{gA}) {
			t.Fatalf("directory asked with roots %v, want only OU A", roots)
		}
	}
}

func TestSearchScopedToAFindsOnlyAUsers(t *testing.T) {
	res, err := search(t, domain(), "pat", 25, authztest.ReadScope(grant([]authz.ScopeTerm{termOf(t, authz.TermSubtree, gA)})))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sams(res), []string{"pat.ua", "pat.ua1", "pat.ux"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSearchAppliesExcludesTheDirectoryCannotExpress(t *testing.T) {
	scope := authztest.ReadScope(grant([]authz.ScopeTerm{termOf(t, authz.TermSubtree, gH)}, termOf(t, authz.TermSubtree, gA1), termOf(t, authz.TermSubtree, gB)))
	res, err := search(t, domain(), "pat", 25, scope)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sams(res), []string{"pat.ua", "pat.uh"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSearchOneLevelReachesDirectChildrenOnly(t *testing.T) {
	d := domain()
	res, err := search(t, d, "pat", 25, authztest.ReadScope(grant([]authz.ScopeTerm{termOf(t, authz.TermOneLevel, gA)})))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sams(res), []string{"pat.ua"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if len(d.Depths) != 1 || d.Depths[0] != connectorv1.SearchDepth_SEARCH_DEPTH_ONE_LEVEL {
		t.Fatalf("depths = %v, want one ONE_LEVEL search", d.Depths)
	}
}

func TestSearchTokenLayerNarrowsTheGrants(t *testing.T) {
	scope := authztest.ReadScopeWithToken(authz.TokenLayer{Include: []authz.ScopeTerm{termOf(t, authz.TermSubtree, gA1)}},
		grant([]authz.ScopeTerm{termOf(t, authz.TermNamingContext, gH)}))
	res, err := search(t, domain(), "pat", 25, scope)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sams(res), []string{"pat.ua1", "pat.ux"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// A token with an empty layer reaches nothing, and the directory is not asked.
	d := domain()
	res, err = search(t, d, "pat", 25, authztest.ReadScopeWithToken(authz.TokenLayer{}, grant([]authz.ScopeTerm{termOf(t, authz.TermNamingContext, gH)})))
	if err != nil || len(res.Users) != 0 || len(d.Searches) != 0 {
		t.Fatalf("empty token layer: %+v %v, searches %v", res, err, d.Searches)
	}
}

func TestSearchWithNoScopeAsksNothing(t *testing.T) {
	d := domain()
	for name, scope := range map[string]authz.ReadScope{
		"zero scope": {},
		"no grants":  authztest.ReadScope(),
		"another connection": authztest.ReadScope(grant([]authz.ScopeTerm{
			{Kind: authz.TermSubtree, Connection: oid(t, "c0c0c0c0-0000-4000-8000-000000000002"), Root: oid(t, gA)}})),
		"unknown kind": authztest.ReadScope(grant([]authz.ScopeTerm{{Kind: 0, Connection: oid(t, connUUID), Root: oid(t, gH)}})),
	} {
		res, err := search(t, d, "pat", 25, scope)
		if err != nil || len(res.Users) != 0 || res.Truncated {
			t.Errorf("%s: %+v %v, want an empty answer", name, res, err)
		}
	}
	if len(d.Searches) != 0 || len(d.Reads) != 0 {
		t.Fatalf("directory was asked (%v, %v) although no scope reaches it", d.Searches, d.Reads)
	}
}

// Counts and pages come after trimming (LF-39): users the scope removes do not use up the match cap
// or the limit.
func TestSearchCapAndLimitCountOnlyAdmittedUsers(t *testing.T) {
	nodes := []clienttest.Node{{GUID: gH}, {GUID: gA, Parent: gH}, {GUID: gB, Parent: gH}}
	for i := 0; i < client.MaxSearchMatches+1; i++ { // out of scope, and sorting before the in-scope ones
		nodes = append(nodes, user(fmt.Sprintf("33333333-0000-4000-8000-%012x", i+1), gB, fmt.Sprintf("aaa.%04d", i)))
	}
	nodes = append(nodes, user("44444444-0000-4000-8000-000000000001", gA, "zed.one"), user("44444444-0000-4000-8000-000000000002", gA, "zed.two"))
	scope := authztest.ReadScope(grant([]authz.ScopeTerm{termOf(t, authz.TermSubtree, gH)}, termOf(t, authz.TermSubtree, gB)))
	res, err := search(t, clienttest.New(nodes...), "", 1, scope)
	if err == nil {
		t.Fatalf("empty text must still be refused, got %+v", res)
	}
	res, err = search(t, clienttest.New(nodes...), ".", 1, scope)
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated || len(res.Users) != 1 || res.Users[0].SAMAccountName != "zed.one" {
		t.Fatalf("got %+v, want the first in-scope user, not truncated by the %d excluded ones", res, client.MaxSearchMatches+1)
	}
}

func TestSearchRootsOverlapAnswerEachUserOnce(t *testing.T) {
	scope := authztest.ReadScope(grant([]authz.ScopeTerm{termOf(t, authz.TermSubtree, gA), termOf(t, authz.TermSubtree, gA1)}))
	res, err := search(t, domain(), "pat", 25, scope)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sams(res), []string{"pat.ua", "pat.ua1", "pat.ux"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSearchReadsEachContainerOncePerSearch(t *testing.T) {
	d := domain()
	if _, err := search(t, d, "pat", 25, authztest.ReadScope(grant([]authz.ScopeTerm{termOf(t, authz.TermNamingContext, gH)}))); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, g := range d.Reads {
		if seen[g] {
			t.Fatalf("container %s read twice: %v", g, d.Reads)
		}
		seen[g] = true
	}
}

// A chain that cannot be read in full is not admitted, and a failed read fails the search; neither
// answers an unchecked user.
func TestSearchFailsClosedWhenAncestryCannotBeRead(t *testing.T) {
	scope := authztest.ReadScope(grant([]authz.ScopeTerm{termOf(t, authz.TermNamingContext, gH)}))
	d := domain()
	d.ReadErr = errors.New("transport down")
	res, err := search(t, d, "pat", 25, scope)
	if !errors.Is(err, client.ErrSearchScope) || len(res.Users) != 0 {
		t.Fatalf("got %+v, %v, want ErrSearchScope and no users", res, err)
	}
	// A parent that no longer exists: the chain is incomplete and the user is dropped.
	orphan := clienttest.New(clienttest.Node{GUID: gH}, user("22222222-0000-4000-8000-0000000000ff", "55555555-0000-4000-8000-000000000001", "pat.orphan"))
	res, err = search(t, orphan, "pat", 25, scope)
	if err != nil || len(res.Users) != 0 {
		t.Fatalf("got %+v, %v, want the orphan dropped", res, err)
	}
}

func TestNewUserSearchNeedsReads(t *testing.T) {
	if _, err := client.NewUserSearch(conns{}, domain(), nil); err == nil {
		t.Fatal("a search without a way to read ancestry would be unscoped")
	}
}
