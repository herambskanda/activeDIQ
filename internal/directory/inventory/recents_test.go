package inventory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const (
	acctOne = "0b2f6a52-7c1e-4a63-9a4e-5d1f0f8a9c10"
	acctTwo = "0b2f6a52-7c1e-4a63-9a4e-5d1f0f8a9c11"
)

func (e *env) account(t *testing.T, id string) {
	t.Helper()
	if err := e.exec(e.a, `INSERT INTO public.authn_accounts (tenant_id, id, kind, display_name, created_by) VALUES ($1, $2::uuid, 'local', 'Admin', 'system')`, e.a.String(), id); err != nil {
		t.Fatalf("seed account: %v", err)
	}
}

func (e *env) opened(t *testing.T, sr *inventory.Searcher, account, obj string, at time.Time) error {
	t.Helper()
	return e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		return sr.RecordOpened(ctx, tx, e.a, account, string(e.adA), obj, at)
	})
}

func (e *env) recents(t *testing.T, sr *inventory.Searcher, scope reportsql.SearchScopes, account string) inventory.SearchResult {
	t.Helper()
	var res inventory.SearchResult
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
		res, err = sr.Recents(ctx, tx, e.a, scope, account, nil, 0)
		return
	}); err != nil {
		t.Fatalf("recents: %v", err)
	}
	return res
}

// AC1: A then B opened; the empty palette lists B, A; an object moved out of the scope is not listed; and
// the list is the account's own.
func Test_recents_list_newest_first_and_never_out_of_scope(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		e.account(t, acctOne)
		e.account(t, acctTwo)
		sr := e.searcher(t)
		if _, err := e.populate(t, e.adA, hBase, sSrchUser(1, "ann", "Ann A"), sSrchUser(2, "bob", "Bob B"), sSrchUser(3, "cy", "Cy C")); err != nil {
			t.Fatal(err)
		}
		now := hBase.Add(time.Hour)
		for i, g := range []string{hGUID(1, 1), hGUID(1, 2)} {
			if err := e.opened(t, sr, acctOne, g, now.Add(time.Duration(i)*time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
		scopes := reportsql.SearchScopes{"directory.read": e.scopeOU(e.adA)}
		if g := searchGUIDs(e.recents(t, sr, scopes, acctOne)); len(g) != 2 || g[0] != hGUID(1, 2) || g[1] != hGUID(1, 1) {
			t.Fatalf("recents %v, want B then A", g)
		}
		// Opening A again moves it to the front.
		if err := e.opened(t, sr, acctOne, hGUID(1, 1), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if g := searchGUIDs(e.recents(t, sr, scopes, acctOne)); len(g) != 2 || g[0] != hGUID(1, 1) {
			t.Fatalf("reopened A first: %v", g)
		}
		if g := searchGUIDs(e.recents(t, sr, scopes, acctTwo)); len(g) != 0 {
			t.Fatalf("another account's recents leaked: %v", g)
		}
		// A leaves the scope (moved under the system container): it disappears, B stays; nothing is deleted.
		moved := sSrchUser(1, "ann", "Ann A")
		moved.Parent, moved.Ancestry = inventory.GUID(hSys), []inventory.GUID{inventory.GUID(hSys), inventory.GUID(hDom)}
		if _, err := e.populate(t, e.adA, hBase.Add(2*time.Hour), moved); err != nil {
			t.Fatal(err)
		}
		if g := searchGUIDs(e.recents(t, sr, scopes, acctOne)); len(g) != 1 || g[0] != hGUID(1, 2) {
			t.Fatalf("an object moved out of scope is listed: %v", g)
		}
		if n := e.count(t, `SELECT count(*) FROM public.inventory_recent_objects`); n != 2 {
			t.Errorf("rows kept: %d", n)
		}
		// An empty scope lists nothing, and an unknown object remembers nothing.
		if g := e.recents(t, sr, reportsql.SearchScopes{"directory.read": {}}, acctOne); len(g.Hits) != 0 {
			t.Errorf("empty scope: %v", g.Hits)
		}
		if err := e.opened(t, sr, acctOne, hGUID(9, 9), now); !errors.Is(err, inventory.ErrUnknownObject) {
			t.Errorf("unknown object: %v", err)
		}
		if err := e.opened(t, sr, "not-a-uuid", hGUID(1, 2), now); !errors.Is(err, inventory.ErrNoAccount) {
			t.Errorf("bad account: %v", err)
		}
	})
}

// The store is bounded: only the newest reportsql.MaxRecents stay.
func Test_recents_are_bounded(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		e.account(t, acctOne)
		sr := e.searcher(t)
		var obs []inventory.Observation
		for i := 1; i <= reportsql.MaxRecents+5; i++ {
			obs = append(obs, sSrchUser(i, "u"+string(rune('a'+i)), "User "+string(rune('a'+i))))
		}
		if _, err := e.populate(t, e.adA, hBase, obs...); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= reportsql.MaxRecents+5; i++ {
			if err := e.opened(t, sr, acctOne, hGUID(1, i), hBase.Add(time.Duration(i)*time.Minute)); err != nil {
				t.Fatal(err)
			}
		}
		if n := e.count(t, `SELECT count(*) FROM public.inventory_recent_objects`); n != reportsql.MaxRecents {
			t.Fatalf("kept %d rows, want %d", n, reportsql.MaxRecents)
		}
		if n := e.count(t, `SELECT count(*) FROM public.inventory_recent_objects WHERE object_guid = $1::uuid`, hGUID(1, 1)); n != 0 {
			t.Error("the oldest was not trimmed")
		}
	})
}

// AC2: a query that prefix-matches a recent object and another ranks the recent one first, but never above
// an exact match; the other account's recents do not rank.
func Test_search_ranks_recent_objects_after_exact(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		e.account(t, acctOne)
		e.account(t, acctTwo)
		sr := e.searcher(t)
		// "sam" is an exact sam; "samuel" and "samira" prefix-match; "samira" was opened by acctOne.
		if _, err := e.populate(t, e.adA, hBase, sSrchUser(1, "sam", "Sam Exact"), sSrchUser(2, "samuel", "Aaron Samuel"), sSrchUser(3, "samira", "Zed Samira")); err != nil {
			t.Fatal(err)
		}
		for _, g := range []string{hGUID(1, 3), hGUID(1, 1)} {
			if err := e.opened(t, sr, acctOne, g, hBase.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
		scope := e.scopeNC(e.adA)
		order := func(account string) []string {
			res, err := e.search(t, sr, scope, inventory.SearchRequest{Text: "sam", Account: account})
			if err != nil {
				t.Fatal(err)
			}
			return searchGUIDs(res)
		}
		want := func(got []string, w ...string) {
			t.Helper()
			if len(got) != len(w) {
				t.Fatalf("got %v want %v", got, w)
			}
			for i := range w {
				if got[i] != w[i] {
					t.Fatalf("got %v want %v", got, w)
				}
			}
		}
		// exact (1) first even though recent; then the recent prefix hit (3) above the name-ordered other (2).
		want(order(acctOne), hGUID(1, 1), hGUID(1, 3), hGUID(1, 2))
		// Without recents (another account, or none) the order is by name: Aaron Samuel before Zed Samira.
		want(order(acctTwo), hGUID(1, 1), hGUID(1, 2), hGUID(1, 3))
		want(order(""), hGUID(1, 1), hGUID(1, 2), hGUID(1, 3))
	})
}
