package search_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/search"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Unit tests of the service with fakes: the refusal order, what is logged, how the scope is obtained and
// handed on. The behaviour against a real inventory is in search_pg_test.go.

var tid = tenant.New()

type fakeScopes struct {
	scope authz.ReadScope
	err   error
	calls []authz.Permission
	chain authority.Chain
	tid   tenant.ID
}

func (f *fakeScopes) ReadScope(_ context.Context, t tenant.ID, c authority.Chain, p authz.Permission) (authz.ReadScope, error) {
	f.calls = append(f.calls, p)
	f.chain, f.tid = c, t
	return f.scope, f.err
}

type fakeIndex struct {
	searches int
	gotScope reportsql.SearchScopes
	gotReq   inventory.SearchRequest
	res      inventory.SearchResult
}

func (f *fakeIndex) Search(_ context.Context, _ store.Tx, _ tenant.ID, s reportsql.SearchScopes, r inventory.SearchRequest) (inventory.SearchResult, error) {
	f.searches++
	f.gotScope, f.gotReq = s, r
	return f.res, nil
}

func (f *fakeIndex) SearchMetadata(context.Context, store.Tx, tenant.ID, authz.ReadScope, time.Time, []reportsql.SearchHit) (map[inventory.SearchRef]inventory.SearchMeta, error) {
	return nil, nil
}

type fakeDB struct{ opened int }

func (f *fakeDB) WithTenant(ctx context.Context, _ tenant.ID, fn func(context.Context, store.Tx) error) error {
	f.opened++
	return fn(ctx, &storetest.FakeTx{})
}

func oneOU() authz.ReadScope {
	return authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: authz.ObjectID{15: 1}, Root: authz.ObjectID{15: 2}}}})
}

func newSvc(t *testing.T, sc *fakeScopes, ix *fakeIndex, logs *bytes.Buffer) (*search.Service, *fakeDB) {
	t.Helper()
	cur, err := search.NewEphemeralCursors()
	if err != nil {
		t.Fatal(err)
	}
	db := &fakeDB{}
	s := &search.Service{DB: db, Scopes: sc, Index: ix, Cursors: cur, Log: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	return s, db
}

// AC5: a text that has the shape of a recovery password is refused as query_refused on the NFKC form, with
// nothing read, no scope asked for, and nothing of the text in the error or the log.
func Test_recovery_password_shaped_text_is_refused_unechoed_and_unlogged(t *testing.T) {
	digits := "123456123456123456123456123456123456123456123456"
	cases := map[string]string{
		"plain":      digits,
		"dashed":     "123456-123456-123456-123456-123456-123456-123456-123456",
		"spaced":     "12345612 3456123456123456 123456123456 123456123456",
		"fullwidth":  strings.Map(func(r rune) rune { return r - '0' + '０' }, digits),
		"arabicdigs": strings.Map(func(r rune) rune { return r - '0' + '٠' }, digits),
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			sc, ix := &fakeScopes{scope: oneOU()}, &fakeIndex{}
			svc, db := newSvc(t, sc, ix, &logs)
			_, err := svc.Search(context.Background(), search.Call{Tenant: tid, Text: q})
			var qe *search.QueryError
			if !errors.As(err, &qe) || qe.Code != search.CodeRefused {
				t.Fatalf("err = %v, want query_refused", err)
			}
			if len(sc.calls) != 0 || ix.searches != 0 || db.opened != 0 {
				t.Errorf("a refused text reached the producer (%d), index (%d) or database (%d)", len(sc.calls), ix.searches, db.opened)
			}
			for _, leak := range []string{err.Error(), logs.String()} {
				if strings.Contains(leak, "123456") || strings.Contains(leak, q) {
					t.Errorf("the refused text leaked: %q", leak)
				}
			}
			if !strings.Contains(logs.String(), "query_refused") {
				t.Errorf("the refusal is logged by reason: %q", logs.String())
			}
		})
	}
}

func Test_other_refusals_carry_codes(t *testing.T) {
	for _, c := range []struct{ q, code string }{
		{"   ", search.CodeTooShort},
		{"a\x00b", search.CodeInvalid},
		{"\xff\xfe", search.CodeInvalid},
		{strings.Repeat("a", 257), search.CodeTooLong},
		{strings.Repeat("a", 5000), search.CodeTooLong},
	} {
		var logs bytes.Buffer
		svc, _ := newSvc(t, &fakeScopes{scope: oneOU()}, &fakeIndex{}, &logs)
		_, err := svc.Search(context.Background(), search.Call{Tenant: tid, Text: c.q})
		var qe *search.QueryError
		if !errors.As(err, &qe) || qe.Code != c.code {
			t.Errorf("%.8q: err = %v, want %s", c.q, err, c.code)
		}
	}
}

// AC5: a served query is logged as its rune length, shape and class set, never the text.
func Test_a_served_query_is_logged_as_length_and_class_only(t *testing.T) {
	var logs bytes.Buffer
	svc, _ := newSvc(t, &fakeScopes{scope: oneOU()}, &fakeIndex{}, &logs)
	for _, q := range []string{"Priya Raman", `EXAMPLE\praman`, "praman@example.test", "S-1-5-21-1-2-3-1105", "xyzzy-secret-name"} {
		if _, err := svc.Search(context.Background(), search.Call{Tenant: tid, Text: q}); err != nil {
			t.Fatal(err)
		}
	}
	out := logs.String()
	for _, leak := range []string{"Priya", "Raman", "praman", "xyzzy", "secret", "EXAMPLE", "1105"} {
		if strings.Contains(out, leak) {
			t.Errorf("the log holds %q:\n%s", leak, out)
		}
	}
	for _, want := range []string{"rune_length=11", "classes=", "shapes="} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %q:\n%s", want, out)
		}
	}
}

// AC2: the scope is the producer's, asked for directory.read through the port with the caller's tenant and
// chain, and it is the one the index is given. The mutation check (see the ticket note) replaces it.
func Test_scope_comes_from_the_producer_and_is_handed_to_the_index_unchanged(t *testing.T) {
	var logs bytes.Buffer
	want := oneOU()
	sc, ix := &fakeScopes{scope: want}, &fakeIndex{}
	svc, _ := newSvc(t, sc, ix, &logs)
	chain := authority.Chain{Requester: authority.Principal{ID: "acct-1", Kind: authority.Human}}
	if _, err := svc.Search(context.Background(), search.Call{Tenant: tid, Chain: chain, Text: "praman"}); err != nil {
		t.Fatal(err)
	}
	if len(sc.calls) != 1 || sc.calls[0] != "directory.read" || sc.tid != tid || !reflect.DeepEqual(sc.chain, chain) {
		t.Errorf("producer asked %v for %v / %v", sc.calls, sc.tid, sc.chain)
	}
	got, ok := ix.gotScope["directory.read"]
	if !ok || got.Fingerprint() != want.Fingerprint() || len(ix.gotScope) != 1 {
		t.Errorf("the index was given %v, not the producer's scope", ix.gotScope)
	}
}

// AC2: no producer, a dead owner, a refused token, an unsupported chain and a denied permission are all 403s
// that read nothing; a scope that grants nothing answers nothing without reading; any other fault is not a 403.
func Test_missing_or_refusing_producer_is_forbidden_and_empty_scope_reads_nothing(t *testing.T) {
	for name, err := range map[string]error{"owner dead": authz.ErrOwnerDead, "token": authz.ErrTokenRefused, "chain": rbac.ErrUnsupportedChain, "denied": rbac.ErrDenied} {
		var logs bytes.Buffer
		ix := &fakeIndex{}
		svc, db := newSvc(t, &fakeScopes{err: err}, ix, &logs)
		if _, got := svc.Search(context.Background(), search.Call{Tenant: tid, Text: "praman"}); !errors.Is(got, search.ErrForbidden) || ix.searches != 0 || db.opened != 0 {
			t.Errorf("%s: err %v, searches %d", name, got, ix.searches)
		}
	}
	var logs bytes.Buffer
	ix := &fakeIndex{}
	svc, db := newSvc(t, nil, ix, &logs)
	svc.Scopes = nil
	if _, err := svc.Search(context.Background(), search.Call{Tenant: tid, Text: "praman"}); !errors.Is(err, search.ErrForbidden) {
		t.Errorf("no producer: %v", err)
	}
	svc, db = newSvc(t, &fakeScopes{scope: authztest.ReadScope()}, ix, &logs)
	res, err := svc.Search(context.Background(), search.Call{Tenant: tid, Text: "praman"})
	if err != nil || ix.searches != 0 || db.opened != 0 || res.Refine || len(res.Groups) != 4 {
		t.Fatalf("empty scope: %v %+v searches %d", err, res, ix.searches)
	}
	for _, g := range res.Groups {
		if len(g.Items) != 0 || g.More || g.NextCursor != "" || g.Count == nil || *g.Count != 0 {
			t.Errorf("empty scope group %+v", g)
		}
	}
	if _, err := newSvcErr(t, errors.New("db down")).Search(context.Background(), search.Call{Tenant: tid, Text: "praman"}); errors.Is(err, search.ErrForbidden) || err == nil {
		t.Errorf("a producer fault must not look like a refusal: %v", err)
	}
}

func newSvcErr(t *testing.T, err error) *search.Service {
	var logs bytes.Buffer
	s, _ := newSvc(t, &fakeScopes{err: err}, &fakeIndex{}, &logs)
	return s
}

// A cursor is bound to its query, type and scope, and needs a type; a forged one reads nothing.
func Test_cursor_is_bound_and_verified_before_anything_is_read(t *testing.T) {
	var logs bytes.Buffer
	sc, ix := &fakeScopes{scope: oneOU()}, &fakeIndex{}
	svc, _ := newSvc(t, sc, ix, &logs)
	if _, err := svc.Search(context.Background(), search.Call{Tenant: tid, Text: "praman", Cursor: "x.y"}); !errors.Is(err, search.ErrCursorRequiresType) {
		t.Errorf("a cursor without a type: %v", err)
	}
	for _, cur := range []string{"x.y", "nodot", strings.Repeat("a", 2000), "e30.AAAA"} {
		if _, err := svc.Search(context.Background(), search.Call{Tenant: tid, Text: "praman", Type: reportsql.TypeUser, Cursor: cur}); !errors.Is(err, search.ErrCursorInvalid) {
			t.Errorf("cursor %.10q: %v", cur, err)
		}
	}
	if ix.searches != 0 {
		t.Error("a bad cursor reached the index")
	}
}
