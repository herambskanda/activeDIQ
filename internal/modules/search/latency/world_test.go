package latency_test

// The world of the search latency benchmark: a real tenant database (PostgreSQL 16 or 18, migrated as an
// install is), the seed written through the real inventory writer, the real search service behind the real
// directory handlers and the real apihost router. Requests go in through ServeHTTP, in process.
//
// What is stubbed, and why: the authenticator (a header names the caller), the authorizer and the limiter
// (allow), and the read-scope producer (a table of two scopes). rbac.ReadScopes.For is not in the timed path;
// it is one indexed read of the caller's assignments, covered by T-1096's composed-producer test, and building
// real accounts and role assignments for two callers would add nothing to the number being proved. The scope
// itself is the real authz.ReadScope the real renderer turns into SQL.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/modules/search"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/searchkey"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

// fuzzyThreshold is pg_trgm.word_similarity_threshold the product uses (inventory searchThreshold, T-1095).
// The benchmark repeats the literal on purpose: if the product value moves, the fuzzy oracle disagrees and
// this test says so, instead of following the change silently.
const fuzzyThreshold = 0.3

type keyRow struct {
	key string
	obj int // index into Seed.Objs
}

type world struct {
	t     *testing.T
	s     *storetest.Server
	d     *storetest.Database
	db    *store.DB
	tid   tenant.ID
	conns [2]string
	seed  *Seed
	byID  map[string]int // object GUID -> index into seed.Objs
	// keys[k] are the key rows of kind k, sorted by key in byte order (the column is COLLATE "C").
	keys  [11][]keyRow
	nKey  int
	src   reportsql.SearchSource
	srcOK bool
}

func newWorld(t *testing.T, s *storetest.Server, seed *Seed) *world {
	t.Helper()
	ctx := context.Background()
	d := s.NewDatabase(t)
	d.Migrate(t)
	w := &world{t: t, s: s, d: d, seed: seed, byID: map[string]int{}}
	w.tid = tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	w.db = db
	reg := connection.NewRegistry(db)
	for c := range w.conns {
		cred := fmt.Sprintf("%d1111111-1111-4111-8111-111111111111", c+1)
		cn, err := reg.Create(ctx, w.tid, connection.New{Kind: connection.KindADForest, DisplayName: domains[c].DNS, CredentialID: connection.CredentialID(cred), Transport: connection.TransportLDAPS})
		if err != nil {
			t.Fatal(err)
		}
		w.conns[c] = string(cn.ID)
	}
	for i, o := range seed.Objs {
		w.byID[o.GUID] = i
	}
	return w
}

// write puts the seed through inventory.Populator, the real writer, in batches of batch observations, one
// tenant transaction each.
func (w *world) write(batch int) time.Duration {
	w.t.Helper()
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	var pop inventory.Populator
	t0 := time.Now()
	for c := range w.conns {
		head, objs := w.seed.Observations(c)
		for _, part := range [][]inventory.Observation{head} {
			w.populate(&pop, c, at, part)
		}
		for lo := 0; lo < len(objs); lo += batch {
			w.populate(&pop, c, at, objs[lo:min(lo+batch, len(objs))])
		}
	}
	return time.Since(t0)
}

func (w *world) populate(pop *inventory.Populator, c int, at time.Time, obs []inventory.Observation) {
	w.t.Helper()
	err := w.db.WithTenant(context.Background(), w.tid, func(ctx context.Context, tx store.Tx) error {
		_, err := pop.Populate(ctx, tx, inventory.ConnectionID(w.conns[c]), at, obs)
		return err
	})
	if err != nil {
		w.t.Fatalf("populate connection %d: %v", c, err)
	}
}

func (w *world) q1(sql string, args ...any) (n int) {
	w.t.Helper()
	if err := w.db.WithTenant(context.Background(), w.tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		w.t.Fatal(err)
	}
	return n
}

// assertSeed checks the row counts before anything is measured (acceptance 1).
func (w *world) assertSeed() string {
	w.t.Helper()
	var sb strings.Builder
	want := w.seed.Counts
	got := map[string]int{}
	err := w.db.WithTenant(context.Background(), w.tid, func(ctx context.Context, tx store.Tx) error {
		rs, err := tx.Query(ctx, `SELECT kind, count(*) FROM public.directory_objects WHERE state = 'live' GROUP BY kind`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var k string
			var n int
			if err := rs.Scan(&k, &n); err != nil {
				return err
			}
			got[k] = n
		}
		return rs.Err()
	})
	if err != nil {
		w.t.Fatal(err)
	}
	total := 0
	for _, k := range []inventory.Kind{inventory.KindUser, inventory.KindGroup, inventory.KindComputer, inventory.KindContact} {
		if got[string(k)] != want[k] {
			w.t.Errorf("seed: %d %s rows written, want %d", got[string(k)], k, want[k])
		}
		total += got[string(k)]
		fmt.Fprintf(&sb, "  %-9s %6d\n", k, got[string(k)])
	}
	if total != w.seed.N {
		w.t.Errorf("seed: %d searchable objects written, want exactly %d", total, w.seed.N)
	}
	if n := w.q1(`SELECT count(*) FROM public.directory_objects WHERE kind = 'ou'`); n != len(w.seed.OUs) {
		w.t.Errorf("seed: %d OUs written, want %d", n, len(w.seed.OUs))
	}
	// The deepest OU holds its five parents and the naming context in its ancestry: six levels.
	if n := w.q1(`SELECT max(cardinality(ancestry)) FROM public.directory_objects WHERE kind = 'ou'`); n != 6 {
		w.t.Errorf("seed: deepest OU has ancestry length %d, want 6 (an OU tree six levels deep)", n)
	}
	if n := w.q1(`SELECT count(DISTINCT connection_id) FROM public.directory_objects WHERE kind = 'user'`); n != 2 {
		w.t.Errorf("seed: users span %d connections, want 2", n)
	}
	// 10 % of the users and of the computers are disabled.
	dis := w.q1(`SELECT count(*) FROM public.directory_objects WHERE kind IN ('user', 'computer') AND enabled IS FALSE`)
	if wantDis := (want[inventory.KindUser] + want[inventory.KindComputer]) / 10; dis != wantDis {
		w.t.Errorf("seed: %d disabled accounts, want %d (10 %%)", dis, wantDis)
	}
	// 5 % duplicate display names: per kind, rows minus distinct names is the number of repeats.
	rep := w.q1(`SELECT COALESCE(sum(n - d), 0)::int FROM (SELECT count(*) AS n, count(DISTINCT display_name) AS d FROM public.directory_objects WHERE kind IN ('user', 'group', 'computer', 'contact') GROUP BY kind) x`)
	dups := 0
	for _, o := range w.seed.Objs {
		if o.Dup {
			dups++
		}
	}
	if rep != dups {
		w.t.Errorf("seed: %d repeated display names in the table, the seed made %d", rep, dups)
	}
	if f := float64(dups) / float64(w.seed.N); f < 0.04 || f > 0.06 {
		w.t.Errorf("seed: %.1f %% duplicate display names, want about 5 %%", 100*f)
	}
	fmt.Fprintf(&sb, "  total     %6d searchable objects (+ %d OUs, 2 naming contexts)\n  disabled  %6d accounts   duplicate display names %d (%.1f %%)\n",
		total, len(w.seed.OUs), dis, dups, 100*float64(dups)/float64(w.seed.N))
	return sb.String()
}

// analyze runs ANALYZE on the two tables, as autovacuum does in production, and loads every key row for the
// oracle.
func (w *world) analyze() {
	w.t.Helper()
	ctx := context.Background()
	for _, tbl := range []string{"inventory_search_keys", "directory_objects"} {
		if err := w.d.ExecOwner(ctx, `ANALYZE public.`+tbl); err != nil {
			w.t.Fatal(err)
		}
	}
	err := w.db.WithTenant(ctx, w.tid, func(ctx context.Context, tx store.Tx) error {
		rs, err := tx.Query(ctx, `SELECT object_guid::text, key_kind, key FROM public.inventory_search_keys`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var g, key string
			var k int16
			if err := rs.Scan(&g, &k, &key); err != nil {
				return err
			}
			i, ok := w.byID[g]
			if !ok {
				return fmt.Errorf("key row of an object the seed does not hold: %s", g)
			}
			w.keys[k] = append(w.keys[k], keyRow{key, i})
			w.nKey++
		}
		return rs.Err()
	})
	if err != nil {
		w.t.Fatal(err)
	}
	for k := range w.keys {
		slices.SortFunc(w.keys[k], func(a, b keyRow) int { return strings.Compare(a.key, b.key) })
	}
}

// ---- the oracle: a brute-force implementation of exact and prefix matching and of the scope ----

// matched is the oracle's account of one query, before any scope.
type matched struct {
	parsed                searchkey.Parsed
	exactRows, prefixRows int
	exact, prefix         map[int]bool
	fuzzyRows             int
	fuzzy                 map[int]bool
}

func (w *world) span(kind searchkey.Kind, lo, hi string, bounded bool) []keyRow {
	ks := w.keys[kind]
	a := sort.Search(len(ks), func(i int) bool { return ks[i].key >= lo })
	b := len(ks)
	if bounded {
		b = sort.Search(len(ks), func(i int) bool { return ks[i].key >= hi })
	}
	return ks[a:b]
}

// match computes what the B-tree classes must find for text, over the whole tenant (rows, not scope).
func (w *world) match(text string) matched {
	p, err := searchkey.Classify(text)
	if err != nil {
		w.t.Fatalf("classify %q: %v", text, err)
	}
	m := matched{parsed: p, exact: map[int]bool{}, prefix: map[int]bool{}, fuzzy: map[int]bool{}}
	for _, pr := range p.Exact {
		for _, r := range w.span(pr.Kind, pr.Key, pr.Key+"\x00", true) {
			m.exactRows++
			m.exact[r.obj] = true
		}
	}
	for _, pf := range p.Prefix {
		for _, r := range w.span(pf.Kind, pf.Lo, pf.Hi, pf.Bounded) {
			m.prefixRows++
			m.prefix[r.obj] = true
		}
	}
	return m
}

// fuzzyOracle reads the fuzzy class the slow way: a sequential scan of the key table with every index
// turned off, in the same tenant transaction shape the product uses. It trusts pg_trgm's operator (not ours
// to test) and nothing about the index, the ceiling, the join, the scope or the ranking.
func (w *world) fuzzyOracle(m *matched) {
	if m.parsed.Fuzzy == "" {
		return
	}
	err := w.db.WithTenant(context.Background(), w.tid, func(ctx context.Context, tx store.Tx) error {
		for _, set := range []string{"enable_indexscan", "enable_bitmapscan", "enable_indexonlyscan"} {
			if _, err := tx.Exec(ctx, "SET LOCAL "+set+" = off"); err != nil {
				return err
			}
		}
		restore, err := store.SetTrigramThreshold(ctx, tx, fuzzyThreshold)
		if err != nil {
			return err
		}
		defer restore()
		rs, err := tx.Query(ctx, `SELECT object_guid::text FROM public.inventory_search_keys WHERE key_kind IN (1, 2, 3, 4, 5) AND $1::text <% key`, m.parsed.Fuzzy)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var g string
			if err := rs.Scan(&g); err != nil {
				return err
			}
			m.fuzzyRows++
			m.fuzzy[w.byID[g]] = true
		}
		return rs.Err()
	})
	if err != nil {
		w.t.Fatalf("fuzzy oracle %q: %v", m.parsed.Fuzzy, err)
	}
}

// ---- the server ----

type callerScopes map[string]authz.ReadScope

func (c callerScopes) ReadScope(_ context.Context, _ tenant.ID, ch authority.Chain, _ authz.Permission) (authz.ReadScope, error) {
	sc, ok := c[string(ch.Requester.ID)]
	if !ok {
		return authz.ReadScope{}, authz.ErrOwnerDead
	}
	return sc, nil
}

// ports is the host's authentication, authorization, limiting and step-up seam: the caller is the value of the
// X-Caller header; every permission is allowed.
type ports struct{ tid tenant.ID }

func (p ports) Authenticate(r *http.Request) (apihost.Principal, error) {
	return apihost.Principal{ID: r.Header.Get("X-Caller"), Tenant: p.tid.String(), Kind: apihost.KindSession, SessionID: "s"}, nil
}
func (ports) CheckCSRF(*http.Request, apihost.Principal) error { return nil }
func (ports) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (ports) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (ports) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (ports) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

// scopes builds the two callers' read scopes over the seed.
func (w *world) scopes() callerScopes {
	oid := func(s string) authz.ObjectID {
		id, err := authz.ParseObjectID(s)
		if err != nil {
			w.t.Fatal(err)
		}
		return id
	}
	var admin authz.ScopeGrant
	for c := range w.conns {
		admin.Include = append(admin.Include, authz.ScopeTerm{Kind: authz.TermNamingContext, Connection: oid(w.conns[c]), Root: oid(w.seed.NC[c])})
	}
	root, excl := w.seed.OUs[w.seed.ScopedRoot()], w.seed.OUs[w.seed.ScopedExclude()]
	scoped := authz.ScopeGrant{
		Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: oid(w.conns[0]), Root: oid(root.GUID)}},
		Exclude: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: oid(w.conns[0]), Root: oid(excl.GUID)}},
	}
	return callerScopes{"admin": authztest.ReadScope(admin), "scoped": authztest.ReadScope(scoped)}
}

// server is the in-process HTTP surface: apihost router, directory handlers, search service, searcher of
// ceiling ceil.
type server struct {
	h    http.Handler
	ceil int
	ix   *inventory.Searcher
}

func (w *world) newServer(ceil int) *server {
	w.t.Helper()
	ctx := context.Background()
	var ix *inventory.Searcher
	if err := w.db.WithTenant(ctx, w.tid, func(ctx context.Context, tx store.Tx) error {
		sc, err := reportsql.CatalogSchema(ctx, tx)
		if err != nil {
			return err
		}
		ix, err = inventory.NewSearcher(sc, inventory.WithCeiling(ceil))
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
	cur, err := search.NewEphemeralCursors()
	if err != nil {
		w.t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &search.Service{DB: w.db, Scopes: w.scopes(), Index: ix, Cursors: cur, Log: quiet}
	hd := directory.Handlers{Searcher: svc, Log: quiet}
	doc, err := apihost.LoadDocument()
	if err != nil {
		w.t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		w.t.Fatal(err)
	}
	p := ports{tid: w.tid}
	srv, err := apihost.Build(doc, []apihost.TagHandlers{hd.Bind()}, pol, apitest.Catalogue(doc), apihost.Ports{Authn: p, Authz: p, Limits: p, StepUp: p})
	if err != nil {
		w.t.Fatal(err)
	}
	return &server{h: srv, ceil: ceil, ix: ix}
}

// response is the part of the searchDirectory answer the benchmark reads.
type response struct {
	Refine bool `json:"refine"`
	Groups []struct {
		Type  string `json:"type"`
		Count *int   `json:"count"`
		More  *bool  `json:"more"`
		Items []struct {
			ObjectID   string `json:"objectId"`
			MatchClass string `json:"matchClass"`
		} `json:"items"`
	} `json:"groups"`
}

// post sends one search as the caller and returns the status, the body and the time ServeHTTP took.
func (s *server) post(caller, text string, groupLimit int) (int, []byte, time.Duration) {
	body := map[string]any{"q": text}
	if groupLimit > 0 {
		body["groupLimit"] = groupLimit
	}
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "/api/v1/directory/search", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Caller", caller)
	r.RemoteAddr = "203.0.113.7:4444"
	rec := httptest.NewRecorder()
	t0 := time.Now()
	s.h.ServeHTTP(rec, r)
	d := time.Since(t0)
	return rec.Code, rec.Body.Bytes(), d
}

// ---- statistics ----

type stats struct {
	n                  int
	p50, p95, p99, max time.Duration
}

// rank is the 0-based nearest-rank index of percentile p among n sorted samples.
func rank(n int, p float64) int { return max(0, min(int(float64(n)*p/100+0.999999999)-1, n-1)) }

// overToMiss is how many of n samples at or over budget make the p-th percentile of all n over budget: the
// samples above the nearest rank, plus the one at it.
func overToMiss(n int, p float64) int { return n - rank(n, p) }

func summarize(ds []time.Duration) stats {
	s := slices.Clone(ds)
	slices.Sort(s)
	at := func(p float64) time.Duration { return s[rank(len(s), p)] }
	return stats{n: len(s), p50: at(50), p95: at(95), p99: at(99), max: s[len(s)-1]}
}

func ms(d time.Duration) string { return fmt.Sprintf("%.1f", float64(d.Microseconds())/1000) }
