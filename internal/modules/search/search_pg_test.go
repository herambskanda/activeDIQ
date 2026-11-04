package search_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/search"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

// A world: one tenant, one AD connection, a naming context with two sibling OUs. "Hidden" objects live in
// OU B; the technician is scoped to OU A.

const (
	gDom = "dddddddd-0000-4000-8000-000000000001"
	gOUA = "dddddddd-0000-4000-8000-00000000000a"
	gOUB = "dddddddd-0000-4000-8000-00000000000b"
)

var base = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

func guid(class byte, i int) string { return fmt.Sprintf("%02x000000-0000-4000-8000-%012x", class, i) }

func sidBytes(rid uint32) []byte {
	b := []byte{1, 5, 0, 0, 0, 0, 0, 5}
	for _, v := range []uint32{21, 1, 2, 3, rid} {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return b
}

type world struct {
	db   *store.DB
	tid  tenant.ID
	conn string
	pop  inventory.Populator
	ix   *inventory.Searcher
}

func newWorld(t *testing.T, s *storetest.Server, opts ...inventory.SearcherOption) *world {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	w := &world{}
	w.tid = tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	w.db = db
	c, err := connection.NewRegistry(db).Create(context.Background(), w.tid,
		connection.New{Kind: connection.KindADForest, DisplayName: "c", CredentialID: "11111111-1111-4111-8111-111111111111", Transport: connection.TransportLDAPS})
	if err != nil {
		t.Fatal(err)
	}
	w.conn = string(c.ID)
	if err := db.WithTenant(context.Background(), w.tid, func(ctx context.Context, tx store.Tx) error {
		sc, err := reportsql.CatalogSchema(ctx, tx)
		if err != nil {
			return err
		}
		w.ix, err = inventory.NewSearcher(sc, opts...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w.populate(t, inventory.Observation{Object: gDom, NC: gDom, Kind: inventory.KindOther, Class: "domainDNS", State: inventory.ObjLive},
		w.ou(gOUA), w.ou(gOUB))
	return w
}

func (w *world) ou(g string) inventory.Observation {
	return inventory.Observation{Object: inventory.GUID(g), NC: gDom, Kind: inventory.KindOU, Class: "organizationalUnit", State: inventory.ObjLive,
		Parent: gDom, Ancestry: []inventory.GUID{gDom}}
}

func (w *world) populate(t *testing.T, obs ...inventory.Observation) {
	t.Helper()
	err := w.db.WithTenant(context.Background(), w.tid, func(ctx context.Context, tx store.Tx) error {
		_, err := w.pop.Populate(ctx, tx, inventory.ConnectionID(w.conn), base, obs)
		return err
	})
	if err != nil {
		t.Fatalf("populate: %v", err)
	}
}

// obj is an object under ou with a display name and a sam.
func obj(kind inventory.Kind, class string, g string, ou, name, sam string) inventory.Observation {
	ouName := map[string]string{gOUA: "A", gOUB: "B"}[ou]
	yes := true
	return inventory.Observation{Object: inventory.GUID(g), NC: gDom, Kind: kind, Class: class, State: inventory.ObjLive, Parent: inventory.GUID(ou),
		Ancestry: []inventory.GUID{inventory.GUID(ou), gDom}, DN: "CN=" + name + ",OU=" + ouName + ",DC=corp,DC=example,DC=test", RDN: "CN=" + name,
		DisplayName: name, SAMAccountName: sam, Enabled: &yes}
}

func (w *world) scope(root string, kind authz.TermKind) authz.ReadScope {
	c, _ := authz.ParseObjectID(w.conn)
	r, _ := authz.ParseObjectID(root)
	return authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: kind, Connection: c, Root: r}}})
}

func (w *world) tech() authz.ReadScope  { return w.scope(gOUA, authz.TermSubtree) }
func (w *world) admin() authz.ReadScope { return w.scope(gDom, authz.TermNamingContext) }

func (w *world) service(t *testing.T, sc authz.ReadScope) (*search.Service, *bytes.Buffer) {
	t.Helper()
	cur, err := search.NewEphemeralCursors()
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	return &search.Service{DB: w.db, Scopes: &fakeScopes{scope: sc}, Index: w.ix, Cursors: cur, Log: slog.New(slog.NewTextHandler(logs, nil))}, logs
}

func (w *world) ask(t *testing.T, svc *search.Service, text string) search.Result {
	t.Helper()
	res, err := svc.Search(context.Background(), search.Call{Tenant: w.tid, Text: text})
	if err != nil {
		t.Fatalf("search %q: %v", text, err)
	}
	return res
}

func names(g search.Group) []string {
	var out []string
	for _, h := range g.Items {
		out = append(out, h.DisplayName)
	}
	return out
}

func group(r search.Result, t reportsql.SearchType) search.Group {
	for _, g := range r.Groups {
		if g.Type == t {
			return g
		}
	}
	return search.Group{}
}

// AC1: a technician scoped to OU A who searches for an object that lives in OU B, in exact, prefix and fuzzy
// forms, gets nothing: no hit, a count of zero in every group, no truncation flag, no cursor and no refine.
// The same texts find the objects for a caller whose scope reaches them (the control), so the test is not
// vacuous. It runs for users, groups, computers and contacts.
func Test_scoped_technician_never_learns_of_an_object_in_another_OU(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		w := newWorld(t, s)
		hiddenUser := obj(inventory.KindUser, "user", guid(1, 1), gOUB, "Zelda Quinn", "zquinn")
		hiddenGroup := obj(inventory.KindGroup, "group", guid(2, 1), gOUB, "Quartz Operators", "QuartzOps")
		hiddenComputer := obj(inventory.KindComputer, "computer", guid(3, 1), gOUB, "QUARTZWS01", "QUARTZWS01$")
		hiddenContact := obj(inventory.KindContact, "contact", guid(4, 1), gOUB, "Quincy Outsider", "")
		hiddenContact.Attributes = map[string]any{"mail": "quincy.outsider@partner.example.test"}
		visible := obj(inventory.KindUser, "user", guid(1, 2), gOUA, "Priya Raman", "praman")
		w.populate(t, hiddenUser, hiddenGroup, hiddenComputer, hiddenContact, visible)

		// finds: the whole-domain caller must find the object with this text (the control). The typos are
		// fuzzy forms; they must also find it for the whole-domain caller, but the pg_trgm threshold decides
		// that, so only the first few are asserted as controls.
		type form struct {
			q     string
			finds bool
		}
		forms := map[reportsql.SearchType][]form{
			reportsql.TypeUser:     {{"zquinn", true}, {"Zelda Quinn", true}, {"zque", false}, {"zeld", true}, {"Zelda Quin", true}, {"Zleda Quinn", false}},
			reportsql.TypeGroup:    {{"Quartz Operators", true}, {"QuartzOps", true}, {"quartz op", true}, {"quart", true}},
			reportsql.TypeComputer: {{"QUARTZWS01", true}, {"quartzws", true}, {"QUARTZWS0", true}},
			reportsql.TypeContact:  {{"Quincy Outsider", true}, {"quincy.outsider@partner.example.test", true}, {"quincy o", true}},
		}
		tech, _ := w.service(t, w.tech())
		admin, _ := w.service(t, w.admin())
		for typ, fs := range forms {
			for _, f := range fs {
				got := w.ask(t, tech, f.q)
				if got.Refine {
					t.Errorf("%q: refine for a technician whose scope hides the object", f.q)
				}
				for _, g := range got.Groups {
					if len(g.Items) != 0 || g.More || g.NextCursor != "" || g.LimitReached {
						t.Errorf("%q: group %v leaks: %+v", f.q, g.Type, g)
					}
					if g.Count != nil && *g.Count != 0 {
						t.Errorf("%q: group %v count %d", f.q, g.Type, *g.Count)
					}
				}
				if f.finds && len(group(w.ask(t, admin, f.q), typ).Items) == 0 {
					t.Errorf("control: %q finds nothing for the whole-domain caller", f.q)
				}
			}
		}
		// The technician still finds what is in A.
		if g := group(w.ask(t, tech, "Priya Raman"), reportsql.TypeUser); len(g.Items) != 1 || g.Items[0].Class != reportsql.ClassPrefix || g.Items[0].DN == "" || g.Items[0].Domain != "" {
			t.Errorf("visible user: %+v", g)
		}
	})
}

// AC3: the ranking table. Every shape IA 5.2 names finds its object first, in the class the shape implies;
// within a class, enabled before disabled before deleted.
func Test_ranking_table(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		w := newWorld(t, s)
		priya := obj(inventory.KindUser, "user", guid(1, 1), gOUA, "Priya Raman", "praman")
		priya.UPN, priya.SID = "praman@example.test", sidBytes(1105)
		prima := obj(inventory.KindUser, "user", guid(1, 2), gOUA, "Primrose Allen", "pallen")
		priyaRamsey := obj(inventory.KindUser, "user", guid(1, 3), gOUA, "Priya Ramsey", "pramsey")
		wk := obj(inventory.KindComputer, "computer", guid(3, 1), gOUA, "WKST01", "WKST01$")
		wk.Attributes = map[string]any{"dNSHostName": "wkst01.corp.example.test"}
		no := false
		tOn := obj(inventory.KindUser, "user", guid(1, 10), gOUA, "Taylor Ames", "tames1")
		tOff := obj(inventory.KindUser, "user", guid(1, 11), gOUA, "Taylor Ames", "tames2")
		tOff.Enabled = &no
		tDel := obj(inventory.KindUser, "user", guid(1, 12), gOUA, "Taylor Ames", "tames3")
		tDel.State = inventory.ObjDeleted
		// An all-digit identifier: searchkey has no digits shape, so it classifies as sam/host/text and the sam is an exact hit.
		dana := obj(inventory.KindUser, "user", guid(1, 20), gOUA, "Dana Ford", "4711")
		w.populate(t, priya, prima, priyaRamsey, wk, tOn, tOff, tDel, dana)
		svc, _ := w.service(t, w.admin())

		for _, c := range []struct {
			q     string
			typ   reportsql.SearchType
			first string
			class reportsql.SearchClass
		}{
			// free text is never "exact" (ADR-0011 rule 8: exact is an identifier shape): the whole name is the best prefix
			{"Priya Raman", reportsql.TypeUser, guid(1, 1), reportsql.ClassPrefix},
			{"Raman, Priya", reportsql.TypeUser, guid(1, 1), 0},
			{"praman", reportsql.TypeUser, guid(1, 1), reportsql.ClassExact},
			{`CORP\praman`, reportsql.TypeUser, guid(1, 1), reportsql.ClassExact},
			{"praman@example.test", reportsql.TypeUser, guid(1, 1), reportsql.ClassExact},
			{"S-1-5-21-1-2-3-1105", reportsql.TypeUser, guid(1, 1), reportsql.ClassExact},
			{strings.ToUpper(guid(1, 1)), reportsql.TypeUser, guid(1, 1), reportsql.ClassExact},
			{"{" + guid(1, 1) + "}", reportsql.TypeUser, guid(1, 1), reportsql.ClassExact},
			// the DN shape: the stored DN of priya as obj() builds it, as typed and lower-cased
			{priya.DN, reportsql.TypeUser, guid(1, 1), reportsql.ClassExact},
			{strings.ToLower(priya.DN), reportsql.TypeUser, guid(1, 1), reportsql.ClassExact},
			{"4711", reportsql.TypeUser, guid(1, 20), reportsql.ClassExact},
			{"wkst01", reportsql.TypeComputer, guid(3, 1), reportsql.ClassExact},
			{"wkst01.corp.example.test", reportsql.TypeComputer, guid(3, 1), reportsql.ClassExact},
			{"pri", reportsql.TypeUser, "", reportsql.ClassPrefix},
			{"Pryia Ramn", reportsql.TypeUser, guid(1, 1), reportsql.ClassFuzzy},
		} {
			g := group(w.ask(t, svc, c.q), c.typ)
			if c.first == "" {
				// no specific first hit: the best hit must at least have the class the shape implies
				if len(g.Items) == 0 || g.Items[0].Class != c.class {
					t.Errorf("%q: %+v", c.q, names(g))
				}
				continue
			}
			if len(g.Items) == 0 || g.Items[0].Object != c.first {
				t.Errorf("%q: first hit %v, want %s", c.q, names(g), c.first)
				continue
			}
			if c.class != 0 && g.Items[0].Class != c.class {
				t.Errorf("%q: class %v, want %v", c.q, g.Items[0].Class, c.class)
			}
		}
		// Classes in order: an exact hit precedes prefix and fuzzy hits of the same query.
		g := group(w.ask(t, svc, "praman"), reportsql.TypeUser)
		if len(g.Items) == 0 || g.Items[0].Class != reportsql.ClassExact {
			t.Errorf("praman: %v", g.Items)
		}
		for i := 1; i < len(g.Items); i++ {
			if g.Items[i].Class < g.Items[i-1].Class {
				t.Errorf("classes out of order: %v", g.Items)
			}
		}
		// Live and enabled before disabled before deleted, in the same class.
		g = group(w.ask(t, svc, "Taylor Ames"), reportsql.TypeUser)
		var order []string
		for _, h := range g.Items {
			order = append(order, h.Object)
		}
		if !slices.Equal(order, []string{guid(1, 10), guid(1, 11), guid(1, 12)}) {
			t.Errorf("taylor ames order %v", order)
		}
		if !hasChip(g.Items[1], search.ChipDisabled) || hasChip(g.Items[2], search.ChipDisabled) || !hasChip(g.Items[2], search.ChipDeleted) {
			t.Errorf("chips: %+v / %+v", g.Items[1], g.Items[2])
		}
		// A highlight is where the typed text sits, in code points.
		hl := group(w.ask(t, svc, "pram"), reportsql.TypeUser).Items[0].Highlights
		if len(hl) == 0 || hl[0].Field != search.FieldSAM || hl[0].Start != 0 || hl[0].Length != 4 {
			t.Errorf("highlights %+v", hl)
		}
	})
}

// countDB counts the statements of each tenant transaction a search opens.
type countDB struct {
	db *store.DB
	l  *storetest.StatementLog
}

func (c countDB) WithTenant(ctx context.Context, id tenant.ID, fn func(context.Context, store.Tx) error) error {
	return c.db.WithTenant(ctx, id, func(ctx context.Context, tx store.Tx) error { return fn(ctx, storetest.Record(tx, c.l)) })
}

// AC4: 5 visible and 500 hidden matches. The count, the per-group limit, the "more" flag and the "show all"
// pages are those of the 5; the work is one search statement and one batched metadata read, whatever the
// scope hides; a text matching more than W keys is the same refine state for the technician as for an admin.
func Test_counts_limits_and_pages_come_after_trimming(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		w := newWorld(t, s)
		var obs []inventory.Observation
		for i := 0; i < 5; i++ {
			obs = append(obs, obj(inventory.KindUser, "user", guid(1, i+1), gOUA, fmt.Sprintf("Quentin Visible %d", i), fmt.Sprintf("qv%d", i)))
		}
		for i := 0; i < 500; i++ {
			obs = append(obs, obj(inventory.KindUser, "user", guid(5, i+1), gOUB, fmt.Sprintf("Quentin Hidden %03d", i), fmt.Sprintf("qh%03d", i)))
		}
		w.populate(t, obs...)

		svc, _ := w.service(t, w.tech())
		l := &storetest.StatementLog{}
		svc.DB = countDB{db: w.db, l: l}
		res, err := svc.Search(context.Background(), search.Call{Tenant: w.tid, Text: "quentin v", Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		u := group(res, reportsql.TypeUser)
		if res.Refine || u.Count == nil || *u.Count != 5 || len(u.Items) != 2 || !u.More || u.NextCursor == "" {
			t.Fatalf("5 visible: refine %v count %v items %d more %v cursor %q", res.Refine, u.Count, len(u.Items), u.More, u.NextCursor)
		}
		if n := l.Count("inventory_search_keys"); n != 1 {
			t.Errorf("%d search statements for one request", n)
		}
		if n := l.Count("unnest($2::uuid[], $3::uuid[])"); n != 1 {
			t.Errorf("%d metadata reads for one request", n)
		}
		// "Show all": pages of the visible five only, in rank order, through a signed cursor.
		var seen []string
		cur := u.NextCursor
		seen = append(seen, names(u)...)
		for pages := 0; cur != ""; pages++ {
			if pages > 5 {
				t.Fatal("paging does not stop")
			}
			r, err := svc.Search(context.Background(), search.Call{Tenant: w.tid, Text: "quentin v", Type: reportsql.TypeUser, Limit: 2, Cursor: cur})
			if err != nil {
				t.Fatal(err)
			}
			g := group(r, reportsql.TypeUser)
			if g.Count != nil {
				t.Error("a cursor page carries a count")
			}
			seen, cur = append(seen, names(g)...), g.NextCursor
		}
		if len(seen) != 5 || seen[0] != "Quentin Visible 0" {
			t.Errorf("pages = %v", seen)
		}
		// The cursor is bound to the scope, the text and the type.
		admin, _ := w.service(t, w.admin())
		admin.Cursors = svc.Cursors
		for name, c := range map[string]struct {
			s *search.Service
			c search.Call
		}{
			"other scope": {admin, search.Call{Tenant: w.tid, Text: "quentin v", Type: reportsql.TypeUser, Limit: 2, Cursor: u.NextCursor}},
			"other text":  {svc, search.Call{Tenant: w.tid, Text: "quentin h", Type: reportsql.TypeUser, Limit: 2, Cursor: u.NextCursor}},
			"other type":  {svc, search.Call{Tenant: w.tid, Text: "quentin v", Type: reportsql.TypeGroup, Limit: 2, Cursor: u.NextCursor}},
		} {
			if _, err := c.s.Search(context.Background(), c.c); !errors.Is(err, search.ErrCursorInvalid) {
				t.Errorf("%s: %v", name, err)
			}
		}
		// A text matching more than W keys (W=300 here; 505 name keys match) is the same refine state for the
		// technician and the admin, and says nothing about which of the 500 are hidden.
		small := newWorld(t, s, inventory.WithCeiling(300))
		small.populate(t, obs...)
		stech, _ := small.service(t, small.tech())
		sadmin, _ := small.service(t, small.admin())
		for _, q := range []string{"q", "quentin v"} {
			a, b := small.ask(t, stech, q), small.ask(t, sadmin, q)
			if !a.Refine || !b.Refine {
				t.Fatalf("%q: refine: tech %v admin %v", q, a.Refine, b.Refine)
			}
			for _, g := range append(a.Groups, b.Groups...) {
				if g.Count != nil || g.More || g.NextCursor != "" {
					t.Errorf("%q: refine group %+v", q, g)
				}
			}
		}
		admin, _ = w.service(t, w.admin())
		// Under W the answers differ only by what each may see: the admin's 'quentin v' also fuzzy-matches the
		// 500 hidden names (505), the technician's count is the five of OU A, and a text aimed at the hidden
		// names returns only visible ones, never a hidden name.
		if g := group(w.ask(t, admin, "quentin v"), reportsql.TypeUser); g.Count == nil || *g.Count != 505 {
			t.Errorf("admin count for 'quentin v': %v", g.Count)
		}
		g := group(w.ask(t, svc, "quentin hidden 042"), reportsql.TypeUser)
		if g.Count == nil || *g.Count != 5 || len(g.Items) != 5 {
			t.Errorf("tech 'quentin hidden 042': count %v, %d items", g.Count, len(g.Items))
		}
		for _, h := range g.Items {
			if strings.Contains(h.DisplayName, "Hidden") || strings.Contains(h.DN, "OU=B") {
				t.Errorf("a hidden object is in the answer: %+v", h)
			}
		}
	})
}

func hasChip(h search.Hit, k search.ChipKind) bool {
	for _, c := range h.Status {
		if c.Kind == k {
			return true
		}
	}
	return false
}
