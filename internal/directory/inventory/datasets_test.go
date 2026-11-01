package inventory_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/filetime"
	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func (e *env) registry(t *testing.T) *reportsql.Registry {
	t.Helper()
	var reg *reportsql.Registry
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		sc, err := reportsql.CatalogSchema(ctx, tx)
		if err != nil {
			return err
		}
		reg, err = reportsql.NewRegistry(reportsql.Options{Schema: sc, SecretKey: inventory.SecretKey}, inventory.Datasets()...)
		return err
	})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

func Test_inventory_datasets_register(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		for _, id := range []string{"inventory.users", "inventory.computers"} {
			if _, ok := reg.Dataset(report.DatasetID(id)); !ok {
				t.Fatalf("%s not registered", id)
			}
		}
	})
}

// A dataset column that reads a secret attribute is refused at registration (D8, TM-TB15-T3), for every
// name the writer refuses; the keys the inventory datasets read pass the same predicate.
func Test_secret_attribute_keys_are_refused(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		var sc reportsql.Schema
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) { sc, err = reportsql.CatalogSchema(ctx, tx); return }); err != nil {
			t.Fatal(err)
		}
		keys := append(secretattr.Static(), "unicodePwd", "msDS-KeyCredentialLink", "UNICODEPWD", "ms-Mcs-AdmPwd;range=0-1", "1.2.840.113556.1.4.90")
		for _, k := range keys {
			ds := inventory.Datasets()[1] // computers
			ds.Columns = append(slices.Clone(ds.Columns), report.Column{ID: "leak", Label: "Leak", Type: report.TypeText, Filter: []report.Op{report.OpEq},
				Source: report.JSONAttr{Col: "attributes", Key: k, As: report.TypeText}})
			_, err := reportsql.NewRegistry(reportsql.Options{Schema: sc, SecretKey: inventory.SecretKey}, ds)
			if err == nil {
				t.Errorf("a column reading %q was registered", k)
			}
		}
		// every JSON key the shipped datasets read is not a secret
		for _, ds := range inventory.Datasets() {
			for _, c := range ds.Columns {
				if j, ok := c.Source.(report.JSONAttr); ok && inventory.SecretKey(j.Key) {
					t.Errorf("%s.%s reads the secret key %q", ds.ID, c.ID, j.Key)
				}
			}
		}
		// and with no predicate configured, a JSON column is refused outright
		if _, err := reportsql.NewRegistry(reportsql.Options{Schema: sc}, inventory.Datasets()[1]); err == nil {
			t.Error("a registry with no SecretKey predicate accepted a JSON column")
		}
	})
}

// ---- harness shared by the dataset tests (T-0958) -------------------------------------------------

const (
	hDom = "dddddddd-0000-4000-8000-000000000001" // the naming-context head
	hOU  = "dddddddd-0000-4000-8000-000000000002" // the OU the users live in
	hSys = "dddddddd-0000-4000-8000-000000000003" // the Password Settings Container (outside hOU)
)

var hBase = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

// hGUID makes a deterministic GUID from a class byte and an index.
func hGUID(class byte, i int) string {
	return fmt.Sprintf("%02x000000-0000-4000-8000-%012x", class, i)
}

// hSID is a domain SID S-1-5-21-1-2-3-<rid>, binary.
func hSID(rid uint32) []byte {
	b := []byte{1, 5, 0, 0, 0, 0, 0, 5}
	for _, v := range []uint32{21, 1, 2, 3, rid} {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return b
}

func i64(v int64) *int64 { return &v }

func (e *env) policyTx(t *testing.T, fn func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error) {
	t.Helper()
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error { return fn(ctx, tx, inventory.PolicyWriter{}) }); err != nil {
		t.Fatalf("policy: %v", err)
	}
}

func days(n int64) *filetime.Interval { return &filetime.Interval{Ticks: n * 86400 * 10_000_000} }
func mins(n int64) *filetime.Interval { return &filetime.Interval{Ticks: n * 60 * 10_000_000} }
func forever() *filetime.Interval     { return &filetime.Interval{Forever: true} }

// hStructure writes the NC head, the OU the users live in and the container the PSOs live in. Both
// children are direct children of the head.
func (e *env) hStructure(t *testing.T, c inventory.ConnectionID) {
	t.Helper()
	obs := []inventory.Observation{
		{Object: inventory.GUID(hDom), NC: inventory.GUID(hDom), Kind: inventory.KindOther, Class: "domainDNS", State: inventory.ObjLive},
		{Object: inventory.GUID(hOU), NC: inventory.GUID(hDom), Kind: inventory.KindOU, Class: "organizationalUnit", State: inventory.ObjLive,
			Parent: inventory.GUID(hDom), Ancestry: []inventory.GUID{inventory.GUID(hDom)}},
		{Object: inventory.GUID(hSys), NC: inventory.GUID(hDom), Kind: inventory.KindContainer, Class: "container", State: inventory.ObjLive,
			Parent: inventory.GUID(hDom), Ancestry: []inventory.GUID{inventory.GUID(hDom)}},
	}
	if _, err := e.populate(t, c, hBase, obs...); err != nil {
		t.Fatalf("structure: %v", err)
	}
}

// hUser is one user with every D7 input read unless a field says otherwise.
type hUser struct {
	guid       string
	sam        string
	rid        uint32
	uac        *int64
	read       inventory.InputsRead
	lockout    time.Time
	pwdLastSet time.Time
	expires    time.Time
	spn        *bool
	primary    string // a group GUID
	kind       inventory.Kind
	class      string
	parent     string // default hOU
}

const uacNormal = 512

func (u hUser) obs() inventory.Observation {
	parent := u.parent
	if parent == "" {
		parent = hOU
	}
	k, cl := u.kind, u.class
	if k == "" {
		k, cl = inventory.KindUser, "user"
	}
	anc := []inventory.GUID{inventory.GUID(parent)}
	if parent != hDom {
		anc = append(anc, inventory.GUID(hDom))
	}
	return inventory.Observation{Object: inventory.GUID(u.guid), NC: inventory.GUID(hDom), Kind: k, Class: cl, State: inventory.ObjLive,
		Parent: inventory.GUID(parent), Ancestry: anc, DN: "CN=" + u.sam + ",OU=People,DC=example,DC=test", RDN: "CN=" + u.sam,
		SID: hSID(u.rid), SAMAccountName: u.sam, UserAccountControl: u.uac, InputsRead: u.read,
		LockoutTime: u.lockout, PwdLastSet: u.pwdLastSet, AccountExpires: u.expires, HasSPN: u.spn,
		PrimaryGroup: inventory.GUID(u.primary), WhenCreated: hBase.Add(-24 * time.Hour)}
}

// hGroup is a group with the given direct members (users or groups).
func hGroup(guid, name string, rid uint32, members ...string) inventory.Observation {
	o := inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(hDom), Kind: inventory.KindGroup, Class: "group", State: inventory.ObjLive,
		Parent: inventory.GUID(hOU), Ancestry: []inventory.GUID{inventory.GUID(hOU), inventory.GUID(hDom)}, DN: "CN=" + name + ",OU=People,DC=example,DC=test",
		RDN: "CN=" + name, SID: hSID(rid), SAMAccountName: name, MembersComplete: true}
	for _, m := range members {
		o.Members = append(o.Members, inventory.GUID(m))
	}
	return o
}

// hPSOObj is the directory object of a PSO, under the container hSys (outside the OU).
func hPSOObj(guid, name string) inventory.Observation {
	return inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(hDom), Kind: inventory.KindOther, Class: "msDS-PasswordSettings", State: inventory.ObjLive,
		Parent: inventory.GUID(hSys), Ancestry: []inventory.GUID{inventory.GUID(hSys), inventory.GUID(hDom)}, DN: "CN=" + name + ",CN=Password Settings Container,CN=System,DC=example,DC=test",
		RDN: "CN=" + name}
}

// scopeNC admits the whole naming context; scopeOU only the OU subtree.
func (e *env) scopeNC(c inventory.ConnectionID) authz.ReadScope {
	return authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: rpID(string(c)), Root: rpID(hDom)}}})
}

func (e *env) scopeOU(c inventory.ConnectionID) authz.ReadScope {
	return authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: rpID(string(c)), Root: rpID(hOU)}}})
}

// hQuery describes one report run.
type hQuery struct {
	dataset report.DatasetID
	cols    []report.ColumnID
	where   report.Expr
	sort    []report.SortKey
	top     int
	limit   int
	scope   authz.ReadScope
	now     time.Time
}

type hResult struct {
	rows  map[string]map[report.ColumnID]report.Cell // by lower-case GUID
	order []string
	count int64
	sql   []string
	args  [][]any
}

func (e *env) run(t *testing.T, reg *reportsql.Registry, q hQuery) hResult {
	t.Helper()
	src := slices.IndexFunc(inventory.Datasets(), func(d report.Dataset) bool { return d.ID == q.dataset })
	ds, ok := reg.Dataset(q.dataset)
	if src < 0 || !ok {
		t.Fatalf("dataset %s", q.dataset)
	}
	def := report.Definition{ID: "t0958-01", Version: 1, Category: report.CategoryUsers, Title: "T-0958", Dataset: q.dataset, Columns: q.cols,
		Sort: q.sort, Presets: []report.Preset{{ID: "all", Where: q.where, Top: q.top}}}
	rq, err := report.Resolve(def, "all", report.RunParams{}, inventory.Datasets()[src])
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	in := reportsql.Inputs{Now: q.now, Limit: q.limit}
	rowsQ, err := reportsql.Compile(rq, ds, q.scope, in)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cntQ, err := reportsql.CompileCount(rq, ds, q.scope, in)
	if err != nil {
		t.Fatalf("CompileCount: %v", err)
	}
	res := hResult{rows: map[string]map[report.ColumnID]report.Cell{}}
	for _, q := range []reportsql.Query{rowsQ, cntQ} {
		sql, args := q.Statement()
		res.sql, res.args = append(res.sql, sql), append(res.args, args)
	}
	err = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		_, err := reportsql.Exec(ctx, tx, rowsQ, 500, func(_ context.Context, rows []report.Row) error {
			for _, row := range rows {
				k := strings.ToLower(row.Key)
				m := map[report.ColumnID]report.Cell{}
				for i, c := range q.cols {
					m[c] = row.Cells[i]
				}
				res.rows[k] = m
				res.order = append(res.order, k)
			}
			return nil
		})
		if err != nil {
			return err
		}
		res.count, err = reportsql.Count(ctx, tx, cntQ)
		return err
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

// cellKey is a comparable form of a cell: its tag and typed text.
func cellKey(c report.Cell) string { return c.Tag() + ":" + string(c.DigestValue()) }

func Test_inventory_users_smoke(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		u := hUser{guid: hGUID(1, 1), sam: "alice", rid: 1100, uac: i64(uacNormal), read: 15, pwdLastSet: hBase}
		if _, err := e.populate(t, e.adA, hBase, u.obs()); err != nil {
			t.Fatal(err)
		}
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			return w.SetDomainPolicy(ctx, tx, e.adA, inventory.GUID(hDom), inventory.DomainPolicy{MaxPwdAge: days(42), LockoutDuration: mins(30), PSOsReadAt: hBase}, hBase)
		})
		cols := []report.ColumnID{"sam_account_name", "locked_out", "lockout_ends_at", "password_state", "password_expires_at", "days_to_password_expiry", "account_expired", "policy_source", "probable_service_account"}
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: cols, scope: e.scopeNC(e.adA), now: hBase.Add(24 * time.Hour),
			sort: []report.SortKey{{Column: "sam_account_name", Dir: report.Asc}}})
		for k, r := range res.rows {
			for _, c := range cols {
				t.Logf("%s %s = %s", k, c, cellKey(r[c]))
			}
		}
		if len(res.rows) != 1 {
			t.Fatalf("rows = %d", len(res.rows))
		}
	})
}
