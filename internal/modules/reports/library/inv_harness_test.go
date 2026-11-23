package library_test

// The slice of the inventory test harness that the library report tests need (they lived in
// internal/directory/inventory until the layering check M2.2 forbade a directory package, tests
// included, to import a module). It writes a realistic inventory through the public inventory API.

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/filetime"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const cred = "11111111-1111-4111-8111-111111111111"

var pop inventory.Populator

var w inventory.Writer

type env struct {
	d    *storetest.Database
	db   *store.DB
	a, b tenant.ID
	adA  inventory.ConnectionID
	enA  inventory.ConnectionID
	adB  inventory.ConnectionID
	r    *inventory.Reader
}

func (e *env) conn(t *testing.T, tid tenant.ID, kind connection.Kind, tr connection.Transport) inventory.ConnectionID {
	t.Helper()
	c, err := connection.NewRegistry(e.db).Create(context.Background(), tid,
		connection.New{Kind: kind, DisplayName: "c", CredentialID: cred, Transport: tr})
	if err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	return inventory.ConnectionID(c.ID)
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	e := &env{d: d}
	e.a = tenanttest.Seed(t, d.ExecOwner, "A")
	e.b = tenanttest.Seed(t, d.ExecOwner, "B")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e.db = db
	e.adA = e.conn(t, e.a, connection.KindADForest, connection.TransportLDAPS)
	e.enA = e.conn(t, e.a, connection.KindEntraTenant, "")
	e.adB = e.conn(t, e.b, connection.KindADForest, connection.TransportLDAPS)
	e.r = inventory.NewReader(db, inventory.NewFake())
	return e
}

func (e *env) tx(t *testing.T, tid tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error {
	t.Helper()
	return e.db.WithTenant(context.Background(), tid, fn)
}

func (e *env) populate(t *testing.T, c inventory.ConnectionID, at time.Time, obs ...inventory.Observation) (inventory.Populated, error) {
	t.Helper()
	var out inventory.Populated
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
		out, err = pop.Populate(ctx, tx, c, at, obs)
		return
	})
	return out, err
}

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

func rpID(s string) authz.ObjectID {
	id, err := authz.ParseObjectID(s)
	if err != nil {
		panic(err)
	}
	return id
}

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

func i64(v int64) *int64              { return &v }
func days(n int64) *filetime.Interval { return &filetime.Interval{Ticks: n * 86400 * 10_000_000} }
func mins(n int64) *filetime.Interval { return &filetime.Interval{Ticks: n * 60 * 10_000_000} }
func forever() *filetime.Interval     { return &filetime.Interval{Forever: true} }
func lvl(n int) *int                  { return &n }

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
func ouObs(guid, name, parent string, anc ...string) inventory.Observation {
	o := inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(hDom), Kind: inventory.KindOU, Class: "organizationalUnit", State: inventory.ObjLive,
		Parent: inventory.GUID(parent), DN: "OU=" + name + ",DC=example,DC=test", RDN: "OU=" + name}
	for _, a := range anc {
		o.Ancestry = append(o.Ancestry, inventory.GUID(a))
	}
	return o
}
func (e *env) policyTx(t *testing.T, fn func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error) {
	t.Helper()
	if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error { return fn(ctx, tx, inventory.PolicyWriter{}) }); err != nil {
		t.Fatalf("policy: %v", err)
	}
}

func cellStr(r map[report.ColumnID]report.Cell, c report.ColumnID) string {
	s := cellKey(r[c])
	if i := strings.Index(s, ":"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// fsp is a foreign security principal row: a member with no resolvable object.
func fsp(guid string, rid uint32) inventory.Observation {
	return inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(hDom), Kind: inventory.KindFSP, Class: "foreignSecurityPrincipal", State: inventory.ObjLive,
		Parent: inventory.GUID(hOU), Ancestry: []inventory.GUID{inventory.GUID(hOU), inventory.GUID(hDom)}, DN: "CN=fsp,OU=People,DC=example,DC=test", RDN: "CN=fsp", SID: hSID(rid)}
}

func (e *env) under(o inventory.Observation, parent string, chain ...string) inventory.Observation {
	o.Parent = inventory.GUID(parent)
	o.Ancestry = nil
	for _, a := range chain {
		o.Ancestry = append(o.Ancestry, inventory.GUID(a))
	}
	return o
}

func cellKey(c report.Cell) string { return c.Tag() + ":" + string(c.DigestValue()) }

// Helpers shared with the library batch 4 and 5 tests that moved here from directory/inventory (T-2249).
// pwUser builds a user observation carrying a classified Cannot Change Password state.
func pwUser(i int, sam string, st sd.PasswordChange, at time.Time) inventory.Observation {
	o := hUser{guid: hGUID(1, i), sam: sam, rid: uint32(1100 + i), uac: i64(uacNormal), read: 15, pwdLastSet: hBase}.obs()
	o.PasswordChange, o.PasswordChangeAt = st, at
	return o
}

func hasEnum(c report.Cell, v string) bool { return strings.HasSuffix(cellKey(c), ":"+v) }

// changeWorld seeds one object of each of the five kinds, a baseline observation, a completed pass, and then
// one change per kind at t1. It returns the ground truth: object GUID -> kind and change kind.
type truth struct{ kind, change string }

func changeWorld(t *testing.T, e *env, c inventory.ConnectionID) (map[string]truth, time.Time) {
	t.Helper()
	e.hStructure(t, c)
	uG, gG, cG, kG, oG, quiet := hGUID(1, 1), hGUID(2, 1), hGUID(4, 1), hGUID(5, 1), hGUID(6, 1), hGUID(1, 2)
	user := func(g, sam string, rid uint32, desc string) inventory.Observation {
		o := hUser{guid: g, sam: sam, rid: rid, uac: i64(uacNormal), read: 15}.obs()
		o.Attributes = map[string]any{"description": desc}
		return o
	}
	comp := func(sam, desc string) inventory.Observation {
		o := hUser{guid: cG, sam: sam, rid: 3001, uac: i64(uacWks), read: 15, kind: inventory.KindComputer, class: "computer"}.obs()
		o.Attributes = map[string]any{"description": desc}
		return o
	}
	contact := func(desc string) inventory.Observation {
		o := inventory.Observation{Object: inventory.GUID(kG), NC: inventory.GUID(hDom), Kind: inventory.KindContact, Class: "contact", State: inventory.ObjLive,
			Parent: inventory.GUID(hOU), Ancestry: []inventory.GUID{inventory.GUID(hOU), inventory.GUID(hDom)}, DN: "CN=kim,OU=People,DC=example,DC=test", RDN: "CN=kim",
			Attributes: map[string]any{"description": desc}}
		return o
	}
	ou := func(name string) inventory.Observation {
		o := ouObs(oG, name, hOU, hOU, hDom)
		return o
	}
	base := []inventory.Observation{user(uG, "alice", 1101, "v1"), user(quiet, "quiet", 1102, "same"), hGroup(gG, "staff", 2001), comp("PC1$", "v1"), contact("v1"), ou("Sales")}
	// Before the first pass completes the connection has no history: the baseline is not "created".
	if _, err := e.populate(t, c, hBase.Add(time.Hour), base...); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM public.directory_object_changes`); n != 0 {
		t.Fatalf("the baseline pass recorded %d changes, want 0", n)
	}
	if err := e.pass(t, c, hDom, hBase.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	t1 := hBase.Add(3 * time.Hour)
	gone := hGroup(gG, "staff", 2001)
	gone.State = inventory.ObjDeleted
	renamed := ou("Sales-EMEA")
	renamed.RDN = "OU=Sales-EMEA"
	if _, err := e.populate(t, c, t1, user(uG, "alice", 1101, "v2"), user(quiet, "quiet", 1102, "same"), gone, comp("PC1$", "v2"), contact("v2"), renamed); err != nil {
		t.Fatal(err)
	}
	return map[string]truth{
		uG: {"user", "edited"}, gG: {"group", "deleted"}, cG: {"computer", "edited"}, kG: {"contact", "edited"}, oG: {"ou", "renamed"},
	}, t1
}

const uacWks = 4096 // WORKSTATION_TRUST_ACCOUNT

func (e *env) count(t *testing.T, sql string, args ...any) (n int) {
	t.Helper()
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error { return tx.QueryRow(ctx, sql, args...).Scan(&n) })
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) pass(t *testing.T, c inventory.ConnectionID, nc string, at time.Time) error {
	t.Helper()
	return e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error { return w.RecordPass(ctx, tx, c, inventory.GUID(nc), at) })
}
