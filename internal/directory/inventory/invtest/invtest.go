// Package invtest is the exported inventory test kit (ADR-0013 decision 4). It writes a realistic,
// deterministic inventory (an NC head, an OU, a PSO container, users, groups, FSPs) through the public
// inventory API into a real PostgreSQL database, so a module's tests can seed what they read without
// importing another module or copying a harness. Tests only: product code never imports it.
package invtest

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
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const Cred = "11111111-1111-4111-8111-111111111111"

var pop inventory.Populator

type Env struct {
	D    *storetest.Database
	DB   *store.DB
	A, B tenant.ID              // two seeded tenants
	AdA  inventory.ConnectionID // an AD forest of tenant A
	EnA  inventory.ConnectionID // an Entra tenant of tenant A
	AdB  inventory.ConnectionID // an AD forest of tenant B
	R    *inventory.Reader
}

func (e *Env) Conn(t *testing.T, tid tenant.ID, kind connection.Kind, tr connection.Transport) inventory.ConnectionID {
	t.Helper()
	c, err := connection.NewRegistry(e.DB).Create(context.Background(), tid,
		connection.New{Kind: kind, DisplayName: "c", CredentialID: Cred, Transport: tr})
	if err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	return inventory.ConnectionID(c.ID)
}

func Setup(t *testing.T, s *storetest.Server) *Env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	e := &Env{D: d}
	e.A = tenanttest.Seed(t, d.ExecOwner, "A")
	e.B = tenanttest.Seed(t, d.ExecOwner, "B")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e.DB = db
	e.AdA = e.Conn(t, e.A, connection.KindADForest, connection.TransportLDAPS)
	e.EnA = e.Conn(t, e.A, connection.KindEntraTenant, "")
	e.AdB = e.Conn(t, e.B, connection.KindADForest, connection.TransportLDAPS)
	e.R = inventory.NewReader(db, inventory.NewFake())
	return e
}

func (e *Env) Tx(t *testing.T, tid tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error {
	t.Helper()
	return e.DB.WithTenant(context.Background(), tid, fn)
}

func (e *Env) Populate(t *testing.T, c inventory.ConnectionID, at time.Time, obs ...inventory.Observation) (inventory.Populated, error) {
	t.Helper()
	var out inventory.Populated
	err := e.Tx(t, e.A, func(ctx context.Context, tx store.Tx) (err error) {
		out, err = pop.Populate(ctx, tx, c, at, obs)
		return
	})
	return out, err
}

func (e *Env) Registry(t *testing.T) *reportsql.Registry {
	t.Helper()
	var reg *reportsql.Registry
	err := e.Tx(t, e.A, func(ctx context.Context, tx store.Tx) error {
		sc, err := reportsql.CatalogSchema(ctx, tx)
		if err != nil {
			return err
		}
		reg, err = reportsql.NewRegistry(reportsql.Options{Schema: sc, SecretKey: inventory.SecretKey}, inventory.Datasets()...)
		return err
	})
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	return reg
}

func RPID(s string) authz.ObjectID {
	id, err := authz.ParseObjectID(s)
	if err != nil {
		panic(err)
	}
	return id
}

const (
	Dom = "dddddddd-0000-4000-8000-000000000001" // the naming-context head
	OU  = "dddddddd-0000-4000-8000-000000000002" // the OU the users live in
	Sys = "dddddddd-0000-4000-8000-000000000003" // the Password Settings Container (outside OU)
)

var Base = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

// GUID makes a deterministic GUID from a class byte and an index.
func GUID(class byte, i int) string {
	return fmt.Sprintf("%02x000000-0000-4000-8000-%012x", class, i)
}

// SID is a domain SID S-1-5-21-1-2-3-<rid>, binary.
func SID(rid uint32) []byte {
	b := []byte{1, 5, 0, 0, 0, 0, 0, 5}
	for _, v := range []uint32{21, 1, 2, 3, rid} {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return b
}

func I64(v int64) *int64              { return &v }
func Days(n int64) *filetime.Interval { return &filetime.Interval{Ticks: n * 86400 * 10_000_000} }
func Mins(n int64) *filetime.Interval { return &filetime.Interval{Ticks: n * 60 * 10_000_000} }
func Forever() *filetime.Interval     { return &filetime.Interval{Forever: true} }

// Structure writes the NC head, the OU the users live in and the container the PSOs live in. Both
// children are direct children of the head.
func (e *Env) Structure(t *testing.T, c inventory.ConnectionID) {
	t.Helper()
	obs := []inventory.Observation{
		{Object: inventory.GUID(Dom), NC: inventory.GUID(Dom), Kind: inventory.KindOther, Class: "domainDNS", State: inventory.ObjLive},
		{Object: inventory.GUID(OU), NC: inventory.GUID(Dom), Kind: inventory.KindOU, Class: "organizationalUnit", State: inventory.ObjLive,
			Parent: inventory.GUID(Dom), Ancestry: []inventory.GUID{inventory.GUID(Dom)}},
		{Object: inventory.GUID(Sys), NC: inventory.GUID(Dom), Kind: inventory.KindContainer, Class: "container", State: inventory.ObjLive,
			Parent: inventory.GUID(Dom), Ancestry: []inventory.GUID{inventory.GUID(Dom)}},
	}
	if _, err := e.Populate(t, c, Base, obs...); err != nil {
		t.Fatalf("structure: %v", err)
	}
}

// User is one user with every D7 input read unless a field says otherwise.
type User struct {
	GUID       string
	Sam        string
	RID        uint32
	UAC        *int64
	Read       inventory.InputsRead
	Lockout    time.Time
	PwdLastSet time.Time
	Expires    time.Time
	SPN        *bool
	Primary    string // a group GUID
	Kind       inventory.Kind
	Class      string
	Parent     string // default OU
}

const UACNormal = 512

func (u User) Obs() inventory.Observation {
	parent := u.Parent
	if parent == "" {
		parent = OU
	}
	k, cl := u.Kind, u.Class
	if k == "" {
		k, cl = inventory.KindUser, "user"
	}
	anc := []inventory.GUID{inventory.GUID(parent)}
	if parent != Dom {
		anc = append(anc, inventory.GUID(Dom))
	}
	return inventory.Observation{Object: inventory.GUID(u.GUID), NC: inventory.GUID(Dom), Kind: k, Class: cl, State: inventory.ObjLive,
		Parent: inventory.GUID(parent), Ancestry: anc, DN: "CN=" + u.Sam + ",OU=People,DC=example,DC=test", RDN: "CN=" + u.Sam,
		SID: SID(u.RID), SAMAccountName: u.Sam, UserAccountControl: u.UAC, InputsRead: u.Read,
		LockoutTime: u.Lockout, PwdLastSet: u.PwdLastSet, AccountExpires: u.Expires, HasSPN: u.SPN,
		PrimaryGroup: inventory.GUID(u.Primary), WhenCreated: Base.Add(-24 * time.Hour)}
}

// Group is a group with the given direct members (users or groups).
func Group(guid, name string, rid uint32, members ...string) inventory.Observation {
	o := inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(Dom), Kind: inventory.KindGroup, Class: "group", State: inventory.ObjLive,
		Parent: inventory.GUID(OU), Ancestry: []inventory.GUID{inventory.GUID(OU), inventory.GUID(Dom)}, DN: "CN=" + name + ",OU=People,DC=example,DC=test",
		RDN: "CN=" + name, SID: SID(rid), SAMAccountName: name, MembersComplete: true}
	for _, m := range members {
		o.Members = append(o.Members, inventory.GUID(m))
	}
	return o
}

// PSOObj is the directory object of a PSO, Under the container Sys (outside the OU).
func PSOObj(guid, name string) inventory.Observation {
	return inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(Dom), Kind: inventory.KindOther, Class: "msDS-PasswordSettings", State: inventory.ObjLive,
		Parent: inventory.GUID(Sys), Ancestry: []inventory.GUID{inventory.GUID(Sys), inventory.GUID(Dom)}, DN: "CN=" + name + ",CN=Password Settings Container,CN=System,DC=example,DC=test",
		RDN: "CN=" + name}
}

func OUObs(guid, name, parent string, anc ...string) inventory.Observation {
	o := inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(Dom), Kind: inventory.KindOU, Class: "organizationalUnit", State: inventory.ObjLive,
		Parent: inventory.GUID(parent), DN: "OU=" + name + ",DC=example,DC=test", RDN: "OU=" + name}
	for _, a := range anc {
		o.Ancestry = append(o.Ancestry, inventory.GUID(a))
	}
	return o
}
func (e *Env) PolicyTx(t *testing.T, fn func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error) {
	t.Helper()
	if err := e.Tx(t, e.A, func(ctx context.Context, tx store.Tx) error { return fn(ctx, tx, inventory.PolicyWriter{}) }); err != nil {
		t.Fatalf("policy: %v", err)
	}
}

func CellStr(r map[report.ColumnID]report.Cell, c report.ColumnID) string {
	s := CellKey(r[c])
	if i := strings.Index(s, ":"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// FSP is a foreign security principal row: a member with no resolvable object.
func FSP(guid string, rid uint32) inventory.Observation {
	return inventory.Observation{Object: inventory.GUID(guid), NC: inventory.GUID(Dom), Kind: inventory.KindFSP, Class: "foreignSecurityPrincipal", State: inventory.ObjLive,
		Parent: inventory.GUID(OU), Ancestry: []inventory.GUID{inventory.GUID(OU), inventory.GUID(Dom)}, DN: "CN=FSP,OU=People,DC=example,DC=test", RDN: "CN=FSP", SID: SID(rid)}
}

func (e *Env) Under(o inventory.Observation, parent string, chain ...string) inventory.Observation {
	o.Parent = inventory.GUID(parent)
	o.Ancestry = nil
	for _, a := range chain {
		o.Ancestry = append(o.Ancestry, inventory.GUID(a))
	}
	return o
}

func CellKey(c report.Cell) string { return c.Tag() + ":" + string(c.DigestValue()) }
