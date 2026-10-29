package inventory_test

import (
	"context"
	"errors"
	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

var (
	pop inventory.Populator
	t2  = t1.Add(time.Hour)
)

const (
	nc1  = "bbbbbbbb-0000-4000-8000-000000000001"
	ou1  = "cccccccc-0000-4000-8000-000000000001"
	usr1 = "aaaaaaaa-0000-4000-8000-0000000000a1"
	usr2 = "aaaaaaaa-0000-4000-8000-0000000000a2"
	grp1 = "aaaaaaaa-0000-4000-8000-0000000000b1"
	grp2 = "aaaaaaaa-0000-4000-8000-0000000000b2"
	dom1 = "aaaaaaaa-0000-4000-8000-0000000000b3"
)

func (e *env) populate(t *testing.T, c inventory.ConnectionID, at time.Time, obs ...inventory.Observation) (inventory.Populated, error) {
	t.Helper()
	var out inventory.Populated
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
		out, err = pop.Populate(ctx, tx, c, at, obs)
		return
	})
	return out, err
}

func (e *env) count(t *testing.T, sql string, args ...any) (n int) {
	t.Helper()
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error { return tx.QueryRow(ctx, sql, args...).Scan(&n) })
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func adUser(g, nc string) inventory.Observation {
	return inventory.Observation{Object: inventory.GUID(g), NC: inventory.GUID(nc), Kind: inventory.KindUser, Class: "user",
		DN: `CN=Smith\, Ünï,OU=Ops,DC=corp,DC=example`, SID: sid, SAMAccountName: "usmith", State: inventory.ObjLive}
}

func enUser(g string, syncEnabled *bool) inventory.Observation {
	return inventory.Observation{Object: inventory.GUID(g), Kind: inventory.KindUser, Class: "user", UPN: "a@x.example",
		OnPremisesSyncEnabled: syncEnabled, State: inventory.ObjActive}
}

func TestPopulateADCycleWithEdges(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		var members []inventory.GUID
		// a group over the 1,500 mark with a circular nest
		for i := 0; i < 1600; i++ {
			members = append(members, inventory.GUID(guidN(i+1)))
		}
		grp := inventory.Observation{Object: grp1, NC: nc1, Kind: inventory.KindGroup, Class: "group", State: inventory.ObjLive,
			SID: sid, Members: append(members, grp2), MembersComplete: true}
		grpB := inventory.Observation{Object: grp2, NC: nc1, Kind: inventory.KindGroup, Class: "group", State: inventory.ObjLive,
			SID: sid, Members: []inventory.GUID{grp1}, MembersComplete: true}
		u := adUser(usr1, nc1)
		u.PrimaryGroup = dom1
		dom := inventory.Observation{Object: dom1, NC: nc1, Kind: inventory.KindGroup, Class: "group", State: inventory.ObjLive, SID: sid}
		res, err := e.populate(t, e.adA, t1, u, grp, grpB, dom)
		if err != nil || res.Inserted != 4 || res.PrimaryGroups != 1 || res.Members != 1602 {
			t.Fatalf("populate: %+v %v", res, err)
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE nc_guid = $1::uuid AND observed_at = $2 AND sid IS NOT NULL`, nc1, t1); n != 4 {
			t.Fatalf("rows: %d", n)
		}
		// primary-group edge reaches GroupsOf; circular nesting terminates.
		got, err := inventory.NewGroups(e.db).GroupsOf(ctx, e.a, e.adA, usr1)
		if err != nil || len(got) != 1 || got[0] != dom1 {
			t.Fatalf("groups of user: %v %v", got, err)
		}
		got, err = inventory.NewGroups(e.db).GroupsOf(ctx, e.a, e.adA, grp1)
		if err != nil || len(got) != 1 || got[0] != grp2 {
			t.Fatalf("circular: %v %v", got, err)
		}
		// Next cycle: a full read without the last 100 members and a changed primary group.
		grp.Members, u.PrimaryGroup = members[:1500], grp2
		grp.DN = "CN=g2,DC=corp"
		if _, err := e.populate(t, e.adA, t2, u, grp); err != nil {
			t.Fatal(err)
		}
		if n := e.count(t, `SELECT count(*) FROM public.links WHERE source_guid = $1::uuid AND link_attr = 'member' AND state = 'active'`, grp1); n != 1500 {
			t.Fatalf("active members: %d", n)
		}
		if n := e.count(t, `SELECT count(*) FROM public.links WHERE link_attr = 'primary_group' AND target_guid = $1::uuid AND state = 'active' AND source_guid = $2::uuid`, usr1, grp2); n != 1 {
			t.Fatalf("new primary group: %d", n)
		}
		got, _ = inventory.NewGroups(e.db).GroupsOf(ctx, e.a, e.adA, usr1)
		if len(got) != 1 || got[0] != grp2 {
			t.Fatalf("primary group after change: %v", got)
		}
		for _, g := range got {
			if g == dom1 {
				t.Fatalf("old primary group still active: %v", got)
			}
		}
	})
}

func TestPopulateStaleAndInvalid(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		u := adUser(usr1, nc1)
		if _, err := e.populate(t, e.adA, t2, u); err != nil {
			t.Fatal(err)
		}
		u.DisplayName = "old"
		res, err := e.populate(t, e.adA, t1, u)
		if err != nil || res.Stale != 1 || res.Updated != 0 {
			t.Fatalf("stale: %+v %v", res, err)
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE display_name = ''`); n != 1 {
			t.Fatal("a late observation overwrote newer state")
		}
		bad := map[string]func(*inventory.Observation){
			"secret attr":     func(o *inventory.Observation) { o.Attributes = map[string]any{"unicodePwd": "x"} },
			"AD without NC":   func(o *inventory.Observation) { o.NC = "" },
			"entra state":     func(o *inventory.Observation) { o.State = inventory.ObjActive },
			"bad kind":        func(o *inventory.Observation) { o.Kind = "x" },
			"upper guid":      func(o *inventory.Observation) { o.Object = "AAAAAAAA-0000-4000-8000-0000000000A1" },
			"members on user": func(o *inventory.Observation) { o.Members = []inventory.GUID{usr2} },
			"cloud on AD":     func(o *inventory.Observation) { o.CloudManaged = true },
			"option form":     func(o *inventory.Observation) { o.Attributes = map[string]any{"unicodePwd;binary": "x"} },
			"range option":    func(o *inventory.Observation) { o.Attributes = map[string]any{"ms-Mcs-AdmPwd;range=0-*": "x"} },
			"OID form":        func(o *inventory.Observation) { o.Attributes = map[string]any{"1.2.840.113556.1.4.90": "x"} },
			"empty key":       func(o *inventory.Observation) { o.Attributes = map[string]any{"": "x"} },
			"nested": func(o *inventory.Observation) {
				o.Attributes = map[string]any{"wrap": map[string]any{"unicodePwd": "x"}}
			},
			"nested in list": func(o *inventory.Observation) {
				o.Attributes = map[string]any{"l": []any{map[string]string{"msFVE-RecoveryPassword": "x"}}}
			},
			"trust auth": func(o *inventory.Observation) { o.Attributes = map[string]any{"TrustAuthIncoming": "x"} },
		}
		for _, n := range secretattr.Static() {
			n := n
			bad["static "+n] = func(o *inventory.Observation) { o.Attributes = map[string]any{strings.ToUpper(n): "x"} }
			bad["static mixed "+n] = func(o *inventory.Observation) { o.Attributes = map[string]any{n + ";binary": "x"} }
		}
		for name, mut := range bad {
			o := adUser(usr2, nc1)
			mut(&o)
			if _, err := e.populate(t, e.adA, t2, adUser(usr1, nc1), o); !errors.Is(err, inventory.ErrInvalid) {
				t.Errorf("%s: %v", name, err)
			}
		}
		if n := e.count(t, `SELECT count(*) FROM public.directory_objects WHERE object_guid = $1::uuid`, usr2); n != 0 {
			t.Fatal("invalid batch partly written")
		}
		// Tenant B's connection is not ours.
		if _, err := e.populate(t, e.adB, t2, u); !errors.Is(err, inventory.ErrUnknownConnection) {
			t.Fatalf("foreign connection: %v", err)
		}
	})
}

// DM-16.I9 and the database guard.
func TestCloudSeenAtOnlyMovesForward(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		yes, no := true, false
		// synced first: not cloud-seen. Cloud-only: seen. Cloud-managed synced: seen.
		if res, err := e.populate(t, e.enA, t1, enUser(enG1, &yes), enUser(enG2, &no), enUser(enG3, nil)); err != nil || res.CloudSeen != 2 {
			t.Fatalf("%+v %v", res, err)
		}
		cm := enUser(enG1, &yes)
		cm.CloudManaged = true
		if _, err := e.populate(t, e.enA, t2, cm, enUser(enG2, &yes)); err != nil {
			t.Fatal(err)
		}
		seen := func(g string) (tm *time.Time) {
			_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT cloud_seen_at FROM public.directory_objects WHERE object_guid = $1::uuid`, g).Scan(&tm)
			})
			return
		}
		if x := seen(enG1); x == nil || !x.Equal(t2) {
			t.Fatalf("cloud-managed: %v", x)
		}
		if x := seen(enG2); x == nil || !x.Equal(t1) { // now synced, but never cleared
			t.Fatalf("cleared: %v", x)
		}
		// The database refuses a clear or a move back from any writer.
		for _, q := range []string{`UPDATE public.directory_objects SET cloud_seen_at = NULL WHERE object_guid = $1::uuid`,
			`UPDATE public.directory_objects SET cloud_seen_at = cloud_seen_at - interval '1 day' WHERE object_guid = $1::uuid`} {
			if err := e.exec(e.a, q, enG2); err == nil {
				t.Errorf("accepted: %s", q)
			}
		}
		// I9: AD objects carry none.
		if err := e.exec(e.a, `UPDATE public.directory_objects SET cloud_seen_at = now(), nc_guid = $2::uuid WHERE object_guid = $1::uuid`, enG2, nc1); err == nil {
			t.Error("cloud_seen_at on an AD-shaped row")
		}
		// Entra computers/others never get one.
		o := enUser("eeeeeeee-0000-4000-8000-0000000000d1", &no)
		o.Kind = inventory.KindOther
		o.Class = "device"
		if res, err := e.populate(t, e.enA, t2, o); err != nil || res.CloudSeen != 0 {
			t.Fatalf("other: %+v %v", res, err)
		}
	})
}

func TestAnchorMatchesAcrossADConnections(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		adA2 := inventory.ConnectionID(e.conn(t, e.a, "ad_forest", "ldaps"))
		g, _ := guid.Parse(usr1)
		a1, _ := guid.Parse(usr2)
		// connection 1: usr1 has objectGUID == anchor; connection 2: another user carries the anchor as ms-DS-ConsistencyGuid.
		u1 := adUser(usr1, nc1)
		u2 := adUser(usr2, nc1)
		u2.ConsistencyGUID = g.Bytes()
		u3 := adUser("aaaaaaaa-0000-4000-8000-0000000000a3", nc1)
		u3.ConsistencyGUID = a1.Bytes()
		if _, err := e.populate(t, e.adA, t1, u1, u3); err != nil {
			t.Fatal(err)
		}
		if _, err := e.populate(t, adA2, t1, u2); err != nil {
			t.Fatal(err)
		}
		count := func(conns []inventory.ConnectionID, v []byte) (n int, err error) {
			err = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
				n, err = w.AnchorMatches(ctx, tx, conns, v)
				return
			})
			return
		}
		both := []inventory.ConnectionID{e.adA, adA2}
		if n, err := count(both, g.Bytes()); err != nil || n != 2 {
			t.Fatalf("both connections: %d %v", n, err)
		}
		if n, err := count([]inventory.ConnectionID{e.adA}, g.Bytes()); err != nil || n != 1 {
			t.Fatalf("one connection: %d %v", n, err)
		}
		if n, err := count(both, a1.Bytes()); err != nil || n != 2 { // usr2 by objectGUID, u3 by consistency guid
			t.Fatalf("mixed: %d %v", n, err)
		}
		if n, err := count(both, []byte("employee-1")); err != nil || n != 0 {
			t.Fatalf("non-guid: %d %v", n, err)
		}
		// Not an AD connection of the tenant: an error, not an undercount.
		if _, err := count([]inventory.ConnectionID{e.adA, e.enA}, g.Bytes()); !errors.Is(err, inventory.ErrUnknownConnection) {
			t.Fatalf("entra connection: %v", err)
		}
		if _, err := count([]inventory.ConnectionID{e.adB}, g.Bytes()); !errors.Is(err, inventory.ErrUnknownConnection) {
			t.Fatalf("other tenant: %v", err)
		}
		_ = ctx
	})
}

func TestAnchorMatchesCountsOnlyUserKinds(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		anchor, _ := guid.Parse(usr1)
		others := []struct {
			kind  inventory.Kind
			class string
		}{{inventory.KindComputer, "computer"}, {inventory.KindGMSA, "msDS-GroupManagedServiceAccount"},
			{inventory.KindGroup, "group"}, {inventory.KindContact, "contact"}}
		var obs []inventory.Observation
		for i, o := range others {
			x := adUser(guidN(0x100+i), nc1) // matches by ms-DS-ConsistencyGuid
			x.Kind, x.Class, x.SID = o.kind, o.class, nil
			x.ConsistencyGUID = anchor.Bytes()
			obs = append(obs, x)
		}
		c := adUser(anchor.String(), nc1) // a computer whose objectGUID is the anchor
		c.Kind, c.Class, c.SID = inventory.KindComputer, "computer", nil
		obs = append(obs, c)
		if _, err := e.populate(t, e.adA, t1, obs...); err != nil {
			t.Fatal(err)
		}
		count := func(v []byte) (n int) {
			if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
				n, err = w.AnchorMatches(ctx, tx, []inventory.ConnectionID{e.adA}, v)
				return
			}); err != nil {
				t.Fatal(err)
			}
			return
		}
		if n := count(anchor.Bytes()); n != 0 {
			t.Fatalf("non-user kinds: %d", n)
		}
		// user and inetOrgPerson still count.
		u := adUser(guidN(0x300), nc1)
		u.ConsistencyGUID = anchor.Bytes()
		ip := adUser(guidN(0x301), nc1)
		ip.Kind, ip.Class = inventory.KindInetOrgPerson, "inetOrgPerson"
		ip.ConsistencyGUID = anchor.Bytes()
		if _, err := e.populate(t, e.adA, t1, u, ip); err != nil {
			t.Fatal(err)
		}
		if n := count(anchor.Bytes()); n != 2 {
			t.Fatalf("user+inetOrgPerson: %d", n)
		}
	})
}

func guidN(i int) string {
	return "dddddddd-0000-4000-8000-" + hex12(i)
}

func hex12(i int) string {
	const d = "0123456789abcdef"
	b := []byte("000000000000")
	for p := 11; i > 0; p-- {
		b[p] = d[i%16]
		i /= 16
	}
	return string(b)
}
