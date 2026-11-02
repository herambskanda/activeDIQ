package sync_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/store"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// The apply step (T-1197) is tested against Postgres only: it is pure inventory SQL, so the directory lab has
// nothing to add. The DirSync wire shapes (what a tombstone carries) are [UNVERIFIED Windows] in contract §6.4;
// these tests pin what the mapper does with the shapes the contract describes.

const (
	hGUID   = domainNC // the head of the naming context
	staff   = ouGUID   // OU=Staff
	priya   = 10
	grpAll  = 20
	grpExtr = 21
	rid     = 1100 // grpAll's RID
)

var (
	t0 = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Hour)
	t2 = t0.Add(2 * time.Hour)
)

func cset(name string, vs ...*connectorv1.AttributeValue) *connectorv1.AttributeChange {
	return &connectorv1.AttributeChange{Name: name, Op: connectorv1.ChangeOp_CHANGE_OP_SET, Values: vs}
}

func cclear(name string) *connectorv1.AttributeChange {
	return &connectorv1.AttributeChange{Name: name, Op: connectorv1.ChangeOp_CHANGE_OP_CLEARED}
}

func cadd(name string, vs ...*connectorv1.AttributeValue) *connectorv1.AttributeChange {
	return &connectorv1.AttributeChange{Name: name, Op: connectorv1.ChangeOp_CHANGE_OP_VALUES_ADDED, Values: vs}
}

func cdel(name string, vs ...*connectorv1.AttributeValue) *connectorv1.AttributeChange {
	return &connectorv1.AttributeChange{Name: name, Op: connectorv1.ChangeOp_CHANGE_OP_VALUES_REMOVED, Values: vs}
}

func classes(cs ...string) *connectorv1.AttributeChange {
	var vs []*connectorv1.AttributeValue
	for _, c := range cs {
		vs = append(vs, txt(c))
	}
	return cset("objectClass", vs...)
}

func change(obj uint64, st connectorv1.ObjectState, dn string, parent *connectorv1.Guid, as ...*connectorv1.AttributeChange) *connectorv1.ObjectChange {
	c := &connectorv1.ObjectChange{ObjectGuid: gid(obj), State: st, ParentGuid: parent, Attributes: as}
	if dn != "" {
		c.Dn = &connectorv1.DnValue{DisplayDn: dn}
	}
	return c
}

func live(obj uint64, dn string, parent uint64, as ...*connectorv1.AttributeChange) *connectorv1.ObjectChange {
	var p *connectorv1.Guid
	if parent != 0 {
		p = gid(parent)
	}
	return change(obj, connectorv1.ObjectState_OBJECT_STATE_LIVE, dn, p, as...)
}

func gen(t time.Time) *connectorv1.AttributeValue { return at(t) }

// newOU is the full creation set of an OU.
func newOU(obj uint64, name string, parentDN string, parent uint64) *connectorv1.ObjectChange {
	return live(obj, "OU="+name+","+parentDN, parent, classes("top", "organizationalUnit"), cset("whenCreated", gen(t0)))
}

const root = "DC=corp,DC=example"

func newHead() *connectorv1.ObjectChange {
	return live(hGUID, root, 0, classes("top", "domain", "domainDNS"), cset("whenCreated", gen(t0)))
}

func userAttrs(sam string, rid uint32, primary int32, extra ...*connectorv1.AttributeChange) []*connectorv1.AttributeChange {
	return append([]*connectorv1.AttributeChange{
		classes("top", "person", "organizationalPerson", "user"), cset("whenCreated", gen(t0)),
		cset("sAMAccountName", txt(sam)), cset("objectSid", sidv(domSID(rid))),
		cset("userAccountControl", i32(0x200)), cset("primaryGroupID", i32(primary)),
		cset("pwdLastSet", gen(t0)),
	}, extra...)
}

func newUser(obj uint64, cn, parentDN string, parent uint64, rid uint32, primary int32, extra ...*connectorv1.AttributeChange) *connectorv1.ObjectChange {
	return live(obj, "CN="+cn+","+parentDN, parent, userAttrs(strings.ToLower(cn), rid, primary, extra...)...)
}

func newGroup(obj uint64, cn, parentDN string, parent uint64, rid uint32, extra ...*connectorv1.AttributeChange) *connectorv1.ObjectChange {
	return live(obj, "CN="+cn+","+parentDN, parent, append([]*connectorv1.AttributeChange{
		classes("top", "group"), cset("whenCreated", gen(t0)), cset("sAMAccountName", txt(cn)),
		cset("objectSid", sidv(domSID(rid))), cset("groupType", i32(-2147483646)),
	}, extra...)...)
}

func member(n uint64) *connectorv1.AttributeValue {
	return dnv(fmt.Sprintf("CN=m%d,%s", n, root), gid(n))
}

func tombstone(obj uint64, state connectorv1.ObjectState) *connectorv1.ObjectChange {
	return change(obj, state, fmt.Sprintf("CN=u\nDEL:%s,CN=Deleted Objects,%s", gtext(obj), root), gid(99))
}

func applier(t *testing.T) *dsync.Applier {
	t.Helper()
	cm, err := dsync.NewChangeMapper(dsync.Config{NC: inventory.GUID(gtext(hGUID))})
	if err != nil {
		t.Fatal(err)
	}
	return &dsync.Applier{Mapper: cm, Writer: dsync.NewIngester()}
}

// apply writes one batch in its own committed transaction.
func (e *env) apply(t *testing.T, ap *dsync.Applier, asOf time.Time, cs ...*connectorv1.ObjectChange) dsync.ApplyReport {
	t.Helper()
	var rep dsync.ApplyReport
	if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		var err error
		rep, err = ap.Apply(ctx, tx, &connectorv1.ChangeBatch{Changes: cs}, e.opts(asOf))
		return err
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	return rep
}

func (e *env) opts(asOf time.Time) dsync.ApplyOptions {
	return dsync.ApplyOptions{Connection: e.conn, Observed: asOf, Now: asOf, ObservedDSA: "dc1"}
}

// dump is every stored fact about the connection, as sorted text: the objects (all columns, optionally without
// observed_at), the member edges and the group closure.
func (e *env) dump(t *testing.T, withObserved bool) string {
	t.Helper()
	var out []string
	if err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		var err error
		out, err = dumpTx(ctx, tx, string(e.conn), withObserved)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return strings.Join(out, "\n")
}

func dumpTx(ctx context.Context, tx store.Tx, conn string, withObserved bool) ([]string, error) {
	var out []string
	col := `to_jsonb(d) - 'observed_at'`
	if withObserved {
		col = `to_jsonb(d)`
	}
	for _, q := range []struct{ label, sql string }{
		{"obj", `SELECT ` + col + `::text FROM public.directory_objects d WHERE connection_id = $1::uuid ORDER BY object_guid`},
		{"link", `SELECT source_guid::text || ' ' || link_attr || ' ' || target_guid::text || ' ' || state FROM public.links WHERE connection_id = $1::uuid ORDER BY 1`},
		{"closure", `SELECT group_guid::text || ' ' || member_guid::text || ' ' || edge_kind || ' ' || depth || ' ' || via::text || ' ' || cut FROM public.inventory_group_members WHERE connection_id = $1::uuid ORDER BY 1`},
		{"dirty", `SELECT group_guid::text FROM public.inventory_group_closure_dirty WHERE connection_id = $1::uuid ORDER BY 1`},
	} {
		rows, err := tx.Query(ctx, q.sql, conn)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, q.label+" "+s)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// row is one directory_objects row as column -> text.
func (e *env) row(t *testing.T, obj uint64) map[string]any {
	t.Helper()
	var js map[string]any
	err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		var s *string
		rows, err := tx.Query(ctx, `SELECT to_jsonb(d)::text FROM public.directory_objects d WHERE connection_id = $1::uuid AND object_guid = $2::uuid`, string(e.conn), gtext(obj))
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			s = new(string)
			if err := rows.Scan(s); err != nil {
				return err
			}
		}
		if s != nil {
			js = map[string]any{}
			return json.Unmarshal([]byte(*s), &js)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return js
}

// edges are the active edges of one attr out of source, as sorted GUID numbers' text.
func (e *env) edges(t *testing.T, source uint64, attr string) []string {
	t.Helper()
	var out []string
	err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT target_guid::text FROM public.links WHERE connection_id = $1::uuid AND source_guid = $2::uuid AND link_attr = $3 AND state = 'active' ORDER BY 1`, string(e.conn), gtext(source), attr)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func texts_(ns ...uint64) []string {
	var out []string
	for _, n := range ns {
		out = append(out, gtext(n))
	}
	slices.Sort(out)
	return out
}

// seed stores the head, OU=Staff, the group everyone is primary-grouped to, a user and a second group.
func (e *env) seed(t *testing.T, ap *dsync.Applier) {
	t.Helper()
	ouDN := "OU=Staff," + root
	rep := e.apply(t, ap, t0,
		newHead(),
		newOU(staff, "Staff", root, hGUID),
		newGroup(grpAll, "Everyone", ouDN, staff, rid, cset("member", member(priya), member(30))),
		newGroup(grpExtr, "Extra", ouDN, staff, rid+1),
		newUser(priya, "Raman\\, Priya", ouDN, staff, 1105, rid,
			cset("displayName", txt("Raman, Priya")), cset("mail", txt("p@corp.example")), cset("lockoutTime", gen(t0)),
			cset("servicePrincipalName", txt("http/x")), cset("description", txt("hello"))),
	)
	if rep.Refused != 0 || len(rep.NeedsRead) != 0 || rep.Created != 5 {
		t.Fatalf("seed: %+v", rep)
	}
}

// AC1: a change that sets only displayName changes display_name and observed_at, and nothing else.
func TestPatchChangesOnlyWhatItNames(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seed(t, ap)
		before := e.row(t, priya)
		beforeDump := e.dump(t, false)
		if before["display_name"] != "Raman, Priya" || before["lockout_time"] == nil {
			t.Fatalf("seed row: %v", before)
		}

		rep := e.apply(t, ap, t1, live(priya, "", 0, cset("displayName", txt("Priya R."))))
		if rep.Updated != 1 || rep.Created != 0 || len(rep.NeedsRead) != 0 {
			t.Fatalf("report: %+v", rep)
		}
		after := e.row(t, priya)
		for k, v := range before {
			switch k {
			case "display_name":
				if after[k] != "Priya R." {
					t.Errorf("display_name = %v", after[k])
				}
			case "observed_at":
				if after[k] == v {
					t.Errorf("observed_at did not move")
				}
			default:
				if fmt.Sprint(after[k]) != fmt.Sprint(v) {
					t.Errorf("column %s changed: %v -> %v", k, v, after[k])
				}
			}
		}
		if len(after) != len(before) {
			t.Errorf("columns %d -> %d", len(before), len(after))
		}
		// Nothing else moved: edges and closure included.
		if got, want := e.dump(t, false), strings.Replace(beforeDump, "Raman, Priya", "Priya R.", 1); got != want {
			t.Errorf("dump differs:\n got %s\nwant %s", got, want)
		}
		if got := e.edges(t, grpAll, "member"); !slices.Equal(got, texts_(priya, 30)) {
			t.Errorf("members = %v", got)
		}
	})
}

func TestPatchClearedIsAbsentAndRead(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seed(t, ap)
		before := e.row(t, priya)
		e.apply(t, ap, t1, live(priya, "", 0, cclear("lockoutTime"), cclear("displayName"), cclear("mail"), cclear("description")))
		after := e.row(t, priya)
		if after["lockout_time"] != nil {
			t.Errorf("lockout_time = %v", after["lockout_time"])
		}
		if after["display_name"] != "" {
			t.Errorf("display_name = %v", after["display_name"])
		}
		attrs := after["attributes"].(map[string]any)
		if _, ok := attrs["mail"]; ok {
			t.Errorf("mail still in bag: %v", attrs)
		}
		if _, ok := attrs["description"]; ok {
			t.Errorf("description still in bag: %v", attrs)
		}
		// pwd_last_set, sid, uac untouched.
		for _, k := range []string{"pwd_last_set", "sid", "enabled", "sam_account_name", "dn", "parent_guid", "ancestry"} {
			if fmt.Sprint(after[k]) != fmt.Sprint(before[k]) {
				t.Errorf("%s changed: %v -> %v", k, before[k], after[k])
			}
		}
		// The inputs_read bit of lockoutTime stays set: absent and read, not unread.
		if fmt.Sprint(after["inputs_read"]) != fmt.Sprint(before["inputs_read"]) {
			t.Errorf("inputs_read changed: %v -> %v", before["inputs_read"], after["inputs_read"])
		}
	})
}

// AC2: one VALUES_ADDED and one VALUES_REMOVED change exactly those two edges.
func TestPatchMemberDeltaChangesTwoEdges(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seed(t, ap)
		ids := []uint64{40, 41, 42}
		for i, n := range ids {
			e.apply(t, ap, t0, newUser(n, fmt.Sprintf("m%d", n), "OU=Staff,"+root, staff, uint32(2000+i), 513))
		}
		e.apply(t, ap, t0, live(grpExtr, "", 0, cset("member", member(40), member(41), member(42))))
		if got := e.edges(t, grpExtr, "member"); !slices.Equal(got, texts_(40, 41, 42)) {
			t.Fatalf("seed members = %v", got)
		}
		e.apply(t, ap, t1, newUser(43, "m43", "OU=Staff,"+root, staff, 2003, 513))
		rep := e.apply(t, ap, t2, live(grpExtr, "", 0, cadd("member", member(43)), cdel("member", member(40))))
		if rep.Updated != 1 || rep.Refused != 0 {
			t.Fatalf("report: %+v", rep)
		}
		if got := e.edges(t, grpExtr, "member"); !slices.Equal(got, texts_(41, 42, 43)) {
			t.Fatalf("members = %v", got)
		}
		// m40's edge is removed, not deleted: the other two kept their rows.
		gs, err := inventory.NewGroups(e.db).GroupsOf(context.Background(), e.a, e.conn, inventory.GUID(gtext(43)))
		if err != nil || !slices.Contains(gs, inventory.GUID(gtext(grpExtr))) {
			t.Fatalf("GroupsOf(43) = %v, %v", gs, err)
		}
		gs, err = inventory.NewGroups(e.db).GroupsOf(context.Background(), e.a, e.conn, inventory.GUID(gtext(40)))
		if err != nil || slices.Contains(gs, inventory.GUID(gtext(grpExtr))) {
			t.Fatalf("GroupsOf(40) = %v, %v", gs, err)
		}
		gs, _ = inventory.NewGroups(e.db).GroupsOf(context.Background(), e.a, e.conn, inventory.GUID(gtext(41)))
		if !slices.Contains(gs, inventory.GUID(gtext(grpExtr))) {
			t.Fatalf("GroupsOf(41) = %v", gs)
		}
		// Adding what is there and removing what is not there change nothing.
		before := e.dump(t, false)
		e.apply(t, ap, t2, live(grpExtr, "", 0, cadd("member", member(41)), cdel("member", member(40))))
		if e.dump(t, false) != before {
			t.Errorf("a repeated delta changed the inventory")
		}
	})
}

// AC4: DELETED with a tombstone DN, then RECYCLED: GUID kept, parent kept, edges ended, never regresses.
func TestPatchDeletedThenRecycled(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seed(t, ap)
		before := e.row(t, priya)
		if got := e.edges(t, grpAll, "primary_group"); !slices.Equal(got, texts_(priya)) {
			t.Fatalf("primary group edge = %v", got)
		}

		del := tombstone(priya, connectorv1.ObjectState_OBJECT_STATE_DELETED)
		rep := e.apply(t, ap, t1, del)
		if rep.Updated != 1 {
			t.Fatalf("report: %+v", rep)
		}
		r := e.row(t, priya)
		if r["state"] != "deleted" || r["object_guid"] != gtext(priya) {
			t.Fatalf("state/guid: %v %v", r["state"], r["object_guid"])
		}
		if r["parent_guid"] != before["parent_guid"] || fmt.Sprint(r["ancestry"]) != fmt.Sprint(before["ancestry"]) {
			t.Errorf("parent/ancestry moved: %v %v", r["parent_guid"], r["ancestry"])
		}
		if !strings.Contains(r["dn"].(string), "CN=Deleted Objects") {
			t.Errorf("dn = %v", r["dn"])
		}
		if r["sam_account_name"] != before["sam_account_name"] || r["sid"] != before["sid"] {
			t.Errorf("identity columns lost: %v %v", r["sam_account_name"], r["sid"])
		}
		if got := e.edges(t, grpAll, "member"); !slices.Equal(got, texts_(30)) {
			t.Errorf("members after delete = %v", got)
		}
		if got := e.edges(t, grpAll, "primary_group"); len(got) != 0 {
			t.Errorf("primary group edge after delete = %v", got)
		}

		rec := tombstone(priya, connectorv1.ObjectState_OBJECT_STATE_RECYCLED)
		e.apply(t, ap, t2, rec)
		if r := e.row(t, priya); r["state"] != "recycled" || r["object_guid"] != gtext(priya) {
			t.Fatalf("after recycle: %v", r["state"])
		}
		// Replaying the DELETED later does not bring it back from recycled.
		e.apply(t, ap, t2.Add(time.Hour), del)
		if r := e.row(t, priya); r["state"] != "recycled" {
			t.Errorf("state regressed to %v", r["state"])
		}
		// Neither does a stale LIVE patch.
		e.apply(t, ap, t2.Add(2*time.Hour), live(priya, "", 0, cset("displayName", txt("again"))))
		if r := e.row(t, priya); r["state"] != "recycled" {
			t.Errorf("state regressed to %v", r["state"])
		}
	})
}

// AC4, the other order: a delete that reaches the group's edges before the group's own member list does.
func TestPatchDeleteBeforeMemberAdd(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seed(t, ap)
		a := tombstone(priya, connectorv1.ObjectState_OBJECT_STATE_DELETED)
		b := live(grpAll, "", 0, cadd("member", member(priya)), cdel("member", member(30)))
		e.apply(t, ap, t1, a, b)
		want := e.dump(t, false)
		if strings.Contains(want, gtext(grpAll)+" member "+gtext(priya)+" active") {
			t.Errorf("an edge to a deleted member is active")
		}
	})
}

// AC5: an unseen object.
func TestPatchUnseenObject(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seed(t, ap)
		ouDN := "OU=Staff," + root

		// (a) a creation set creates it.
		rep := e.apply(t, ap, t1, newUser(50, "newbie", ouDN, staff, 3000, 513))
		if rep.Created != 1 || len(rep.NeedsRead) != 0 {
			t.Fatalf("(a) %+v", rep)
		}
		if r := e.row(t, 50); r == nil || r["state"] != "live" || r["sam_account_name"] != "newbie" {
			t.Fatalf("(a) row %v", r)
		}

		// (b) only displayName: needs a read, nothing stored.
		rep = e.apply(t, ap, t1, live(51, "", 0, cset("displayName", txt("who"))))
		if rep.Created != 0 || rep.Updated != 0 || !slices.Equal(rep.NeedsRead, []inventory.GUID{inventory.GUID(gtext(51))}) {
			t.Fatalf("(b) %+v", rep)
		}
		if e.row(t, 51) != nil {
			t.Fatalf("(b) a half object was stored")
		}

		// (c) a class, a DN and a name, but no SID, creation time or account name: still not enough.
		rep = e.apply(t, ap, t1, live(52, "CN=half,"+ouDN, staff, classes("top", "person", "organizationalPerson", "user"), cset("displayName", txt("half"))))
		if !slices.Equal(rep.NeedsRead, []inventory.GUID{inventory.GUID(gtext(52))}) || rep.Created != 0 {
			t.Fatalf("(c) %+v", rep)
		}
		if e.row(t, 52) != nil {
			t.Fatalf("(c) a half object was stored")
		}

		// (d) an unseen tombstone is stored as deleted.
		rep = e.apply(t, ap, t1, tombstone(53, connectorv1.ObjectState_OBJECT_STATE_DELETED))
		if len(rep.NeedsRead) != 0 {
			t.Fatalf("(d) %+v", rep)
		}
		if r := e.row(t, 53); r == nil || r["state"] != "deleted" {
			t.Fatalf("(d) row %v", r)
		}
	})
}

// A group's member list for an unseen object, and an unseen member, store edges but no object.
func TestPatchMemberOfUnseenObjectIsNotStored(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seed(t, ap)
		rep := e.apply(t, ap, t1, live(60, "", 0, cadd("member", member(priya))))
		if !slices.Equal(rep.NeedsRead, []inventory.GUID{inventory.GUID(gtext(60))}) {
			t.Fatalf("%+v", rep)
		}
		if e.row(t, 60) != nil || len(e.edges(t, 60, "member")) != 0 {
			t.Fatalf("something was stored for an unseen group")
		}
	})
}

// The primary-group edge exists whichever of the user and its group arrives first.
func TestPatchPrimaryGroupEitherOrder(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		ouDN := "OU=Staff," + root
		e.apply(t, ap, t0, newHead(), newOU(staff, "Staff", root, hGUID))
		// Two separate batches in each order, so the arrival order is what differs.
		e.apply(t, ap, t0, newUser(70, "pg1", ouDN, staff, 4000, 5000))
		e.apply(t, ap, t0, newGroup(71, "pgroup1", ouDN, staff, 5000))
		e.apply(t, ap, t0, newGroup(73, "pgroup2", ouDN, staff, 5001))
		e.apply(t, ap, t0, newUser(72, "pg2", ouDN, staff, 4001, 5001))
		if got := e.edges(t, 71, "primary_group"); !slices.Equal(got, texts_(70)) {
			t.Errorf("user first: primary group edge = %v", got)
		}
		if got := e.edges(t, 73, "primary_group"); !slices.Equal(got, texts_(72)) {
			t.Errorf("group first: primary group edge = %v", got)
		}
		gs, err := inventory.NewGroups(e.db).GroupsOf(context.Background(), e.a, e.conn, inventory.GUID(gtext(70)))
		if err != nil || !slices.Contains(gs, inventory.GUID(gtext(71))) {
			t.Errorf("GroupsOf = %v, %v", gs, err)
		}
	})
}

var errRollback = errors.New("rollback")

// cycle is the eight changes of one feed cycle of the permutation test: nested new OUs whose children may come
// first, a group over users that do not exist yet, a primary group, a display name change, a delete of a group
// member, and a member delta that names a group the same cycle creates.
func cycle() []*connectorv1.ObjectChange {
	sales := "OU=Sales," + root
	team := "OU=Team," + sales
	deep := "OU=Deep," + team
	return []*connectorv1.ObjectChange{
		newOU(3, "Sales", root, hGUID),
		newOU(4, "Team", sales, 3),
		newOU(5, "Deep", team, 4),
		newUser(11, "deepuser", deep, 5, 2011, rid),
		newGroup(80, "NewGroup", team, 4, 2080, cset("member", member(priya), member(11))),
		live(priya, "", 0, cset("displayName", txt("Priya R."))),
		tombstone(13, connectorv1.ObjectState_OBJECT_STATE_DELETED),
		live(grpExtr, "", 0, cadd("member", member(11), member(80)), cdel("member", member(priya))),
	}
}

// seedCycle is the inventory the cycle's changes land on.
func (e *env) seedCycle(t *testing.T, ap *dsync.Applier) {
	t.Helper()
	ouDN := "OU=Staff," + root
	e.apply(t, ap, t0, newHead(), newOU(staff, "Staff", root, hGUID),
		newGroup(grpAll, "Everyone", ouDN, staff, rid, cset("member", member(priya), member(13))),
		newGroup(grpExtr, "Extra", ouDN, staff, rid+1, cset("member", member(priya))),
		newUser(priya, "Raman\\, Priya", ouDN, staff, 1105, rid, cset("displayName", txt("Raman, Priya"))),
		newUser(13, "gone", ouDN, staff, 1113, rid))
}

// applyRolledBack applies the batches (each in one call) in a transaction, dumps the result and rolls back.
func (e *env) applyRolledBack(t *testing.T, ap *dsync.Applier, asOf time.Time, batches ...[]*connectorv1.ObjectChange) string {
	t.Helper()
	var out string
	err := e.tx(e.a, func(ctx context.Context, tx store.Tx) error {
		for _, b := range batches {
			if _, err := ap.Apply(ctx, tx, &connectorv1.ChangeBatch{Changes: b}, e.opts(asOf)); err != nil {
				return err
			}
		}
		lines, err := dumpTx(ctx, tx, string(e.conn), true)
		if err != nil {
			return err
		}
		out = strings.Join(lines, "\n")
		return errRollback
	})
	if !errors.Is(err, errRollback) {
		t.Fatalf("apply: %v", err)
	}
	return out
}

func permute(cs []*connectorv1.ObjectChange, order []int) []*connectorv1.ObjectChange {
	out := make([]*connectorv1.ObjectChange, len(order))
	for i, j := range order {
		out[i] = cs[j]
	}
	return out
}

// perms yields every permutation of 0..n-1 (Heap's algorithm).
func perms(n int, yield func([]int)) {
	a := make([]int, n)
	for i := range a {
		a[i] = i
	}
	var rec func(k int)
	rec = func(k int) {
		if k == 1 {
			yield(slices.Clone(a))
			return
		}
		for i := 0; i < k; i++ {
			rec(k - 1)
			if k%2 == 0 {
				a[i], a[k-1] = a[k-1], a[i]
			} else {
				a[0], a[k-1] = a[k-1], a[0]
			}
		}
	}
	rec(n)
}

// AC3 (CC-FEED-16): the final inventory is the same for every order of the cycle's changes.
//
// 8! = 40,320 applies of ~60-120 ms each is over an hour per Postgres version, so the coverage is: every
// permutation of the six changes that depend on one another (the three nested OUs, the user under the deepest,
// the group over users that may not exist yet, and the member delta that names that group), with the other two
// changes (the display name and the delete) at the head on half of them and at the tail on the other half, which
// is 720 orders; plus 80 seeded-random orders of all eight; plus the reversed order; plus orders that spread the changes over
// several batches and over one change per batch.
func TestPatchEveryOrderOfACycleGivesTheSameInventory(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seedCycle(t, ap)
		cs := cycle()
		want := e.applyRolledBack(t, ap, t1, cs)
		if strings.Count(want, "obj ") < 11 {
			t.Fatalf("the cycle did not create its objects:\n%s", want)
		}
		// What the cycle must have done at all (so "all orders equal" is not "all orders empty").
		for _, must := range []string{
			gtext(80) + " " + gtext(priya) + " direct", // the new group's closure
			gtext(grpExtr) + " " + gtext(80) + " direct",
			gtext(grpExtr) + " " + gtext(11) + " direct",
			`"display_name": "Priya R."`,
		} {
			if !strings.Contains(want, must) {
				t.Fatalf("expected %q in the result:\n%s", must, want)
			}
		}
		// the deepest user's chain is complete in every order
		if !strings.Contains(want, `"ancestry_complete": true`) {
			t.Fatalf("no complete chain:\n%s", want)
		}

		checked := 0
		check := func(order []int, batches ...[]*connectorv1.ObjectChange) {
			t.Helper()
			checked++
			if got := e.applyRolledBack(t, ap, t1, batches...); got != want {
				t.Fatalf("order %v (batches %d) differs:\n%s", order, len(batches), diffLines(want, got))
			}
		}
		// exhaustive over the dependent six; ids 0-4 and 7 are the OUs, the user, the group and the delta, 5 and 6 the loose two.
		dependent := []int{0, 1, 2, 3, 4, 7}
		n := 0
		perms(len(dependent), func(p []int) {
			order := make([]int, 0, 8)
			for _, i := range p {
				order = append(order, dependent[i])
			}
			// the loose two lead on even orders and trail on odd ones
			if n++; n%2 == 0 {
				order = append([]int{5, 6}, order...)
			} else {
				order = append(order, 6, 5)
			}
			check(order, permute(cs, order))
		})
		rng := newRand(20261102)
		for i := 0; i < 80; i++ {
			order := rng.Perm(8)
			check(order, permute(cs, order))
		}
		rev := []int{7, 6, 5, 4, 3, 2, 1, 0}
		check(rev, permute(cs, rev))
		// the same changes over several batches and one per batch
		for i := 0; i < 12; i++ {
			order := rng.Perm(8)
			p := permute(cs, order)
			check(order, p[:3], p[3:6], p[6:])
			var singles [][]*connectorv1.ObjectChange
			for _, c := range p {
				singles = append(singles, []*connectorv1.ObjectChange{c})
			}
			check(order, singles...)
		}
		t.Logf("%d orders checked, all equal", checked)
	})
}

// AC3: replaying the cycle changes nothing.
func TestPatchReplayingTheCycleChangesNothing(t *testing.T) {
	each(t, func(t *testing.T, e *env) {
		ap := applier(t)
		e.seedCycle(t, ap)
		e.apply(t, ap, t1, cycle()...)
		once := e.dump(t, true)
		onceNoStamp := e.dump(t, false)

		e.apply(t, ap, t1, cycle()...)
		if got := e.dump(t, true); got != once {
			t.Errorf("a replay at the same as-of changed the inventory:\n%s", diffLines(once, got))
		}
		rep := e.apply(t, ap, t2, permute(cycle(), []int{7, 6, 5, 4, 3, 2, 1, 0})...)
		if rep.Created != 0 || len(rep.NeedsRead) != 0 || rep.Refused != 0 {
			t.Errorf("replay report: %+v", rep)
		}
		if got := e.dump(t, false); got != onceNoStamp {
			t.Errorf("a replay at a later as-of changed more than observed_at:\n%s", diffLines(onceNoStamp, got))
		}
		// An older replay is ignored too.
		e.apply(t, ap, t0.Add(30*time.Minute), cycle()...)
		if got := e.dump(t, false); got != onceNoStamp {
			t.Errorf("an older replay changed the inventory:\n%s", diffLines(onceNoStamp, got))
		}
	})
}

func diffLines(a, b string) string {
	as, bs := strings.Split(a, "\n"), strings.Split(b, "\n")
	var out []string
	for _, l := range as {
		if !slices.Contains(bs, l) {
			out = append(out, "- "+l)
		}
	}
	for _, l := range bs {
		if !slices.Contains(as, l) {
			out = append(out, "+ "+l)
		}
	}
	return strings.Join(out, "\n")
}

func newRand(seed int64) *rand.Rand { return rand.New(rand.NewSource(seed)) }
