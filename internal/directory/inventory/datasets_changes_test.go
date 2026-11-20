package inventory_test

import (
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

var changeCols = []report.ColumnID{"change_id", "object_guid", "object_kind", "change_kind", "name", "sam_account_name", "dn",
	"attributes_changed", "automatic_only", "observed_at", "basis", "domain", "connection_id"}

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

// AC1 and AC4: each change appears once with its kind and the observed time; a kind filter returns only its rows.
func Test_object_changes_ground_truth_and_kind_filter(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		want, t1 := changeWorld(t, e, c)
		now := t1.Add(24 * time.Hour)
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetObjectChanges, cols: changeCols, scope: e.scopeNC(c), now: now,
			where: report.Cmp{Column: "observed_at", Op: report.OpWithinLastDays, Value: report.IntV(30)}})
		if len(res.rows) != len(want) || res.count != int64(len(want)) {
			t.Fatalf("rows = %d, count = %d, want %d each (one change per object, none for the quiet user)", len(res.rows), res.count, len(want))
		}
		seen := map[string]bool{}
		for _, r := range res.rows {
			g := strings.ToLower(cellStr(r, "object_guid"))
			w, ok := want[g]
			if !ok {
				t.Fatalf("unexpected change for %s", g)
			}
			if seen[g] {
				t.Errorf("%s appears twice", g)
			}
			seen[g] = true
			if got := cellStr(r, "object_kind"); got != w.kind {
				t.Errorf("%s kind = %s, want %s", g, got, w.kind)
			}
			if got := cellStr(r, "change_kind"); got != w.change {
				t.Errorf("%s change = %s, want %s", g, got, w.change)
			}
			if got := cellKey(r["observed_at"]); !strings.Contains(got, t1.UTC().Format("2006-01-02T15:04:05")) && got != cellKey(report.TimeCell(t1)) {
				t.Errorf("%s observed_at = %s, want the observation time %s", g, got, t1)
			}
			if got := cellStr(r, "basis"); got != "observed" {
				t.Errorf("%s basis = %s, want observed", g, got)
			}
		}
		// the edit names the attribute, never a value
		for _, r := range res.rows {
			if cellStr(r, "change_kind") == "edited" && cellStr(r, "object_kind") == "user" {
				if got := cellStr(r, "attributes_changed"); !strings.Contains(got, "description") || strings.Contains(got, "v1") || strings.Contains(got, "v2") {
					t.Errorf("attributes_changed = %q, want the name description and no value", got)
				}
			}
		}
		// AC4: by kind, each kind returns only its own rows
		for kind, n := range map[string]int{"user": 1, "group": 1, "computer": 1, "contact": 1, "ou": 1, "inetorgperson": 0} {
			r := e.run(t, reg, hQuery{dataset: inventory.DatasetObjectChanges, cols: changeCols, scope: e.scopeNC(c), now: now,
				where: report.Cmp{Column: "object_kind", Op: report.OpEq, Value: report.EnumV(kind)}})
			if len(r.rows) != n {
				t.Errorf("kind %s: %d rows, want %d", kind, len(r.rows), n)
			}
			for _, row := range r.rows {
				if got := cellStr(row, "object_kind"); got != kind {
					t.Errorf("kind filter %s returned a %s row", kind, got)
				}
			}
		}
		// a later pass with nothing changed adds no rows
		if _, err := e.populate(t, c, t1.Add(time.Hour), hUser{guid: hGUID(1, 2), sam: "quiet", rid: 1102, uac: i64(uacNormal), read: 15}.obs()); err != nil {
			t.Fatal(err)
		}
	})
}

// AC2: the registry labels the time column "Observed at", never "Changed at", and the basis only "observed".
func Test_object_changes_registry_labels_observed(t *testing.T) {
	var ds report.Dataset
	for _, d := range inventory.Datasets() {
		if d.ID == inventory.DatasetObjectChanges {
			ds = d
		}
	}
	if ds.ID == "" {
		t.Fatal("inventory.object_changes is not registered")
	}
	byID := map[report.ColumnID]report.Column{}
	for _, c := range ds.Columns {
		byID[c.ID] = c
		if strings.Contains(strings.ToLower(c.Label), "changed at") || strings.Contains(strings.ToLower(c.Label), "deleted at") {
			t.Errorf("column %s is labelled %q: the dataset has observation time only", c.ID, c.Label)
		}
	}
	if byID["observed_at"].Label != "Observed at" || byID["observed_at"].Type != report.TypeTime {
		t.Errorf("observed_at = %+v, want a time column labelled Observed at", byID["observed_at"])
	}
	if b := byID["basis"]; len(b.Enum) != 1 || b.Enum[0].ID != "observed" {
		t.Errorf("basis enum = %+v, want exactly observed", b.Enum)
	}
	for _, id := range []report.ColumnID{"actor", "changed_at", "changed_by", "origin_at"} {
		if _, ok := byID[id]; ok {
			t.Errorf("column %s must not exist (DM-18.I3: no actor, no invented DC time)", id)
		}
	}
}

// AC3: RP11 world for the dataset, called from Test_dataset_reveals_nothing_outside_scope.
func rpObjectChanges(t *testing.T, e *env, reg *reportsql.Registry, c inventory.ConnectionID, cols []report.ColumnID, now, at time.Time) {
	baseU, sentU, sentDel, baseDel := hGUID(1, 1), sentinelGUID(1), sentinelGUID(2), hGUID(1, 2)
	mk := func(guid, sam string, rid uint32, desc string, st inventory.ObjectState) inventory.Observation {
		o := named(hUser{guid: guid, sam: sam, rid: rid, uac: i64(uacNormal), read: 15}.obs(), sam)
		o.Attributes = map[string]any{"description": desc}
		o.State = st
		return o
	}
	live := inventory.ObjLive
	if _, err := e.populate(t, c, at.Add(-3*time.Hour), mk(baseU, "base-user", 1101, "a", live), mk(sentU, sentinel+"-user", 1201, "a", live),
		mk(sentDel, sentinel+"-gone", 1202, "a", live), mk(baseDel, "base-gone", 1103, "a", live)); err != nil {
		t.Fatal(err)
	}
	if err := e.pass(t, c, hDom, at.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.populate(t, c, at, mk(baseU, "base-user", 1101, "b", live), mk(sentU, sentinel+"-user", 1201, "b", live),
		mk(sentDel, sentinel+"-gone", 1202, "a", inventory.ObjDeleted), mk(baseDel, "base-gone", 1103, "a", inventory.ObjDeleted)); err != nil {
		t.Fatal(err)
	}
	// in scope: base-user (edited) and base-gone (deleted) only. The deleted out-of-scope user has a row in the table,
	// and so does the edited sentinel user; neither may show a name, DN, GUID or count.
	scope := scopeOf(c, baseU, baseDel)
	res := e.run(t, reg, hQuery{dataset: inventory.DatasetObjectChanges, cols: cols, scope: scope, now: now})
	if len(res.rows) != 2 || res.count != 2 {
		t.Fatalf("rows = %d, count = %d, want 2 and 2", len(res.rows), res.count)
	}
	own := map[string]string{}
	for k, r := range res.rows {
		switch strings.ToLower(cellStr(r, "object_guid")) {
		case strings.ToLower(baseU):
			own[k] = realDN("base-user")
		case strings.ToLower(baseDel):
			own[k] = realDN("base-gone")
		default:
			t.Fatalf("row for %s is not in scope", cellStr(r, "object_guid"))
		}
	}
	checkNoLeaks(t, res, own)
	// positive control: with the scope widened the out-of-scope rows do exist
	wide := e.run(t, reg, hQuery{dataset: inventory.DatasetObjectChanges, cols: cols, scope: scopeOf(c, baseU, baseDel, sentU, sentDel), now: now})
	if len(wide.rows) != 4 {
		t.Fatalf("widened scope rows = %d, want 4", len(wide.rows))
	}
}
