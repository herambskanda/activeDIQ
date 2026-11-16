package inventory_test

// Library batch 5: Recently Modified and Recently Deleted for users, groups, computers, contacts and OUs
// (T-1110, reports-2-second-slice §4.1). The seed is changeWorld: one change per object kind at t1, a quiet
// user that never changes, and a group that leaves the directory. The expected sets are written from that
// seed (the ground truth: which object changed how), not from the SQL. The live-Samba LDAP comparison needs
// the lab; this oracle holds the same expectation.

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func Test_reports_library_batch5_changes_equal_seed_truth(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		e := setup(t, srv)
		l, err := library.Load(library.Shipped(), library.Options{Datasets: inventory.Datasets(), Registry: e.registry(t)})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		truth, t1 := changeWorld(t, e, e.adA)
		kindOf := map[string]string{"usr-06": "user", "grp-05": "group", "cmp-03": "computer", "ctc-02": "contact", "ou-02": "ou"}
		// the expected GUIDs: Modified = every non-deleted change of the kind, Deleted = the deleted ones
		want := func(id, preset string) []string {
			var out []string
			for g, tr := range truth {
				if tr.kind != kindOf[id] || (tr.change == "deleted") != (preset == "deleted") {
					continue
				}
				out = append(out, g)
			}
			slices.Sort(out)
			return out
		}
		for id := range kindOf {
			for _, preset := range []string{"modified", "deleted"} {
				// inside the period: exactly the seeded rows. Outside it (changes 10 days old, period 7): none.
				for _, c := range []struct {
					name string
					now  time.Time
					days int64
					all  bool
				}{{"30 days", t1.Add(10 * 24 * time.Hour), 30, true}, {"7 days", t1.Add(10 * 24 * time.Hour), 7, false}} {
					rows, err := e.runB2(t, l, id, preset, report.RunParams{Columns: []report.ColumnID{"object_guid", "basis"}, Params: map[string]report.ParamValue{"days": report.DaysP(c.days)}}, e.scopeNC(e.adA), c.now)
					if err != nil {
						t.Fatalf("%s/%s: %v", id, preset, err)
					}
					var got []string
					for _, r := range rows {
						got = append(got, strings.ToLower(r.s("object_guid")))
						if r.s("basis") != "observed" {
							t.Errorf("%s/%s %s: basis %q, want observed", id, preset, c.name, r.s("basis"))
						}
					}
					slices.Sort(got)
					w := want(id, preset)
					if !c.all {
						w = nil
					}
					if !slices.Equal(got, w) {
						t.Errorf("%s/%s over %s: rows %v, want %v", id, preset, c.name, got, w)
					}
				}
			}
		}
	})
}
