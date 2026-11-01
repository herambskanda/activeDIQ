package reports_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// staleFresh answers the watermarks of conn1 in three naming contexts, each stale for a different cause,
// and names the connection (or not, to model a record that predates names).
type staleFresh struct{ names map[string]string }

var ncA, ncB, ncC = oid(0x11), oid(0x12), oid(0x13)

func (f staleFresh) Freshness(_ context.Context, _ tenant.ID, cs []authz.ObjectID, now time.Time) (run.FreshnessRead, error) {
	var ws []report.NCWatermark
	for _, c := range cs {
		ws = append(ws,
			report.NCWatermark{Connection: c, NC: ncA, LastPassAt: now.Add(-3 * time.Hour), State: report.NCResyncRequired},
			report.NCWatermark{Connection: c, NC: ncB, LastPassAt: now.Add(-90 * time.Minute), State: report.NCPaused},
			report.NCWatermark{Connection: c, NC: ncC, LastPassAt: now.Add(-2 * time.Hour), State: report.NCOK},
		)
	}
	return run.FreshnessRead{Label: report.Label(ws, time.Hour, now), Threshold: time.Hour, Names: f.names}, nil
}

func (e *apiEnv) runAndGet(body string) map[string]any {
	e.t.Helper()
	code, created := e.do(alice, "POST", "/api/v1/reports/runs", body)
	if code != 202 {
		e.t.Fatalf("create: %d %v", code, created)
	}
	e.work()
	code, got := e.do(alice, "GET", "/api/v1/reports/runs/"+created["id"].(string), "")
	if code != 200 || got["state"] != "succeeded" {
		e.t.Fatalf("get: %d %v", code, got)
	}
	return got
}

// T-1074 AC-1: a stale run names the cause and the connections behind it, oldest first, and the same
// freshness is on the history list; a synced run carries an empty list and its threshold.
func TestStaleFreshnessNamesCauseAndConnections(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := apiSetup(t, s)

		synced := e.runAndGet(`{"definitionId":"tst-01","parameters":{"columns":["name"]}}`)
		fr := synced["freshness"].(map[string]any)
		if fr["state"] != "synced" || !reflect.DeepEqual(fr["stale"], []any{}) || fr["thresholdSeconds"] != float64(3600) {
			t.Fatalf("synced freshness = %v", fr)
		}

		e.svc.Fresh = staleFresh{names: map[string]string{report.GUIDString(conn1): "emea.corp.example"}}
		got := e.runAndGet(`{"definitionId":"tst-01","parameters":{"columns":["name","logon_name"]}}`)
		fr = got["freshness"].(map[string]any)
		if fr["state"] != "stale" || fr["thresholdSeconds"] != float64(3600) {
			t.Fatalf("freshness = %v", fr)
		}
		stale := fr["stale"].([]any)
		type want struct {
			nc    authz.ObjectID
			cause string
			age   float64
		}
		for i, w := range []want{{ncA, "resync_required", 3 * 3600}, {ncC, "older_than_threshold", 2 * 3600}, {ncB, "paused", 90 * 60}} {
			g := stale[i].(map[string]any)
			if g["connectionId"] != report.GUIDString(conn1) || g["connectionName"] != "emea.corp.example" || g["namingContextId"] != report.GUIDString(w.nc) ||
				g["cause"] != w.cause || g["ageSeconds"] != w.age {
				t.Errorf("stale[%d] = %v, want nc %s cause %s age %v", i, g, report.GUIDString(w.nc), w.cause, w.age)
			}
			// lastPassAt is the pass time: the age before the moment the run was judged.
			last, err := time.Parse(time.RFC3339, g["lastPassAt"].(string))
			if err != nil || time.Since(last) < time.Duration(w.age)*time.Second {
				t.Errorf("stale[%d].lastPassAt = %v", i, g["lastPassAt"])
			}
		}
		if len(stale) != 3 {
			t.Errorf("%d stale sources, want 3", len(stale))
		}

		// The history list carries the same freshness for the same run.
		_, list := e.do(alice, "GET", "/api/v1/reports/runs", "")
		var found bool
		for _, it := range list["items"].([]any) {
			if it.(map[string]any)["id"] == got["id"] {
				found = true
				if !reflect.DeepEqual(it.(map[string]any)["freshness"], fr) {
					t.Errorf("list freshness %v differs from run %v", it.(map[string]any)["freshness"], fr)
				}
			}
		}
		if !found {
			t.Error("the run is not in the history list")
		}

		// A connection with no known name is named by its id, never left blank.
		e.svc.Fresh = staleFresh{}
		got = e.runAndGet(`{"definitionId":"tst-01","parameters":{"columns":["logon_name"]}}`)
		if n := got["freshness"].(map[string]any)["stale"].([]any)[0].(map[string]any)["connectionName"]; n != report.GUIDString(conn1) {
			t.Errorf("unnamed connection shown as %v", n)
		}
	})
}

// T-1074 AC-1: a run that hid probable service accounts returns their count; a group the report cannot
// show is marked locked; a run that hid nothing returns an empty list. (Showing a group needs showHidden
// in the request schema, which the contract does not carry yet.)
func TestRunReturnsHiddenGroupCounts(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := apiSetup(t, s)
		lib := e.svc.Catalog.(library)
		lib.d.Def.Presets = append(lib.d.Def.Presets, report.Preset{ID: "hides", Hidden: []report.HiddenGroup{
			{ID: "service_accounts", Label: "Probable service accounts", Where: report.Cmp{Column: "name", Op: report.OpContains, Value: report.TextV("a")}},
			{ID: "tier0", Label: "Tier 0 accounts", Locked: true, Where: report.Cmp{Column: "name", Op: report.OpEq, Value: report.TextV("bob")}},
		}})
		e.svc.Catalog = lib

		none := e.runAndGet(`{"definitionId":"tst-01","parameters":{"columns":["name"]}}`)
		if !reflect.DeepEqual(none["hiddenGroups"], []any{}) {
			t.Errorf("a run that hid nothing: hiddenGroups = %v", none["hiddenGroups"])
		}

		// conn1 holds ann, cat, bob: ann and cat are probable service accounts, bob is locked away.
		got := e.runAndGet(`{"definitionId":"tst-01","presetId":"hides","parameters":{"columns":["name"]}}`)
		want := []any{
			map[string]any{"id": "service_accounts", "label": "Probable service accounts", "count": float64(2), "locked": false},
			map[string]any{"id": "tier0", "label": "Tier 0 accounts", "count": float64(1), "locked": true},
		}
		if !reflect.DeepEqual(got["hiddenGroups"], want) {
			t.Errorf("hiddenGroups = %v, want %v", got["hiddenGroups"], want)
		}
		// The count reconciles: hidden rows plus stored rows are the objects checked.
		if got["rowCount"] != float64(0) || got["objectsChecked"] != float64(3) {
			t.Errorf("rowCount %v objectsChecked %v, want 0 and 3", got["rowCount"], got["objectsChecked"])
		}
	})
}
