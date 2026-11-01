package reports_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// historyStub is a test double for the two T-0891 operations. It records what reached the handler and
// answers a fixed page; the real handlers belong to the reports module (modules/reports.md 12, row B4).
type historyStub struct {
	api.Handlers
	listed  []api.ListReportRunsInput
	retried []apitypes.UUID
}

func (s *historyStub) ListReportRuns(_ context.Context, in api.ListReportRunsInput) (api.ListReportRunsOutput, error) {
	s.listed = append(s.listed, in)
	at := apitypes.NewTimestamp(time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC))
	done := apitypes.NewTimestamp(time.Date(2026, 10, 30, 9, 1, 0, 0, time.UTC))
	rows := int64(42)
	newer := api.ReportRunSummary{
		ID: mustUUID("0a1b2c3d-0000-4000-8000-000000000002"), DefinitionID: "USR-01", DefinitionVersion: 3,
		State: api.ReportRunStateSucceeded, CreatedAt: done, AsOf: &at, FinishedAt: &done, Freshness: api.ReportFreshness{Label: "Synced", State: api.ReportFreshnessStateSynced},
		RowCount: &rows, ScopeCurrent: true,
	}
	older := api.ReportRunSummary{
		ID: mustUUID("0a1b2c3d-0000-4000-8000-000000000001"), DefinitionID: "USR-01", DefinitionVersion: 3,
		State: api.ReportRunStateExpired, CreatedAt: at, AsOf: &at, Freshness: api.ReportFreshness{Label: "Synced", State: api.ReportFreshnessStateSynced}, ScopeCurrent: false,
	}
	next := "c3VtbWFyeQ"
	return api.ListReportRuns200{Body: api.ReportRunList{Items: []api.ReportRunSummary{newer, older}, Page: apitypes.PageInfo{NextCursor: &next}}}, nil
}

func (s *historyStub) RetryReportRun(_ context.Context, in api.RetryReportRunInput) (api.RetryReportRunOutput, error) {
	s.retried = append(s.retried, in.RunID)
	created := apitypes.NewTimestamp(time.Date(2026, 10, 30, 9, 5, 0, 0, time.UTC))
	rerunOf := in.RunID
	return api.RetryReportRun202{Location: "/api/v1/reports/runs/0a1b2c3d-0000-4000-8000-000000000003", Body: api.ReportRun{
		ID: mustUUID("0a1b2c3d-0000-4000-8000-000000000003"), DefinitionID: "USR-01", DefinitionVersion: 3, State: api.ReportRunStateQueued,
		CreatedBy: apitypes.JobActor{ID: "admin", Type: "user"}, CreatedAt: created, Freshness: api.ReportFreshness{Label: "Not synced yet", State: api.ReportFreshnessStateNotSyncedYet},
		SkippedConnections: []api.ReportSkippedConnection{}, Progress: api.ReportRunProgress{Stage: api.ReportRunStageQueued},
		RerunOf: &rerunOf, Parameters: api.ReportParametersView{Columns: []string{}, ConnectionIds: []apitypes.UUID{}, Filters: []api.ReportFilterView{},
			OUExclude: []api.ReportOuRef{}, OUInclude: []api.ReportOuRef{}, Subjects: []api.ReportSubjectRef{}},
	}}, nil
}

func mustUUID(s string) apitypes.UUID {
	u, err := apitypes.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return apitypes.UUID(u)
}

// serveHistory mounts the stub behind the real router, authn/authz ports and the response conformance harness.
func serveHistory(t *testing.T, s *historyStub, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	perms := apitest.Catalogue(doc)
	var rec apitest.Recorder
	srv, err := apihost.Build(doc, apitest.Conform(&rec, api.Bind(s)), pol, perms, apihost.Ports{Authn: ports{}, Authz: ports{}, Limits: ports{}, StepUp: ports{}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = "203.0.113.7:4444"
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

// T-0891 acceptance 1: listReportRuns pages the caller's runs by cursor, newest first, with state and
// as_of. The example call below runs through the router and the response-conformance harness (A14).
func TestListReportRunsPagesByCursorWithStateAndAsOf(t *testing.T) {
	s := &historyStub{}
	w := serveHistory(t, s, "GET", "/api/v1/reports/runs?limit=2&state=succeeded&definitionId=USR-01&cursor=abc")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if len(s.listed) != 1 {
		t.Fatalf("handler reached %d times", len(s.listed))
	}
	in := s.listed[0]
	if in.State == nil || *in.State != api.ReportRunStateFilterSucceeded || in.DefinitionID == nil || *in.DefinitionID != "USR-01" || in.Limit == nil || *in.Limit != 2 || in.Cursor == nil {
		t.Errorf("query not decoded as typed values: %+v", in)
	}
	var body struct {
		Items []map[string]any `json:"items"`
		Page  struct {
			NextCursor *string `json:"nextCursor"`
		} `json:"page"`
	}
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) != 2 || body.Page.NextCursor == nil {
		t.Fatalf("want 2 items and a nextCursor: %s", w.Body)
	}
	for i, it := range body.Items {
		for _, k := range []string{"id", "state", "asOf", "createdAt", "scopeCurrent", "rowCount"} {
			if _, ok := it[k]; !ok {
				t.Errorf("item %d lacks %q: %v", i, k, it)
			}
		}
		for _, k := range []string{"digest", "scopeApplied", "parameters", "createdBy"} {
			if _, ok := it[k]; ok {
				t.Errorf("item %d carries %q, which the history list must not", i, k)
			}
		}
	}
	if body.Items[0]["createdAt"].(string) < body.Items[1]["createdAt"].(string) {
		t.Errorf("the example page is not newest first: %v", body.Items)
	}
	if body.Items[1]["scopeCurrent"] != false || body.Items[1]["rowCount"] != nil {
		t.Errorf("a run whose scope is no longer current must show no row count: %v", body.Items[1])
	}
	t.Logf("GET /api/v1/reports/runs?limit=2&state=succeeded&definitionId=USR-01 -> %d\n%s", w.Code, w.Body)
}

// The list takes typed values only. A bad value is a 400 problem+json and the handler never runs. There is
// no parameter that selects another account's runs: the contract lists exactly four, and the generated input
// has no field a client could use to name a runner, so a stray ?owner=any is never decoded.
func TestListReportRunsRefusesRawFiltersAndOtherRunners(t *testing.T) {
	bad := map[string]string{
		"state outside the enum":  "?state=running%3Bdrop",
		"definition id with sql":  "?definitionId=USR-01%3B%20DROP%20TABLE%20runs",
		"definition id as ldap":   "?definitionId=(objectClass%3D*)",
		"limit zero":              "?limit=0",
		"limit over the page cap": "?limit=1001",
	}
	for name, q := range bad {
		s := &historyStub{}
		w := serveHistory(t, s, "GET", "/api/v1/reports/runs"+q)
		if w.Code != 400 {
			t.Errorf("%s: status %d, want 400 (%s)", name, w.Code, w.Body)
		}
		if len(s.listed) != 0 {
			t.Errorf("%s: reached the handler", name)
		}
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "problem+json") {
			t.Errorf("%s: content type %q", name, ct)
		}
	}
	params := map[string]bool{}
	registry := at(t, bundle(t), "components", "parameters")
	for _, p := range reportOperations(t)["listReportRuns"]["parameters"].([]any) {
		ref := p.(map[string]any)["$ref"].(string)
		params[registry[ref[strings.LastIndex(ref, "/")+1:]].(map[string]any)["name"].(string)] = true
	}
	if len(params) != 4 || !params["state"] || !params["definitionId"] || !params["cursor"] || !params["limit"] {
		t.Errorf("listReportRuns parameters are %v, want exactly state, definitionId, cursor, limit", params)
	}
	in := reflect.TypeOf(api.ListReportRunsInput{})
	for i := 0; i < in.NumField(); i++ {
		switch in.Field(i).Name {
		case "State", "DefinitionID", "Cursor", "Limit":
		default:
			t.Errorf("ListReportRunsInput has field %s, which could select runs", in.Field(i).Name)
		}
	}
	s := &historyStub{}
	if w := serveHistory(t, s, "GET", "/api/v1/reports/runs?owner=any&runner=x"); w.Code != 200 || len(s.listed) != 1 {
		t.Errorf("stray selectors: status %d, handler calls %d", w.Code, len(s.listed))
	}
}

// retryReportRun takes the run in the path and no body; a path that is not a uuid never reaches the handler.
func TestRetryReportRunTakesOnlyARunID(t *testing.T) {
	s := &historyStub{}
	w := serveHistory(t, s, "POST", "/api/v1/reports/runs/0a1b2c3d-0000-4000-8000-000000000001/retry")
	if w.Code != 202 || len(s.retried) != 1 {
		t.Fatalf("status %d, handler calls %d: %s", w.Code, len(s.retried), w.Body)
	}
	if loc := w.Header().Get("Location"); loc == "" {
		t.Error("retry answers no Location")
	}
	for _, id := range []string{"not-a-uuid", "0a1b2c3d-0000-4000-8000-000000000001%3BDROP"} {
		s := &historyStub{}
		w := serveHistory(t, s, "POST", "/api/v1/reports/runs/"+id+"/retry")
		if w.Code != 400 || len(s.retried) != 0 {
			t.Errorf("%q: status %d, handler calls %d", id, w.Code, len(s.retried))
		}
	}
}

// The operation text carries the rules a handler must implement: own runs only, the scope check of the
// list, the states a retry may start from, and the codes a client branches on.
func TestRunHistoryRulesAreStatedInTheContract(t *testing.T) {
	ops := reportOperations(t)
	list, retry := ops["listReportRuns"], ops["retryReportRun"]
	if list == nil || retry == nil {
		t.Fatal("listReportRuns or retryReportRun missing")
	}
	for _, op := range []string{"listReportRuns", "retryReportRun"} {
		if p := ops[op]["x-permission"]; p != "reports.run" {
			t.Errorf("%s binds %v", op, p)
		}
	}
	for want, text := range map[string]string{
		"newest first": opDesc(list), "reports.schedule.manage_all never lists": opDesc(list), "scopeCurrent": opDesc(list), "scope_changed_rerun": opDesc(list),
		"run_in_progress": opDesc(retry), "too_many_report_jobs": opDesc(retry), "rerunOf": opDesc(retry), "current read scope": opDesc(retry), "not an Action": opDesc(retry),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("operation text lacks %q", want)
		}
	}
	for _, st := range []string{"400", "401", "403", "429"} {
		if _, ok := at(t, list, "responses")[st]; !ok {
			t.Errorf("listReportRuns declares no %s", st)
		}
	}
	for _, st := range []string{"202", "404", "409", "429"} {
		if _, ok := at(t, retry, "responses")[st]; !ok {
			t.Errorf("retryReportRun declares no %s", st)
		}
	}
	if _, ok := at(t, list, "responses")["404"]; ok {
		t.Error("listReportRuns declares 404; a list of the caller's own runs has nothing to not find")
	}
}

func opDesc(op map[string]any) string { s, _ := op["description"].(string); return s }

func reportOperations(t *testing.T) map[string]map[string]any {
	t.Helper()
	d := bundle(t)
	ops := map[string]map[string]any{}
	for path, item := range at(t, d, "paths") {
		if !strings.HasPrefix(path, "/reports/") {
			continue
		}
		for _, o := range item.(map[string]any) {
			if op, ok := o.(map[string]any); ok {
				if id, ok := op["operationId"].(string); ok {
					ops[id] = op
				}
			}
		}
	}
	return ops
}
