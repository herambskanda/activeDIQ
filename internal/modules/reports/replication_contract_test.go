package reports_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/modules/reports"
	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// T-1720: the SYS-03 DC Replication Status contract (reports-2 second slice 7.3 and 13) and the USR-12 manager picker.
// The static half reads the bundle; the example half runs a stub through the real router and the response-conformance
// harness (A14), so a body the contract does not allow fails here.

func strs(v any) []string {
	var out []string
	for _, x := range anyList(v) {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func props(t *testing.T, schemas map[string]any, name string) (map[string]any, []string) {
	t.Helper()
	sc, ok := schemas[name].(map[string]any)
	if !ok {
		t.Fatalf("bundle has no schema %s", name)
	}
	p, _ := sc["properties"].(map[string]any)
	return p, strs(sc["required"])
}

// Acceptance 1: the contract carries the SYS-03 columns, the coverage block and the status counts, and unreachable is not healthy.
func TestSys03ContractCarriesColumnsCoverageAndStatusCounts(t *testing.T) {
	d := bundle(t)
	schemas := at(t, d, "components", "schemas")

	col, _ := schemas["ReportColumnId"].(map[string]any)
	cols := strs(col["enum"])
	for _, id := range []string{"domain_controller", "domain", "partition", "partner_dc", "last_attempt", "last_success", "consecutive_failures", "last_error_code", "last_error", "status", "lingering_risk", "read_at"} {
		if !slices.Contains(cols, id) {
			t.Errorf("ReportColumnId lacks the SYS-03 column %q", id)
		}
	}
	if strings.Contains(strings.ToLower(jsonString(t, schemas["ReportLingeringRiskValue"])), "detected\"]") {
		t.Errorf("the lingering risk values must not say detected")
	}

	// An open Status enum with not_reported, and no way to spell "unreachable" as a status.
	st, _ := schemas["ReportReplicationStatusValue"].(map[string]any)
	if st["x-activediq-enum"] != "open" {
		t.Errorf("ReportReplicationStatusValue is not an open enum: %v", st["x-activediq-enum"])
	}
	got := strs(st["enum"])
	for _, want := range []string{"healthy", "warning", "failing", "not_reported"} {
		if !slices.Contains(got, want) {
			t.Errorf("status enum lacks %q: %v", want, got)
		}
	}
	if slices.Contains(got, "unreachable") {
		t.Errorf("unreachable must not be a status; an unreachable DC is not_reported with a reason: %v", got)
	}

	// Coverage block: answered, total, unanswered DCs with the error, and the not-read-by-cap count.
	cp, creq := props(t, schemas, "ReportDcCoverage")
	for _, k := range []string{"dcsInScope", "dcsAnswered", "complete", "unanswered", "notReadByCap", "readCap"} {
		if cp[k] == nil {
			t.Errorf("ReportDcCoverage lacks %q", k)
		}
	}
	for _, k := range []string{"unanswered", "notReadByCap", "readCap"} {
		if slices.Contains(creq, k) {
			t.Errorf("%q is required on ReportDcCoverage, which would break the existing per-DC reports (additive only)", k)
		}
	}
	_, ureq := props(t, schemas, "ReportDcUnanswered")
	for _, k := range []string{"dc", "reason", "error", "rowKey", "readAt"} {
		if !slices.Contains(ureq, k) {
			t.Errorf("ReportDcUnanswered does not require %q", k)
		}
	}
	ep, _ := props(t, schemas, "ReportDcError")
	if len(ep) != 2 || ep["code"] == nil || ep["message"] == nil {
		t.Errorf("ReportDcError must be a stable code and a fixed message only: %v", ep)
	}

	// Status counts and thresholds ride the run header, optional so every other report is unchanged.
	rp, rreq := props(t, schemas, "ReportRun")
	if rp["replication"] == nil || slices.Contains(rreq, "replication") {
		t.Errorf("ReportRun.replication must exist and be optional (present on SYS-03 runs only)")
	}
	_, sreq := props(t, schemas, "ReportReplicationSummary")
	for _, k := range []string{"thresholds", "statusCounts", "tombstoneLifetimeDays", "nextReadAllowedAfter"} {
		if !slices.Contains(sreq, k) {
			t.Errorf("ReportReplicationSummary does not require %q", k)
		}
	}
}

func jsonString(t *testing.T, v any) string {
	t.Helper()
	b, err := jsonv2.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The thresholds are read under reports.replication.read and edited under reports.replication.configure, both distinct from
// reports.run; the edit is an Action with a preview twin and an undo pair; the manager picker is a plain reports.run read.
func TestSys03ThresholdsAndManagerPickerAreBoundToTheirOwnPermissions(t *testing.T) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"getReportReplicationThresholds":                  string(reports.ReplicationReadPermission),
		"updateReportReplicationThresholds":               string(reports.ReplicationConfigurePermission),
		"previewUpdateReportReplicationThresholds":        string(reports.ReplicationConfigurePermission),
		"undoReportReplicationThresholdsOperation":        string(reports.ReplicationConfigurePermission),
		"previewUndoReportReplicationThresholdsOperation": string(reports.ReplicationConfigurePermission),
		"listReportManagers":                              string(reports.RunPermission),
	}
	seen := map[string]bool{}
	for _, op := range doc.Operations() {
		if p, ok := want[op.ID]; ok {
			seen[op.ID] = true
			if op.Permission != p {
				t.Errorf("%s binds %q, want %q", op.ID, op.Permission, p)
			}
			if op.Permission == string(reports.RunPermission) && strings.Contains(op.ID, "Replication") {
				t.Errorf("%s must not be reachable with reports.run alone", op.ID)
			}
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("operation %s is missing", id)
		}
	}
}

// The manager picker accepts literal text only and returns the pick as a ReportSubjectRef-compatible pair, never a DN.
func TestManagerPickerTakesLiteralTextAndReturnsGuidsNotDNs(t *testing.T) {
	d := bundle(t)
	schemas := at(t, d, "components", "schemas")
	mp, mreq := props(t, schemas, "ReportManagerCandidate")
	for _, k := range []string{"connectionId", "guid", "displayName", "logonName", "ouPath", "directReports"} {
		if mp[k] == nil || !slices.Contains(mreq, k) {
			t.Errorf("ReportManagerCandidate lacks required %q", k)
		}
	}
	for k := range mp {
		if k == "dn" || k == "distinguishedName" {
			t.Errorf("ReportManagerCandidate returns %q; objects are addressed by objectGUID", k)
		}
	}
	sp, _ := props(t, schemas, "ReportSubjectRef")
	for _, k := range []string{"connectionId", "guid"} {
		if sp[k] == nil || mp[k] == nil {
			t.Errorf("the picker's %q must match ReportSubjectRef so the pick travels as a subject", k)
		}
	}
	list, _ := at(t, d, "paths", "/reports/managers")["get"].(map[string]any)
	for _, p := range anyList(list["parameters"]) {
		m, _ := p.(map[string]any)
		if m["name"] != "q" {
			continue
		}
		sc, _ := m["schema"].(map[string]any)
		if sc["maxLength"] == nil || sc["pattern"] == nil {
			t.Errorf("q must be bounded and refuse control characters: %v", sc)
		}
	}
}

// sys03Stub answers the SYS-03 run header (5 of 6 DCs read, and a 138-DC run capped at 100), the row page and the
// thresholds. It is a test double: the real handlers belong to T-1743 and T-1744.
type sys03Stub struct{ api.Handlers }

var (
	sys03Run   = mustUUID("0a1b2c3d-0000-4000-8000-0000000003a1")
	sys03Capd  = mustUUID("0a1b2c3d-0000-4000-8000-0000000003a2")
	sys03Conn  = mustUUID("0a1b2c3d-0000-4000-8000-0000000000c1")
	sys03Start = time.Date(2026, 11, 7, 14, 2, 0, 0, time.UTC)
)

func sys03Header(id apitypes.UUID, cov api.ReportDcCoverage, counts []api.ReportReplicationStatusCount, rows int64) api.ReportRun {
	at := apitypes.NewTimestamp(sys03Start)
	next := apitypes.NewTimestamp(sys03Start.Add(time.Hour))
	days := int64(180)
	return api.ReportRun{
		ID: id, DefinitionID: "SYS-03", DefinitionVersion: 1, State: api.ReportRunStateSucceeded,
		CreatedBy: apitypes.JobActor{ID: "admin", Type: "user"}, CreatedAt: at, StartedAt: &at, FinishedAt: &at, AsOf: &at,
		Freshness: api.ReportFreshness{Label: "Read 14:02", State: api.ReportFreshnessStatePerDcRead, Stale: []api.ReportStaleSource{}},
		RowCount:  &rows, SkippedConnections: []api.ReportSkippedConnection{}, HiddenGroups: []api.ReportHiddenGroup{},
		Progress: api.ReportRunProgress{Stage: api.ReportRunStageDone, Percent: 100},
		Coverage: &cov,
		Replication: &api.ReportReplicationSummary{
			Thresholds:            api.ReportReplicationThresholdPair{WarningAfterSeconds: 3600, FailingAfterSeconds: 86400},
			StatusCounts:          counts,
			TombstoneLifetimeDays: &days, NextReadAllowedAfter: &next,
		},
		Parameters: api.ReportParametersView{Columns: []string{}, ConnectionIds: []apitypes.UUID{}, Filters: []api.ReportFilterView{},
			OUExclude: []api.ReportOuRef{}, OUInclude: []api.ReportOuRef{}, Subjects: []api.ReportSubjectRef{}},
	}
}

func counts(failing, warning, healthy, notReported int64) []api.ReportReplicationStatusCount {
	return []api.ReportReplicationStatusCount{
		{Status: api.ReportReplicationStatusValueFailing, Count: failing},
		{Status: api.ReportReplicationStatusValueWarning, Count: warning},
		{Status: api.ReportReplicationStatusValueHealthy, Count: healthy},
		{Status: api.ReportReplicationStatusValueNotReported, Count: notReported},
	}
}

func (sys03Stub) GetReportRun(_ context.Context, in api.GetReportRunInput) (api.GetReportRunOutput, error) {
	if in.RunID == sys03Capd {
		six, answered, capN, left := int64(100), int64(100), int64(38), int64(138)
		return api.GetReportRun200{Body: sys03Header(sys03Capd, api.ReportDcCoverage{
			DcsInScope: left, DcsAnswered: answered, Complete: false, NotReadByCap: &capN, ReadCap: &six, Unanswered: []api.ReportDcUnanswered{},
		}, counts(2, 1, 400, 0), 403)}, nil
	}
	readCap, none := int64(100), int64(0)
	cov := api.ReportDcCoverage{
		DcsInScope: 6, DcsAnswered: 5, Complete: false, NotReadByCap: &none, ReadCap: &readCap,
		Unanswered: []api.ReportDcUnanswered{{
			Dc: "dc-emea2.corp.example", ConnectionID: sys03Conn, Reason: api.ReportDcUnansweredReasonUnreachable,
			Error:  api.ReportDcError{Code: "connection_refused", Message: "The domain controller refused the connection."},
			RowKey: "dc-emea2", ReadAt: apitypes.NewTimestamp(sys03Start),
		}},
	}
	return api.GetReportRun200{Body: sys03Header(sys03Run, cov, counts(1, 1, 14, 1), 17)}, nil
}

func (sys03Stub) ListReportRunRows(_ context.Context, in api.ListReportRunRowsInput) (api.ListReportRunRowsOutput, error) {
	txt := func(s string) api.ReportCell {
		return api.ReportCell{Kind: "text", Text: &api.ReportCellText{Kind: "text", Value: s}}
	}
	num := func(s string) api.ReportCell {
		return api.ReportCell{Kind: "integer", Integer: &api.ReportCellInteger{Kind: "integer", Value: s}}
	}
	en := func(s string) api.ReportCell {
		return api.ReportCell{Kind: "enum", Enum: &api.ReportValueEnum{Kind: "enum", Value: s}}
	}
	tm := func(h int) api.ReportCell {
		return api.ReportCell{Kind: "time", Time: &api.ReportValueTime{Kind: "time", Value: apitypes.NewTimestamp(sys03Start.Add(-time.Duration(h) * time.Hour))}}
	}
	absent := api.ReportCell{Kind: "absent", Absent: &api.ReportCellAbsent{Kind: "absent"}}
	ids := []string{"domain_controller", "domain", "partition", "partner_dc", "last_attempt", "last_success", "consecutive_failures", "last_error_code", "last_error", "status", "lingering_risk", "read_at"}
	var ci []api.ReportColumnInfo
	for _, id := range ids {
		c := api.ReportColumnInfo{ID: id, Label: id, Type: api.ReportColumnTypeValueText, Sortable: true, Filterable: false, DefaultVisible: true,
			FilterOperators: []api.ReportFilterOperatorValue{}, Choices: []api.ReportChoice{}}
		if id == "status" {
			c.Type, c.Filterable = api.ReportColumnTypeValueEnum, true
			c.FilterOperators = []api.ReportFilterOperatorValue{api.ReportFilterOperatorValueEquals, api.ReportFilterOperatorValueIn}
			c.Choices = []api.ReportChoice{{ID: "failing", Label: "Failing"}, {ID: "warning", Label: "Warning"}, {ID: "healthy", Label: "Healthy"}, {ID: "not_reported", Label: "Not reported"}}
		}
		ci = append(ci, c)
	}
	failing := []api.ReportCell{txt("dc-emea1.corp.example"), txt("corp.example"), txt("corp.example"), txt("dc-emea3.corp.example"), tm(1), tm(190 * 24), num("12"), num("8524"),
		txt("The DSA operation is unable to proceed because of a DNS lookup failure."), en("failing"), en("at_risk"), tm(0)}
	didNotAnswer := []api.ReportCell{txt("dc-emea2.corp.example"), txt("corp.example"), absent, absent, absent, absent, absent, absent,
		txt("The domain controller refused the connection."), en("not_reported"), en("not_reported"), tm(0)}
	return api.ListReportRunRows200{Body: api.ReportRowPage{
		RunID: in.RunID, Columns: ci, RowCount: 17, Page: apitypes.PageInfo{},
		Rows: []api.ReportRow{{RowKey: "dc-emea1:corp.example:dc-emea3", Cells: failing}, {RowKey: "dc-emea2", Cells: didNotAnswer}},
	}}, nil
}

func (sys03Stub) GetReportReplicationThresholds(context.Context, api.GetReportReplicationThresholdsInput) (api.GetReportReplicationThresholdsOutput, error) {
	return api.GetReportReplicationThresholds200{ETag: `"v1"`, Body: api.ReportReplicationThresholds{
		WarningAfterSeconds: 3600, FailingAfterSeconds: 86400, IsDefault: true,
		Defaults: api.ReportReplicationThresholdPair{WarningAfterSeconds: 3600, FailingAfterSeconds: 86400},
	}}, nil
}

func (sys03Stub) ListReportManagers(_ context.Context, in api.ListReportManagersInput) (api.ListReportManagersOutput, error) {
	return api.ListReportManagers200{Body: api.ReportManagerList{Items: []api.ReportManagerCandidate{
		{ConnectionID: sys03Conn, GUID: sys03Run, DisplayName: "Ana Silva", LogonName: "asilva", OUPath: "corp.example/Sales", DirectReports: 3},
		{ConnectionID: sys03Conn, GUID: sys03Capd, DisplayName: "Ana Silva", LogonName: "asilva2", OUPath: "corp.example/Support", DirectReports: 1},
	}}}, nil
}

func serveSys03(t *testing.T, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	var rec apitest.Recorder
	srv, err := apihost.Build(doc, apitest.Conform(&rec, api.Bind(sys03Stub{})), pol, apitest.Catalogue(doc), apihost.Ports{Authn: ports{}, Authz: ports{}, Limits: ports{}, StepUp: ports{}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

type sys03Body struct {
	Coverage struct {
		DcsInScope   int  `json:"dcsInScope"`
		DcsAnswered  int  `json:"dcsAnswered"`
		Complete     bool `json:"complete"`
		NotReadByCap int  `json:"notReadByCap"`
		ReadCap      int  `json:"readCap"`
		Unanswered   []struct {
			Dc     string `json:"dc"`
			Reason string `json:"reason"`
			RowKey string `json:"rowKey"`
			Error  struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		} `json:"unanswered"`
	} `json:"coverage"`
	Replication struct {
		StatusCounts []struct {
			Status string `json:"status"`
			Count  int    `json:"count"`
		} `json:"statusCounts"`
	} `json:"replication"`
	RowCount int `json:"rowCount"`
}

// Acceptance 1, example call: 5 of 6 DCs read, the sixth in the Did-not-answer entries with its error and a row, and the status counts
// sum to the row count with the unreachable DC counted as not_reported, never healthy.
func TestSys03RunHeaderShowsCoverageUnansweredDcAndStatusCounts(t *testing.T) {
	w := serveSys03(t, http.MethodGet, "/api/v1/reports/runs/"+sys03Run.String())
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var b sys03Body
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	c := b.Coverage
	if c.DcsInScope != 6 || c.DcsAnswered != 5 || c.Complete || len(c.Unanswered) != 1 {
		t.Fatalf("want 5 of 6, incomplete, one unanswered: %+v", c)
	}
	if c.DcsAnswered+len(c.Unanswered)+c.NotReadByCap != c.DcsInScope {
		t.Errorf("answered + unanswered + notReadByCap must equal dcsInScope: %+v", c)
	}
	u := c.Unanswered[0]
	if u.Reason != "unreachable" || u.Error.Code == "" || u.Error.Message == "" || u.RowKey == "" {
		t.Errorf("the unanswered DC must carry its reason, error and row key: %+v", u)
	}
	sum := 0
	for i, want := range []string{"failing", "warning", "healthy", "not_reported"} {
		sc := b.Replication.StatusCounts[i]
		if sc.Status != want {
			t.Errorf("statusCounts[%d] is %q, want %q (fixed order, zeros included)", i, sc.Status, want)
		}
		sum += sc.Count
	}
	if sum != b.RowCount {
		t.Errorf("statusCounts sum %d, rowCount %d", sum, b.RowCount)
	}
	t.Logf("GET /api/v1/reports/runs/%s -> %d\n%s", sys03Run, w.Code, w.Body)
}

// The 100-DC cap: 138 in scope, 100 read, 38 not read; the run is not refused and coverage is incomplete.
func TestSys03CapReadsOneHundredAndCountsTheRest(t *testing.T) {
	w := serveSys03(t, http.MethodGet, "/api/v1/reports/runs/"+sys03Capd.String())
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var b sys03Body
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	c := b.Coverage
	if c.DcsInScope != 138 || c.DcsAnswered != 100 || c.NotReadByCap != 38 || c.ReadCap != 100 || c.Complete {
		t.Errorf("want 138 in scope, 100 read, 38 not read by the cap, incomplete: %+v", c)
	}
	t.Logf("GET /api/v1/reports/runs/%s -> %d\n%s", sys03Capd, w.Code, w.Body)
}

// Typed cells: the failing row carries typed values, the Did-not-answer row is not_reported with absent cells, so an unanswered DC
// is told apart from a healthy one in the rows too.
func TestSys03RowsAreTypedAndTheUnansweredDcIsNotReported(t *testing.T) {
	w := serveSys03(t, http.MethodGet, "/api/v1/reports/runs/"+sys03Run.String()+"/rows")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var page struct {
		Columns []struct {
			ID string `json:"id"`
		} `json:"columns"`
		Rows []struct {
			RowKey string           `json:"rowKey"`
			Cells  []map[string]any `json:"cells"`
		} `json:"rows"`
	}
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	idx := map[string]int{}
	for i, c := range page.Columns {
		idx[c.ID] = i
	}
	for _, r := range page.Rows {
		if len(r.Cells) != len(page.Columns) {
			t.Fatalf("row %s has %d cells for %d columns", r.RowKey, len(r.Cells), len(page.Columns))
		}
	}
	failing, none := page.Rows[0].Cells, page.Rows[1].Cells
	if failing[idx["last_error_code"]]["kind"] != "integer" || failing[idx["last_success"]]["kind"] != "time" || failing[idx["status"]]["value"] != "failing" {
		t.Errorf("failing row cells are not typed: %v", failing)
	}
	if none[idx["status"]]["value"] != "not_reported" || none[idx["last_success"]]["kind"] != "absent" || none[idx["lingering_risk"]]["value"] != "not_reported" {
		t.Errorf("the Did-not-answer row must be not_reported with absent values: %v", none)
	}
	if none[idx["status"]]["value"] == "healthy" {
		t.Errorf("an unanswered DC must never read as healthy")
	}
	t.Logf("GET /api/v1/reports/runs/%s/rows -> %d\n%s", sys03Run, w.Code, w.Body)
}

func TestSys03ThresholdsReadReturnsDefaultsAndAnETag(t *testing.T) {
	w := serveSys03(t, http.MethodGet, "/api/v1/reports/replication/thresholds")
	if w.Code != 200 || w.Header().Get("ETag") == "" {
		t.Fatalf("status %d, ETag %q: %s", w.Code, w.Header().Get("ETag"), w.Body)
	}
	var b struct {
		Warning   int  `json:"warningAfterSeconds"`
		Failing   int  `json:"failingAfterSeconds"`
		IsDefault bool `json:"isDefault"`
	}
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if b.Warning != 3600 || b.Failing != 86400 || !b.IsDefault {
		t.Errorf("defaults are 1 h and 24 h: %+v", b)
	}
	t.Logf("GET /api/v1/reports/replication/thresholds -> %d ETag %s\n%s", w.Code, w.Header().Get("ETag"), w.Body)
}

func TestManagerPickerExampleTellsSameNamesApart(t *testing.T) {
	w := serveSys03(t, http.MethodGet, "/api/v1/reports/managers?q=ana&limit=10")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var b struct {
		Items []map[string]any `json:"items"`
	}
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Items) != 2 || b.Items[0]["logonName"] == b.Items[1]["logonName"] {
		t.Errorf("same-name managers must differ by logon name: %v", b.Items)
	}
	t.Logf("GET /api/v1/reports/managers?q=ana&limit=10 -> %d\n%s", w.Code, w.Body)
}

// The PUT declares a required If-Match, so it cannot overwrite blind (428 precondition-required is the contract's answer without it).
func TestSys03ThresholdsUpdateNeedsIfMatch(t *testing.T) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range doc.Operations() {
		if op.ID == "updateReportReplicationThresholds" && op.Class != "write" {
			t.Errorf("updateReportReplicationThresholds has class %q", op.Class)
		}
	}
	d := bundle(t)
	put, _ := at(t, d, "paths", "/reports/replication/thresholds")["put"].(map[string]any)
	found := false
	for _, p := range anyList(put["parameters"]) {
		m, _ := p.(map[string]any)
		if r, _ := m["$ref"].(string); strings.HasSuffix(r, "/parameters/RequiredIfMatch") || (m["name"] == "If-Match" && m["required"] == true) {
			found = true
		}
	}
	if !found {
		t.Errorf("updateReportReplicationThresholds must require If-Match")
	}
}
