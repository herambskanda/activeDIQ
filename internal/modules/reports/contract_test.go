package reports_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/modules/reports"
	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/operation"
)

const wantOperations = 29 // 21 on main (T-0866, T-0891) + 6 preview twins + the undo pair (T-0892, ADR-0004 rule 14)

var fivePermissions = map[string]bool{
	string(reports.RunPermission):               true,
	string(reports.ExportPermission):            true,
	string(reports.SchedulePermission):          true,
	string(reports.ScheduleManageAllPermission): true,
	string(reports.DeliverExternalPermission):   true,
}

// Acceptance 1 and 3: every reports operation binds exactly one of the five permissions of spec 8.5 and
// carries a limit class; reports.deliver.external is bound to none (it guards the external-recipient case
// inside the schedule Action), and reports.schedule.manage_all only to the reassign operation and its preview twin.
func TestEveryReportsOperationBindsOneSpecPermissionAndAClass(t *testing.T) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, op := range doc.Operations() {
		if op.Tag != "reports" {
			continue
		}
		n++
		if !fivePermissions[op.Permission] {
			t.Errorf("%s binds %q, not one of the five reports permissions", op.ID, op.Permission)
		}
		if op.Permission == string(reports.DeliverExternalPermission) {
			t.Errorf("%s binds reports.deliver.external; it may only guard the external-recipient case", op.ID)
		}
		if op.Permission == string(reports.ScheduleManageAllPermission) && op.ID != "reassignReportSchedule" && op.ID != "previewReassignReportSchedule" {
			t.Errorf("%s binds reports.schedule.manage_all; only reassignReportSchedule and its preview twin may", op.ID)
		}
		if op.ID == "reassignReportSchedule" && op.Permission != string(reports.ScheduleManageAllPermission) {
			t.Errorf("reassignReportSchedule binds %q", op.Permission)
		}
		switch op.Class {
		case "read", "write", "bulk":
		default:
			t.Errorf("%s has limit class %q", op.ID, op.Class)
		}
		if !strings.HasPrefix(op.Path, "/reports/") {
			t.Errorf("%s path %q is outside /reports", op.ID, op.Path)
		}
	}
	if n != wantOperations {
		t.Fatalf("reports has %d operations, want %d", n, wantOperations)
	}
}

// Acceptance 4: the three problem types exist in the bundle, are distinct, are reachable from the
// operations the contract names, and their fixed text carries no object name or value.
func TestScopeAndExpiryProblemTypesAreDistinctAndSayNoNames(t *testing.T) {
	raw, err := os.ReadFile("../../platform/apihost/spec/openapi.gen.json")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := jsonv2.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	responses := at(t, d, "components", "responses")
	typeOf := func(name string) (typ, title string) {
		ex := at(t, responses, name, "content", "application/problem+json", "example")
		return ex["type"].(string), ex["title"].(string)
	}
	slugs := map[string]string{ // response component -> type
		"ReportResultExpired":    "/problems/report-result-expired",
		"ReportScopeEmpty":       "/problems/report-scope-empty",
		"ReportScopeUnsupported": "/problems/report-scope-unsupported",
	}
	seen := map[string]string{}
	for name, want := range slugs {
		typ, title := typeOf(name)
		if typ != want {
			t.Errorf("%s: type %q, want %q", name, typ, want)
		}
		if prev, dup := seen[typ]; dup {
			t.Errorf("%s and %s share type %s", prev, name, typ)
		}
		seen[typ] = name
		if strings.ContainsAny(title, `"'{}<>@\/=`) || strings.ContainsAny(title, "0123456789") {
			t.Errorf("%s: title %q looks like it carries a name or value", name, title)
		}
	}
	// Which operation answers which slug, on which status.
	reached := map[string][]string{}
	for path, item := range at(t, d, "paths") {
		if !strings.HasPrefix(path, "/reports/") {
			continue
		}
		for _, o := range item.(map[string]any) {
			op, ok := o.(map[string]any)
			if !ok {
				continue
			}
			perStatus := map[string]string{}
			for status, r := range op["responses"].(map[string]any) {
				ref, _ := r.(map[string]any)["$ref"].(string)
				name := ref[strings.LastIndex(ref, "/")+1:]
				if _, ok := slugs[name]; ok {
					reached[name] = append(reached[name], op["operationId"].(string)+" "+status)
					perStatus[status] = name
				}
			}
			byName := map[string]string{}
			for st, name := range perStatus {
				if prev, dup := byName[name]; dup {
					t.Errorf("%v answers %s on both %s and %s", op["operationId"], name, prev, st)
				}
				byName[name] = st
			}
		}
	}
	for name := range slugs {
		if len(reached[name]) == 0 {
			t.Errorf("no reports operation answers %s", name)
		}
	}
	for _, name := range []string{"ReportScopeEmpty", "ReportScopeUnsupported"} {
		for _, hit := range reached[name] {
			if !strings.Contains("createReportSchedule updateReportSchedule resumeReportSchedule createReportExport", strings.Fields(hit)[0]) {
				t.Errorf("%s is answered by %s; it guards data-leaving or recurring things only", name, hit)
			}
		}
	}
	t.Logf("slug -> operations: %v", reached)
}

func bundle(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../platform/apihost/spec/openapi.gen.json")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := jsonv2.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func at(t *testing.T, m map[string]any, path ...string) map[string]any {
	t.Helper()
	cur := m
	for _, k := range path {
		next, ok := cur[k].(map[string]any)
		if !ok {
			t.Fatalf("bundle has no %v", path)
		}
		cur = next
	}
	return cur
}

// stub records which operations reached a handler. Every method is the embedded nil interface's, so a
// call to an operation this test does not expect panics.
type stub struct {
	api.Handlers
	runs int
}

func (s *stub) CreateReportRun(context.Context, api.CreateReportRunInput) (api.CreateReportRunOutput, error) {
	s.runs++
	return api.CreateReportRun202{Location: "/api/v1/reports/runs/x"}, nil
}

type ports struct{}

func (ports) Authenticate(*http.Request) (apihost.Principal, error) {
	return apihost.Principal{ID: "admin", Tenant: "00000000-0000-4000-8000-000000000001", Kind: apihost.KindSession, SessionID: "s"}, nil
}
func (ports) CheckCSRF(*http.Request, apihost.Principal) error { return nil }
func (ports) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (ports) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (ports) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (ports) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

func postRun(t *testing.T, s *stub, body string) *httptest.ResponseRecorder {
	t.Helper()
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := apihost.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	perms := apihost.Permissions{"reports.deliver.external", "reports.export", "reports.run", "reports.schedule", "reports.schedule.manage_all",
		"directory.read", "connections.takeover.attest", "siem.destination.manage", "siem.destination.read"}
	srv, err := apihost.Build(doc, []apihost.TagHandlers{api.Bind(s)}, pol, perms, apihost.Ports{Authn: ports{}, Authz: ports{}, Limits: ports{}, StepUp: ports{}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/v1/reports/runs", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "203.0.113.7:4444"
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

// Acceptance 2, the corpus case: a create-run body that carries a free-text column name, a raw filter
// string, an LDAP filter, a DN, an SQL fragment or any member the contract does not define is refused at
// the schema with a 400 problem, and the handler never runs. A valid body reaches the handler.
func TestCreateRunRefusesFreeTextColumnsRawFiltersAndSQL(t *testing.T) {
	bad := map[string]string{
		"free-text column":       `{"definitionId":"USR-01","parameters":{"columns":["name; DROP TABLE users"]}}`,
		"column not in the enum": `{"definitionId":"USR-01","parameters":{"columns":["samAccountName"]}}`,
		"compare on free column": `{"definitionId":"USR-01","parameters":{"filters":[{"kind":"compare","column":"(cn=*)","operator":"equals","value":{"kind":"text","value":"x"}}]}}`,
		"raw filter string":      `{"definitionId":"USR-01","parameters":{"filters":["(&(objectClass=user)(adminCount=1))"]}}`,
		"ldap filter member":     `{"definitionId":"USR-01","parameters":{"ldapFilter":"(objectClass=*)"}}`,
		"sql filter member":      `{"definitionId":"USR-01","sql":"SELECT * FROM users"}`,
		"where member":           `{"definitionId":"USR-01","parameters":{"where":"1=1"}}`,
		"sql fragment as preset": `{"definitionId":"USR-01","presetId":"x' OR '1'='1"}`,
		"sql fragment as def id": `{"definitionId":"USR-01; DROP TABLE runs"}`,
		"dn as ou reference":     `{"definitionId":"USR-01","parameters":{"ouInclude":["OU=Staff,DC=lab,DC=test"]}}`,
		"missing definition":     `{"parameters":{}}`,
	}
	for name, body := range bad {
		s := &stub{}
		w := postRun(t, s, body)
		if w.Code != 400 {
			t.Errorf("%s: status %d, want 400 (%s)", name, w.Code, w.Body)
		}
		if s.runs != 0 {
			t.Errorf("%s: reached the handler", name)
		}
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "problem+json") {
			t.Errorf("%s: content type %q", name, ct)
		}
	}
	s := &stub{}
	w := postRun(t, s, `{"definitionId":"USR-01","presetId":"locked_out","parameters":{"columns":["name","logon_name"]}}`)
	if s.runs != 1 {
		t.Fatalf("a valid body did not reach the handler: %d %s", w.Code, w.Body)
	}
	t.Log("valid body status " + strconv.Itoa(w.Code))
	// Positive control for the typed tree: the same filter shape as the refused one, with a registry column, is accepted.
	w = postRun(t, s, `{"definitionId":"USR-01","parameters":{"filters":[{"kind":"compare","column":"name","operator":"equals","value":{"kind":"text","value":"x"}}]}}`)
	if s.runs != 2 {
		t.Fatalf("a valid typed filter did not reach the handler: %d %s", w.Code, w.Body)
	}
}

// The run-read gate of modules/reports.md 6.6: the four operations that read a stored run (the run header,
// its rows, an export of it, and the creator's download of that export) declare 409 and name the
// scope_changed_rerun code; rows and export also name run_not_ready and run_failed as separate codes.
// The delivery, delete and run-now rules from 7.1, 7.2 and 6.6 are stated in the operation text.
func TestRunReadGateIsDeclaredOnEveryRunRead(t *testing.T) {
	raw, err := os.ReadFile("../../platform/apihost/spec/openapi.gen.json")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := jsonv2.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
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
	desc := func(id string) string {
		op, ok := ops[id]
		if !ok {
			t.Fatalf("operation %s missing", id)
		}
		s, _ := op["description"].(string)
		return s
	}
	for _, id := range []string{"getReportRun", "listReportRunRows", "createReportExport", "downloadReportExport"} {
		if _, ok := at(t, ops[id], "responses")["409"]; !ok {
			t.Errorf("%s declares no 409", id)
		}
		if !strings.Contains(desc(id), "scope_changed_rerun") {
			t.Errorf("%s does not name the scope_changed_rerun code", id)
		}
	}
	for _, id := range []string{"listReportRunRows", "createReportExport"} {
		for _, code := range []string{"run_not_ready", "run_failed"} {
			if !strings.Contains(desc(id), code) {
				t.Errorf("%s does not name the %s code", id, code)
			}
		}
	}
	if d := desc("createReportExport"); !strings.Contains(d, "reports.run") {
		t.Error("createReportExport must say reports.run is checked inside the operation")
	}
	if p := ops["createReportExport"]["x-permission"]; p != string(reports.ExportPermission) {
		t.Errorf("createReportExport binds %v", p)
	}
	dl := desc("downloadReportExport")
	for _, want := range []string{"delivery record", "never comes from the schedule's current recipient list", "reports.export", "enabled", "byte for byte"} {
		if !strings.Contains(dl, want) {
			t.Errorf("downloadReportExport does not say %q", want)
		}
	}
	if del := desc("deleteReportExport"); strings.Contains(del, "account named in a delivery") || !strings.Contains(del, "may not") {
		t.Errorf("deleteReportExport must refuse recipients: %s", del)
	}
	if rn := desc("runReportScheduleNow"); !strings.Contains(rn, "Only the schedule's owner") || !strings.Contains(rn, "404") {
		t.Error("runReportScheduleNow must say owner only, everyone else 404")
	}
	if cr := desc("createReportRun"); !strings.Contains(cr, "too_many_report_jobs") || !strings.Contains(cr, "60 seconds") || strings.Contains(cr, "Exporting or scheduling from such a scope is refused") {
		t.Error("createReportRun must state the reuse window, the job limit and that exports are allowed")
	}
	for _, reason := range []string{"runner_inactive", "token_refused", "row_cap_exceeded", "per_dc_read_cap_exceeded", "scope_too_large", "query_timeout", "connection_unavailable", "definition_retired", "interrupted", "internal"} {
		found := false
		for _, v := range at(t, d, "components", "schemas", "ReportFailureReason")["enum"].([]any) {
			found = found || v == reason
		}
		if !found {
			t.Errorf("ReportFailureReason lacks %s", reason)
		}
	}
}

// T-0892, ADR-0004 rule 14 (the per-module evidence until fitness-api A15, T-0976, checks every tag): each
// reports.schedule.* write has a preview twin with the same permission, path parameters, If-Match and request
// body that answers the shared OperationPreview; every 2xx of the write carries ActiveDIQ-Operation-Id and it
// declares 202 OperationRef; and the family has its undo pair bound to reports.schedule.
func TestScheduleActionsHavePreviewTwinsAndAnUndoPair(t *testing.T) {
	raw, err := os.ReadFile("../../platform/apihost/spec/openapi.gen.json")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := jsonv2.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	type found struct {
		path, method string
		op           map[string]any
	}
	ops := map[string]found{}
	for path, item := range at(t, d, "paths") {
		for method, o := range item.(map[string]any) {
			om, ok := o.(map[string]any)
			if !ok {
				continue
			}
			if id, _ := om["operationId"].(string); id != "" {
				ops[id] = found{path, method, om}
			}
		}
	}
	ref := func(v any) string {
		m, _ := v.(map[string]any)
		r, _ := m["$ref"].(string)
		return r
	}
	params := func(o map[string]any) []string {
		var out []string
		for _, p := range anyList(o["parameters"]) {
			out = append(out, ref(p))
		}
		return out
	}
	bodyRef := func(o map[string]any) string {
		rb, _ := o["requestBody"].(map[string]any)
		if rb == nil {
			return ""
		}
		c, _ := rb["content"].(map[string]any)
		j, _ := c["application/json"].(map[string]any)
		return ref(j["schema"])
	}
	respRef := func(o map[string]any, code string) (schema string, headers map[string]any) {
		r, _ := o["responses"].(map[string]any)[code].(map[string]any)
		if r == nil {
			return "", nil
		}
		headers, _ = r["headers"].(map[string]any)
		if c, _ := r["content"].(map[string]any); c != nil {
			j, _ := c["application/json"].(map[string]any)
			schema = ref(j["schema"])
		}
		return schema, headers
	}
	const (
		preview = "#/components/schemas/OperationPreview"
		opRef   = "#/components/schemas/OperationRef"
		header  = "ActiveDIQ-Operation-Id"
	)
	writes := map[string]struct{ twin, verb, ok string }{
		"createReportSchedule":   {"previewCreateReportSchedule", "create", "201"},
		"updateReportSchedule":   {"previewUpdateReportSchedule", "update", "200"},
		"deleteReportSchedule":   {"previewDeleteReportSchedule", "delete", "204"},
		"pauseReportSchedule":    {"previewPauseReportSchedule", "pause", "200"},
		"resumeReportSchedule":   {"previewResumeReportSchedule", "resume", "200"},
		"reassignReportSchedule": {"previewReassignReportSchedule", "reassign", "200"},
	}
	for id, w := range writes {
		wr, ok := ops[id]
		if !ok {
			t.Fatalf("%s is missing", id)
		}
		tw, ok := ops[w.twin]
		if !ok {
			t.Errorf("%s has no preview twin %s", id, w.twin)
			continue
		}
		if tw.method != "post" || !strings.HasSuffix(tw.path, "/previews/"+w.verb) {
			t.Errorf("%s: twin is %s %s, want POST .../previews/%s", id, tw.method, tw.path, w.verb)
		}
		if tw.op["x-permission"] != wr.op["x-permission"] {
			t.Errorf("%s: twin binds %v, write binds %v", id, tw.op["x-permission"], wr.op["x-permission"])
		}
		if a, b := strings.Join(params(tw.op), ","), strings.Join(params(wr.op), ","); a != b {
			t.Errorf("%s: twin parameters %q, write parameters %q", id, a, b)
		}
		if a, b := bodyRef(tw.op), bodyRef(wr.op); a != b {
			t.Errorf("%s: twin body %q, write body %q", id, a, b)
		}
		if s, _ := respRef(tw.op, "200"); s != preview {
			t.Errorf("%s: twin answers %q, want %s", w.twin, s, preview)
		}
		for code := range wr.op["responses"].(map[string]any) {
			if code[0] != '2' {
				continue
			}
			if _, h := respRef(wr.op, code); h[header] == nil {
				t.Errorf("%s %s lacks the %s header", id, code, header)
			}
		}
		if s, _ := respRef(wr.op, w.ok); w.ok != "204" && s == "" {
			t.Errorf("%s %s has no body", id, w.ok)
		}
		if s, _ := respRef(wr.op, "202"); s != opRef {
			t.Errorf("%s: 202 answers %q, want %s", id, s, opRef)
		}
	}
	for id, want := range map[string]string{"undoReportScheduleOperation": opRef, "previewUndoReportScheduleOperation": preview} {
		u, ok := ops[id]
		if !ok {
			t.Errorf("the reports.schedule family has no %s", id)
			continue
		}
		if u.op["x-permission"] != string(reports.SchedulePermission) {
			t.Errorf("%s binds %v, want the family base permission %s", id, u.op["x-permission"], reports.SchedulePermission)
		}
		if !strings.HasPrefix(u.path, "/reports/schedules/operations/{operationId}/") {
			t.Errorf("%s path %q", id, u.path)
		}
		if s, _ := respRef(u.op, "200"); s != want {
			t.Errorf("%s answers %q, want %s", id, s, want)
		}
	}
	if s, h := respRef(ops["undoReportScheduleOperation"].op, "200"); s == "" || h[header] == nil {
		t.Errorf("undoReportScheduleOperation 200 lacks %s", header)
	}
	if s, _ := respRef(ops["undoReportScheduleOperation"].op, "202"); s != opRef {
		t.Errorf("undoReportScheduleOperation 202 answers %q, want %s", s, opRef)
	}

	// The held answer says why it is held (TM-D30 SX-4): OperationRef carries a required holdReason of the
	// open enum that mirrors the kernel's HoldReason, and the preview uses the same enum.
	const holdRef = "#/components/schemas/OperationHoldReasonValue"
	schemas := at(t, d, "components", "schemas")
	for _, name := range []string{"OperationRef", "OperationPreview"} {
		sc, _ := schemas[name].(map[string]any)
		props, _ := sc["properties"].(map[string]any)
		if ref(props["holdReason"]) != holdRef {
			t.Errorf("%s.holdReason is %v, want $ref %s", name, props["holdReason"], holdRef)
		}
		if !slices.Contains(anyList(sc["required"]), any("holdReason")) {
			t.Errorf("%s does not require holdReason", name)
		}
	}
	hr, _ := schemas["OperationHoldReasonValue"].(map[string]any)
	if hr["x-activediq-enum"] != "open" {
		t.Errorf("OperationHoldReasonValue is a response enum and must be open")
	}
	got := map[string]bool{}
	for _, v := range anyList(hr["enum"]) {
		got[v.(string)] = true
	}
	for _, h := range []operation.HoldReason{operation.HoldStepUp, operation.HoldBlastRadius, operation.HoldIrreversible, operation.HoldUndoNeededAppr, operation.HoldGate} {
		if !got[string(h)] {
			t.Errorf("OperationHoldReasonValue lacks the kernel hold reason %q", h)
		}
	}
	if !got["none"] || len(got) != 6 {
		t.Errorf("OperationHoldReasonValue is %v, want none plus the five kernel hold reasons", hr["enum"])
	}

	// The undo restores external recipients under step-up (TM-D30 SX-1, R6): it declares 401 step-up-required.
	r401, _ := ops["undoReportScheduleOperation"].op["responses"].(map[string]any)["401"]
	if ref(r401) != "#/components/responses/StepUpRequired" {
		t.Errorf("undoReportScheduleOperation 401 is %v, want $ref StepUpRequired", r401)
	}
	// The header that names the undo handle has the format of the OperationId path parameter it feeds.
	for id := range writes {
		for code, r := range ops[id].op["responses"].(map[string]any) {
			if code[0] != '2' {
				continue
			}
			h, _ := r.(map[string]any)["headers"].(map[string]any)[header].(map[string]any)
			if sc, _ := h["schema"].(map[string]any); sc["format"] != "uuid" {
				t.Errorf("%s %s: %s is not format uuid", id, code, header)
			}
		}
	}
}

func anyList(v any) []any {
	l, _ := v.([]any)
	return l
}
