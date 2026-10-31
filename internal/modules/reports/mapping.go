package reports

import (
	"encoding/json/jsontext"
	"fmt"
	"strconv"
	"strings"
	"time"

	jsonv2 "encoding/json/v2"

	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
)

// Codec decodes the stored API-shape run parameters into typed report parameters. It is the one place
// the request vocabulary (api.ReportRunParameters) meets the engine's (report.RunParams); the run
// package never imports the API. Every refusal is a report.ValidationError with a path and no request value.
type Codec struct{}

var _ run.ParamsCodec = Codec{}

// Decode implements run.ParamsCodec. def names the one Days parameter a period of lastDays sets.
func (Codec) Decode(raw jsontext.Value, def report.Definition) (report.RunParams, error) {
	var p api.ReportRunParameters
	if err := jsonv2.Unmarshal(raw, &p); err != nil {
		return report.RunParams{}, bad("parameters")
	}
	out := report.RunParams{Params: map[string]report.ParamValue{}}
	for i, c := range p.ConnectionIds {
		g, err := objectID(c.String())
		if err != nil {
			return report.RunParams{}, bad(fmt.Sprintf("connectionIds[%d]", i))
		}
		out.Connections = append(out.Connections, g)
	}
	var err error
	if out.Include, err = roots(p.OUInclude, "ouInclude"); err != nil {
		return report.RunParams{}, err
	}
	if out.Exclude, err = roots(p.OUExclude, "ouExclude"); err != nil {
		return report.RunParams{}, err
	}
	for i, s := range p.Subjects {
		g, err := objectID(s.GUID.String())
		if err != nil {
			return report.RunParams{}, bad(fmt.Sprintf("subjects[%d]", i))
		}
		out.Subjects = append(out.Subjects, g)
	}
	for _, c := range p.Columns {
		out.Columns = append(out.Columns, report.ColumnID(c))
	}
	for i, f := range p.Filters {
		e, err := expr(f, fmt.Sprintf("filters[%d]", i), 0)
		if err != nil {
			return report.RunParams{}, err
		}
		out.Filters = append(out.Filters, e)
	}
	if p.Period != nil {
		if err := period(*p.Period, def, out.Params); err != nil {
			return report.RunParams{}, err
		}
	}
	return out, nil
}

func bad(path string) error { return report.ValidationError{Code: report.CodeBadValue, Path: path} }

func objectID(s string) (authz.ObjectID, error) { return authz.ParseObjectID(s) }

func roots(in []api.ReportOuRef, name string) ([]report.NarrowRoot, error) {
	var out []report.NarrowRoot
	for i, r := range in {
		c, err1 := objectID(r.ConnectionID.String())
		g, err2 := objectID(r.GUID.String())
		if err1 != nil || err2 != nil {
			return nil, report.ValidationError{Code: report.CodeBadNarrowing, Path: fmt.Sprintf("%s[%d]", name, i)}
		}
		d := report.DepthSubtree
		if r.OneLevel {
			d = report.DepthOneLevel
		}
		out = append(out, report.NarrowRoot{Connection: c, Root: g, Depth: d})
	}
	return out, nil
}

// period maps lastDays onto the definition's single Days parameter. A date range is the audit
// reports' (E-005); no 2a definition takes one, so it is refused rather than ignored.
func period(p api.ReportPeriod, def report.Definition, into map[string]report.ParamValue) error {
	if p.LastDays == nil {
		return report.ValidationError{Code: report.CodeUnknownParameter, Path: "period"}
	}
	var name string
	for _, s := range def.Params {
		if s.Kind != report.ParamDays {
			continue
		}
		if name != "" {
			return report.ValidationError{Code: report.CodeUnknownParameter, Path: "period"} // ambiguous: set params, not a period
		}
		name = s.Name
	}
	if name == "" {
		return report.ValidationError{Code: report.CodeUnknownParameter, Path: "period"}
	}
	into[name] = report.DaysP(p.LastDays.Days)
	return nil
}

const maxFilterDepth = 8

func expr(f api.ReportFilter, path string, depth int) (report.Expr, error) {
	if depth > maxFilterDepth {
		return nil, report.ValidationError{Code: report.CodeTooComplex, Path: path}
	}
	switch {
	case f.Compare != nil:
		op, ok := compareOps[f.Compare.Operator]
		v, err := value(f.Compare.Value)
		if !ok || err != nil {
			return nil, bad(path)
		}
		return report.Cmp{Column: report.ColumnID(f.Compare.Column), Op: op, Value: v}, nil
	case f.In != nil:
		var vs []report.Value
		for _, x := range f.In.Values {
			v, err := value(x)
			if err != nil {
				return nil, bad(path)
			}
			vs = append(vs, v)
		}
		return report.Cmp{Column: report.ColumnID(f.In.Column), Op: report.OpIn, Values: vs}, nil
	case f.Presence != nil:
		op := report.OpPresent
		if f.Presence.Presence == api.ReportPresenceEmpty {
			op = report.OpAbsent
		}
		return report.Cmp{Column: report.ColumnID(f.Presence.Column), Op: op}, nil
	case f.RelativeTime != nil:
		var op report.Op
		switch f.RelativeTime.Relation {
		case api.ReportRelativeTimeWithinLast:
			op = report.OpWithinLastDays
		case api.ReportRelativeTimeWithinNext:
			op = report.OpWithinNextDays
		case api.ReportRelativeTimeOlderThan:
			op = report.OpOlderThanDays
		default:
			return nil, bad(path)
		}
		return report.Cmp{Column: report.ColumnID(f.RelativeTime.Column), Op: op, Value: report.IntV(f.RelativeTime.Days)}, nil
	case f.Group != nil:
		var terms []report.Expr
		for i, c := range f.Group.Filters {
			e, err := expr(c, fmt.Sprintf("%s.filters[%d]", path, i), depth+1)
			if err != nil {
				return nil, err
			}
			terms = append(terms, e)
		}
		switch f.Group.Match {
		case api.ReportFilterMatchAll:
			return report.And{Terms: terms}, nil
		case api.ReportFilterMatchAny:
			return report.Or{Terms: terms}, nil
		case api.ReportFilterMatchNone:
			return report.Not{Term: report.Or{Terms: terms}}, nil
		}
	}
	return nil, bad(path)
}

var compareOps = map[api.ReportCompareOperator]report.Op{
	api.ReportCompareOperatorEquals:         report.OpEq,
	api.ReportCompareOperatorNotEquals:      report.OpNe,
	api.ReportCompareOperatorLessThan:       report.OpLt,
	api.ReportCompareOperatorLessOrEqual:    report.OpLe,
	api.ReportCompareOperatorGreaterThan:    report.OpGt,
	api.ReportCompareOperatorGreaterOrEqual: report.OpGe,
	api.ReportCompareOperatorContains:       report.OpContains,
	api.ReportCompareOperatorStartsWith:     report.OpPrefix,
}

func value(v api.ReportValue) (report.Value, error) {
	switch {
	case v.Text != nil:
		return report.TextV(v.Text.Value), nil
	case v.Integer != nil:
		return report.IntV(v.Integer.Value), nil
	case v.Boolean != nil:
		return report.BoolV(v.Boolean.Value), nil
	case v.Time != nil:
		return report.TimeV(v.Time.Value.Time()), nil
	case v.Enum != nil:
		return report.EnumV(v.Enum.Value), nil
	}
	return report.Value{}, fmt.Errorf("value")
}

// ---- stored run -> API ----

func uuid(s string) apitypes.UUID {
	u, err := apitypes.ParseUUID(s)
	if err != nil {
		return apitypes.UUID{}
	}
	return u
}

func ts(t time.Time) apitypes.Timestamp { return apitypes.NewTimestamp(t) }

func tsp(t *time.Time) *apitypes.Timestamp {
	if t == nil {
		return nil
	}
	x := ts(*t)
	return &x
}

func idp(id *run.ID) *apitypes.UUID {
	if id == nil {
		return nil
	}
	u := uuid(id.String())
	return &u
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// failureMessages is fixed text per reason: it names no object, account or value (contract: ReportFailure).
var failureMessages = map[run.FailureReason]string{
	run.FailRunnerInactive:        "The account that started this run is no longer active.",
	run.FailTokenRefused:          "The token that started this run was refused.",
	run.FailRowCapExceeded:        "The result is over the row limit for a stored run. Narrow the filters or the scope and run it again.",
	run.FailPerDCReadCapExceeded:  "Too many domain controllers were needed for this run.",
	run.FailScopeTooLarge:         "The scope is too large to run as one report. Narrow it and run it again.",
	run.FailQueryTimeout:          "The run took too long and was stopped. Narrow the scope or the filters and run it again.",
	run.FailConnectionUnavailable: "A directory connection this run needs is not available.",
	run.FailDefinitionRetired:     "This report version was retired before the run could start. Run it again.",
	run.FailInterrupted:           "The run was interrupted before it finished. Run it again.",
	run.FailInternal:              "The run failed for an internal reason. Run it again; if it keeps failing, contact support.",
}

func failure(r run.Run) *api.ReportFailure {
	if r.Failure == "" {
		return nil
	}
	msg := failureMessages[r.Failure]
	if r.Failure == run.FailRowCapExceeded {
		if rows, ok := r.ScopeApplied.Detail["rows"]; ok {
			msg = fmt.Sprintf("The result has %d rows; a stored run holds at most %d. Narrow the filters or the scope and run it again.", rows, r.ScopeApplied.Detail["cap"])
		}
	}
	return &api.ReportFailure{Reason: api.ReportFailureReason(r.Failure), Message: msg}
}

// exportFailure is the ReportFailure of a failed export. The row-cap message names the numbers the job
// recorded; every other message is fixed text (a run's own reasons keep the run's wording).
func exportFailure(e export.Export) *api.ReportFailure {
	if e.Failure == "" {
		return nil
	}
	msg := failureMessages[e.Failure]
	switch e.Failure {
	case run.FailRowCapExceeded:
		msg = "The result is over the row limit for this export format. Narrow the filters or the scope and export again."
		if rows, ok := e.FailureDetail["rows"]; ok {
			msg = fmt.Sprintf("This export has %d rows. %s allows %d. Narrow the filters or the scope and export again.",
				rows, strings.ToUpper(string(e.Format)), e.FailureDetail["cap"])
		}
	case run.FailInternal:
		msg = "The export failed for an internal reason. Export it again; if it keeps failing, contact support."
	}
	return &api.ReportFailure{Reason: api.ReportFailureReason(e.Failure), Message: msg}
}

// exportView is the ReportExport of one export. The state is the effective one: a succeeded export past its
// expiry reads as expired before the sweep has flipped the record. The blob key never appears.
func exportView(e export.Export, now time.Time) api.ReportExport {
	st := e.State
	if e.Expired(now) {
		st = export.StateExpired
	}
	v := api.ReportExport{
		ID: uuid(e.ID.String()), RunID: uuid(e.RunID.String()), Rerun: e.Rerun, RerunOfRunID: idp(e.RerunOf),
		Format: api.ReportExportFormatValue(e.Format), State: api.ReportExportState(st),
		CreatedBy: apitypes.JobActor{ID: e.CreatedBy, Type: "user"}, CreatedAt: ts(e.CreatedAt), FinishedAt: tsp(e.FinishedAt),
		RowCount: e.RowCount, ByteSize: e.ByteSize, Digest: digestHex(e.Digest), Failure: exportFailure(e),
	}
	if st == export.StateSucceeded || st == export.StateExpired {
		v.FileName = e.FileName
	}
	if e.State != export.StateFailed {
		exp := ts(e.ExpiresAt)
		v.ExpiresAt = &exp
	}
	return v
}

func freshness(r run.Run) api.ReportFreshness {
	f := r.Freshness
	if f == nil {
		return api.ReportFreshness{Label: "Not synced yet", State: api.ReportFreshnessStateNotSyncedYet, Stale: []api.ReportStaleSource{}}
	}
	st := api.ReportFreshnessState(f.State)
	switch st {
	case api.ReportFreshnessStateSynced, api.ReportFreshnessStateStale, api.ReportFreshnessStateNotSyncedYet, api.ReportFreshnessStatePerDcRead:
	default:
		st = api.ReportFreshnessStateNotSyncedYet
	}
	out := api.ReportFreshness{Label: f.Label, State: st, Stale: staleSources(f)}
	if f.Threshold > 0 { // zero: the run was judged against no connection
		t := f.Threshold
		out.ThresholdSeconds = &t
	}
	return out
}

// staleSources lists the naming contexts behind a stale result, oldest first (the record's order). It is
// empty unless the state is stale, so a synced run never carries a cause. The ids are canonical text
// written by the run job.
func staleSources(f *run.FreshnessRecord) []api.ReportStaleSource {
	out := []api.ReportStaleSource{}
	if f.State != "stale" {
		return out
	}
	for _, e := range f.Stale {
		cause := api.ReportStaleCauseOlderThanThreshold
		switch e.State {
		case "resync_required":
			cause = api.ReportStaleCauseResyncRequired
		case "paused":
			cause = api.ReportStaleCausePaused
		}
		name := e.ConnectionName
		if name == "" {
			name = e.Connection
		}
		out = append(out, api.ReportStaleSource{
			ConnectionID: uuid(e.Connection), ConnectionName: name, NamingContextID: uuid(e.NC), Cause: cause,
			LastPassAt: ts(f.ComputedAt.Add(-time.Duration(e.AgeSeconds) * time.Second)), AgeSeconds: e.AgeSeconds,
		})
	}
	return out
}

func emptyReason(r run.Run) *api.ReportEmptyReason {
	switch e := api.ReportEmptyReason(r.ScopeApplied.EmptyReason); e {
	case api.ReportEmptyReasonScopeGrantsNothing, api.ReportEmptyReasonUnsupportedScopeKind:
		return &e
	}
	return nil
}

func skipped(r run.Run) []api.ReportSkippedConnection {
	out := []api.ReportSkippedConnection{}
	if r.Freshness == nil {
		return out
	}
	for _, c := range r.Freshness.NotSynced {
		out = append(out, api.ReportSkippedConnection{ConnectionID: uuid(c), Reason: api.ReportSkipReasonNotSyncedYet})
	}
	return out
}

func hiddenView(hs []run.HiddenGroup) []api.ReportHiddenGroup {
	out := make([]api.ReportHiddenGroup, 0, len(hs))
	for _, h := range hs {
		out = append(out, api.ReportHiddenGroup{ID: h.ID, Label: h.Label, Count: h.Count, Locked: h.Locked})
	}
	return out
}

func progress(s run.State) api.ReportRunProgress {
	switch s {
	case run.StateRunning:
		return api.ReportRunProgress{Stage: api.ReportRunStageReadingDirectory}
	case run.StateSucceeded:
		return api.ReportRunProgress{Stage: api.ReportRunStageDone, Percent: 100}
	case run.StateQueued:
		return api.ReportRunProgress{Stage: api.ReportRunStageQueued}
	}
	return api.ReportRunProgress{Stage: api.ReportRunStageDone}
}

func digestHex(d []byte) *string {
	if len(d) == 0 {
		return nil
	}
	const hexd = "0123456789abcdef"
	b := make([]byte, 0, len(d)*2)
	for _, x := range d {
		b = append(b, hexd[x>>4], hexd[x&15])
	}
	s := string(b)
	return &s
}

// runView is the ReportRun of one stored run. The state is the effective one: a succeeded run past its
// expiry reads as expired before the sweep has flipped the record.
func runView(r run.Run, hidden []run.HiddenGroup, now time.Time) api.ReportRun {
	st := r.EffectiveState(now)
	var created apitypes.JobActor
	created = apitypes.JobActor{ID: r.Runner, Type: "user"}
	var sa *string
	if r.ScopeApplied.Summary != "" {
		sa = strp(r.ScopeApplied.Summary)
	}
	return api.ReportRun{
		ID: uuid(r.ID.String()), DefinitionID: r.DefinitionID, DefinitionVersion: int64(r.DefinitionVer), PresetID: strp(r.Preset),
		State: api.ReportRunState(st), Progress: progress(st), CreatedBy: created, CreatedAt: ts(r.CreatedAt),
		StartedAt: tsp(r.StartedAt), FinishedAt: tsp(r.FinishedAt), ExpiresAt: tsp(r.ExpiresAt), AsOf: tsp(r.AsOf),
		Freshness: freshness(r), SkippedConnections: skipped(r), HiddenGroups: hiddenView(hidden), RowCount: r.RowCount, ObjectsChecked: r.ObjectsChecked,
		Digest: digestHex(r.Digest), ScopeApplied: sa, EmptyReason: emptyReason(r), Failure: failure(r), RerunOf: idp(r.RerunOf),
		Parameters: paramsView(r),
	}
}

func summaryView(it run.Item, now time.Time) api.ReportRunSummary {
	r := it.Run
	st := r.EffectiveState(now)
	s := api.ReportRunSummary{
		ID: uuid(r.ID.String()), DefinitionID: r.DefinitionID, DefinitionVersion: int64(r.DefinitionVer), PresetID: strp(r.Preset),
		State: api.ReportRunState(st), CreatedAt: ts(r.CreatedAt), StartedAt: tsp(r.StartedAt), FinishedAt: tsp(r.FinishedAt),
		ExpiresAt: tsp(r.ExpiresAt), AsOf: tsp(r.AsOf), Freshness: freshness(r), EmptyReason: emptyReason(r), Failure: failure(r),
		RerunOf: idp(r.RerunOf), ScopeCurrent: it.ScopeCurrent,
	}
	if it.ScopeCurrent { // a count taken under a scope the caller no longer holds is not shown
		s.RowCount = r.RowCount
	}
	return s
}

// paramsView renders what the run was asked, from the stored request. A parameter set that no longer
// decodes shows as empty rather than failing the read; the columns are the resolved ones.
func paramsView(r run.Run) api.ReportParametersView {
	v := api.ReportParametersView{Columns: append([]string{}, r.Columns...), ConnectionIds: []apitypes.UUID{}, Filters: []api.ReportFilterView{},
		OUExclude: []api.ReportOuRef{}, OUInclude: []api.ReportOuRef{}, Subjects: []api.ReportSubjectRef{}}
	var p api.ReportRunParameters
	if len(r.Params) == 0 || jsonv2.Unmarshal(r.Params, &p) != nil {
		return v
	}
	v.ConnectionIds = append(v.ConnectionIds, p.ConnectionIds...)
	v.OUInclude = append(v.OUInclude, p.OUInclude...)
	v.OUExclude = append(v.OUExclude, p.OUExclude...)
	v.Subjects = append(v.Subjects, p.Subjects...)
	v.Period = p.Period
	if p.IncludeReadOnlyDcs != nil {
		v.IncludeReadOnlyDcs = *p.IncludeReadOnlyDcs
	} else {
		v.IncludeReadOnlyDcs = true
	}
	for _, f := range p.Filters {
		v.Filters = append(v.Filters, filterView(f)...)
	}
	return v
}

// filterView flattens the request filter into the condition/group view. A compare, presence or relative
// filter is one condition; "in" is one condition with several values.
func filterView(f api.ReportFilter) []api.ReportFilterView {
	cond := func(col string, op api.ReportFilterOperatorValue, vs ...api.ReportValue) []api.ReportFilterView {
		if vs == nil {
			vs = []api.ReportValue{}
		}
		return []api.ReportFilterView{{Kind: "condition", Condition: &api.ReportFilterConditionView{Column: col, Kind: "condition", Operator: op, Values: vs}}}
	}
	switch {
	case f.Compare != nil:
		return cond(string(f.Compare.Column), api.ReportFilterOperatorValue(f.Compare.Operator), f.Compare.Value)
	case f.In != nil:
		return cond(string(f.In.Column), api.ReportFilterOperatorValueIn, f.In.Values...)
	case f.Presence != nil:
		op := api.ReportFilterOperatorValueHasValue
		if f.Presence.Presence == api.ReportPresenceEmpty {
			op = api.ReportFilterOperatorValueEmpty
		}
		return cond(string(f.Presence.Column), op)
	case f.RelativeTime != nil:
		op := api.ReportFilterOperatorValue(f.RelativeTime.Relation)
		return cond(string(f.RelativeTime.Column), op, api.ReportValue{Kind: "integer", Integer: &api.ReportValueInteger{Kind: "integer", Value: f.RelativeTime.Days}})
	case f.Group != nil:
		g := &api.ReportFilterGroupView{Kind: "group", Match: api.ReportFilterMatchValue(f.Group.Match), Filters: []api.ReportFilterView{}}
		for _, c := range f.Group.Filters {
			g.Filters = append(g.Filters, filterView(c)...)
		}
		return []api.ReportFilterView{{Kind: "group", Group: g}}
	}
	return nil
}

// ---- stored page -> API ----

var opNames = map[report.Op]api.ReportFilterOperatorValue{
	report.OpEq: api.ReportFilterOperatorValueEquals, report.OpNe: api.ReportFilterOperatorValueNotEquals,
	report.OpLt: api.ReportFilterOperatorValueLessThan, report.OpLe: api.ReportFilterOperatorValueLessOrEqual,
	report.OpGt: api.ReportFilterOperatorValueGreaterThan, report.OpGe: api.ReportFilterOperatorValueGreaterOrEqual,
	report.OpIn: api.ReportFilterOperatorValueIn, report.OpPresent: api.ReportFilterOperatorValueHasValue,
	report.OpAbsent: api.ReportFilterOperatorValueEmpty, report.OpContains: api.ReportFilterOperatorValueContains,
	report.OpPrefix: api.ReportFilterOperatorValueStartsWith, report.OpWithinLastDays: api.ReportFilterOperatorValueWithinLast,
	report.OpOlderThanDays: api.ReportFilterOperatorValueOlderThan, report.OpWithinNextDays: api.ReportFilterOperatorValueWithinNext,
}

func columnInfo(c report.Column) api.ReportColumnInfo {
	t := api.ReportColumnTypeValueText
	switch c.Type {
	case report.TypeInt:
		t = api.ReportColumnTypeValueInteger
	case report.TypeBool:
		t = api.ReportColumnTypeValueBoolean
	case report.TypeTime:
		t = api.ReportColumnTypeValueTime
	case report.TypeEnum:
		t = api.ReportColumnTypeValueEnum
	}
	ops := []api.ReportFilterOperatorValue{}
	for _, o := range c.Filter {
		if n, ok := opNames[o]; ok {
			ops = append(ops, n)
		}
	}
	choices := []api.ReportChoice{}
	for _, e := range c.Enum {
		choices = append(choices, api.ReportChoice{ID: e.ID, Label: e.Label})
	}
	return api.ReportColumnInfo{ID: string(c.ID), Label: c.Label, Type: t, Sortable: c.Sortable, Filterable: len(ops) > 0,
		FilterOperators: ops, DefaultVisible: c.Default, Choices: choices}
}

// cellView maps a stored cell to the contract's tagged cell. The stored JSON form [tag] / [tag, value]
// is the source of truth for the value, so the two cannot drift.
func cellView(c report.Cell) (api.ReportCell, error) {
	b, err := c.MarshalJSON()
	if err != nil {
		return api.ReportCell{}, err
	}
	var parts []jsontext.Value
	if err := jsonv2.Unmarshal(b, &parts); err != nil || len(parts) == 0 {
		return api.ReportCell{}, fmt.Errorf("cell")
	}
	var v jsontext.Value
	if len(parts) > 1 {
		v = parts[1]
	}
	str := func() string { var s string; _ = jsonv2.Unmarshal(v, &s); return s }
	switch c.Tag() {
	case "a":
		return api.ReportCell{Kind: "absent", Absent: &api.ReportCellAbsent{Kind: "absent"}}, nil
	case "n":
		return api.ReportCell{Kind: "never", Never: &api.ReportCellNever{Kind: "never"}}, nil
	case "u":
		return api.ReportCell{Kind: "unknown", Unknown: &api.ReportCellUnknown{Kind: "unknown"}}, nil
	case "s":
		return api.ReportCell{Kind: "text", Text: &api.ReportCellText{Kind: "text", Value: str()}}, nil
	case "i":
		if _, err := strconv.ParseInt(str(), 10, 64); err != nil {
			return api.ReportCell{}, err
		}
		return api.ReportCell{Kind: "integer", Integer: &api.ReportCellInteger{Kind: "integer", Value: str()}}, nil
	case "b":
		var x bool
		_ = jsonv2.Unmarshal(v, &x)
		return api.ReportCell{Kind: "boolean", Boolean: &api.ReportValueBoolean{Kind: "boolean", Value: x}}, nil
	case "t":
		t, err := apitypes.ParseTimestamp(str())
		if err != nil {
			return api.ReportCell{}, err
		}
		return api.ReportCell{Kind: "time", Time: &api.ReportValueTime{Kind: "time", Value: t}}, nil
	case "e":
		return api.ReportCell{Kind: "enum", Enum: &api.ReportValueEnum{Kind: "enum", Value: str()}}, nil
	case "g":
		return api.ReportCell{Kind: "guid", GUID: &api.ReportCellGuid{Kind: "guid", Value: uuid(str())}}, nil
	case "l":
		var l []string
		_ = jsonv2.Unmarshal(v, &l)
		if l == nil {
			l = []string{}
		}
		return api.ReportCell{Kind: "textList", TextList: &api.ReportCellTextList{Kind: "textList", Value: l}}, nil
	}
	return api.ReportCell{}, fmt.Errorf("cell kind")
}

func pageView(p run.Page) (api.ReportRowPage, error) {
	out := api.ReportRowPage{RunID: uuid(p.Run.ID.String()), Columns: []api.ReportColumnInfo{}, Rows: []api.ReportRow{}}
	if p.Run.RowCount != nil {
		out.RowCount = *p.Run.RowCount
	}
	for _, c := range p.Columns {
		out.Columns = append(out.Columns, columnInfo(c))
	}
	for _, r := range p.Rows {
		row := api.ReportRow{RowKey: r.Key, Cells: make([]api.ReportCell, 0, len(r.Cells))}
		for _, c := range r.Cells {
			cv, err := cellView(c)
			if err != nil {
				return api.ReportRowPage{}, err
			}
			row.Cells = append(row.Cells, cv)
		}
		out.Rows = append(out.Rows, row)
	}
	out.Page = apitypes.PageInfo{NextCursor: strp(p.Next)}
	return out, nil
}
