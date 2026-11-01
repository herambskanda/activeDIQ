package reports

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"

	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/report"
)

// Library is what the definition operations read: the shipped report library (package library). It is
// immutable after load, so the handlers hold no state of their own over it.
type Library interface {
	List() []library.Item
	Search(query string, limit int) []library.Match
	Definition(id string, version int) (run.Definition, bool)
}

var _ Library = (*library.Library)(nil)

const (
	defaultDefinitionPage = 50
	// searchAll lifts Library.Search's default cap of 20: the handler pages the whole answer itself.
	searchAll = math.MaxInt32
	// minIntervalPerDC is the least gap between two scheduled runs of a per-DC report (it reads DCs live).
	minIntervalPerDC = 24
	minIntervalOther = 1
)

// categoryOrder is the order the library shows its categories in (spec 6.1).
var categoryOrder = []report.Category{report.CategoryUsers, report.CategoryPasswords, report.CategoryGroups,
	report.CategoryComputers, report.CategoryContacts, report.CategoryOUs}

var categoryNames = map[report.Category]api.ReportCategoryValue{
	report.CategoryUsers:     api.ReportCategoryValueUsers,
	report.CategoryPasswords: api.ReportCategoryValuePasswords,
	report.CategoryGroups:    api.ReportCategoryValueGroups,
	report.CategoryComputers: api.ReportCategoryValueComputers,
	report.CategoryContacts:  api.ReportCategoryValueContacts,
	report.CategoryOUs:       api.ReportCategoryValueOrganizationalUnits,
}

var categoryByAPI = map[api.ReportCategory]report.Category{
	api.ReportCategoryUsers:               report.CategoryUsers,
	api.ReportCategoryPasswords:           report.CategoryPasswords,
	api.ReportCategoryGroups:              report.CategoryGroups,
	api.ReportCategoryComputers:           report.CategoryComputers,
	api.ReportCategoryContacts:            report.CategoryContacts,
	api.ReportCategoryOrganizationalUnits: report.CategoryOUs,
}

func categoryRank(c report.Category) int {
	if i := slices.Index(categoryOrder, c); i >= 0 {
		return i
	}
	return len(categoryOrder)
}

// before is the library's display order: category, then name, then ID (so the order is total).
func before(a, b report.Definition) bool {
	if ra, rb := categoryRank(a.Category), categoryRank(b.Category); ra != rb {
		return ra < rb
	}
	if na, nb := strings.ToLower(a.Title), strings.ToLower(b.Title); na != nb {
		return na < nb
	}
	if a.Title != b.Title {
		return a.Title < b.Title
	}
	return a.ID < b.ID
}

func (h *Handlers) library() (Library, error) {
	if h.Library == nil {
		return nil, apitypes.NotReady("the report library is not available on this installation")
	}
	return h.Library, nil
}

// ListReportDefinitions implements api.Handlers: the newest version of every shipped report, in the
// library's order (category, then name), filtered by category and by q, a page at a time. The library holds
// no tenant data and a caller's scope narrows what a run returns, never which reports exist, so the
// route's reports.run permission is the whole check.
func (h *Handlers) ListReportDefinitions(_ context.Context, in api.ListReportDefinitionsInput) (api.ListReportDefinitionsOutput, error) {
	lib, err := h.library()
	if err != nil {
		return nil, err
	}
	items := lib.List()
	var cat report.Category
	if in.Category != nil {
		c, ok := categoryByAPI[*in.Category]
		if !ok {
			return nil, coded(apitypes.Validation("the category is not one of the library's"), apitypes.InQuery, "category", "bad_category", "")
		}
		cat = c
	}
	var hits map[report.DefinitionID][]string // matched preset IDs per report; nil means no search
	if in.Q != nil {
		hits = findReports(lib, items, *in.Q)
	}
	sel := make([]library.Item, 0, len(items))
	for _, it := range items {
		if cat != "" && it.Def.Category != cat {
			continue
		}
		if hits != nil {
			if _, ok := hits[it.Def.ID]; !ok {
				continue
			}
		}
		sel = append(sel, it)
	}
	sort.Slice(sel, func(i, j int) bool { return before(sel[i].Def, sel[j].Def) })

	if in.Cursor != nil {
		last, err := decodeDefinitionCursor(string(*in.Cursor), items)
		if err != nil {
			return nil, err
		}
		i := sort.Search(len(sel), func(i int) bool { return before(last, sel[i].Def) })
		sel = sel[i:]
	}
	limit := defaultDefinitionPage
	if in.Limit != nil {
		limit = int(*in.Limit)
	}
	var next *string
	if len(sel) > limit {
		c := encodeDefinitionCursor(sel[limit-1].Def.ID)
		next = &c
		sel = sel[:limit]
	}
	out := api.ReportDefinitionList{Items: make([]api.ReportDefinitionSummary, 0, len(sel)), Page: apitypes.PageInfo{NextCursor: next}}
	for _, it := range sel {
		rd, ok := lib.Definition(string(it.Def.ID), it.Def.Version)
		if !ok {
			h.log().Error("reports: a listed definition is not in the library", "definition", it.Def.Key())
			return nil, apitypes.Internal("")
		}
		sum, err := summaryOf(rd, hits[it.Def.ID])
		if err != nil {
			h.log().Error("reports: a shipped definition could not be rendered", "definition", it.Def.Key(), "err", err)
			return nil, apitypes.Internal("")
		}
		out.Items = append(out.Items, sum)
	}
	return api.ListReportDefinitions200{Body: out}, nil
}

// findReports answers q: the reports whose ManageEngine name, title or ID the library search matches
// (a name that leads nowhere yet, because its report or preset is not shipped, finds nothing), and the
// reports whose title or description holds every word of q. The value is the presets whose ME name matched,
// so the listing can show the matched name first.
func findReports(lib Library, items []library.Item, q string) map[report.DefinitionID][]string {
	hits := map[report.DefinitionID][]string{}
	for _, m := range lib.Search(q, searchAll) {
		if !m.Available {
			continue
		}
		if m.Name != "" && !slices.Contains(hits[m.Report], m.Preset) {
			hits[m.Report] = append(hits[m.Report], m.Preset)
		} else if _, ok := hits[m.Report]; !ok {
			hits[m.Report] = nil
		}
	}
	words := strings.Fields(strings.ToLower(q))
	if len(words) == 0 {
		return hits
	}
	for _, it := range items {
		text := strings.ToLower(it.Def.Title + " " + it.Def.Description)
		if !slices.ContainsFunc(words, func(w string) bool { return !strings.Contains(text, w) }) {
			if _, ok := hits[it.Def.ID]; !ok {
				hits[it.Def.ID] = nil
			}
		}
	}
	return hits
}

// The cursor names the last report of the page. It is opaque to clients; the next page is every report
// that sorts after it, so a change of the library between two calls cannot repeat or skip a report that
// is still there.
const cursorPrefix = "defs1:"

func encodeDefinitionCursor(id report.DefinitionID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + string(id)))
}

func decodeDefinitionCursor(c string, items []library.Item) (report.Definition, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if id, ok := strings.CutPrefix(string(raw), cursorPrefix); err == nil && ok {
		for _, it := range items {
			if string(it.Def.ID) == id {
				return it.Def, nil
			}
		}
	}
	return report.Definition{}, coded(apitypes.Validation("the cursor is not valid"), apitypes.InQuery, "cursor", "bad_cursor", "")
}

// GetReportDefinition implements api.Handlers: one definition at its newest or a named version.
func (h *Handlers) GetReportDefinition(_ context.Context, in api.GetReportDefinitionInput) (api.GetReportDefinitionOutput, error) {
	lib, err := h.library()
	if err != nil {
		return nil, err
	}
	version := 0
	if in.Version != nil {
		version = int(*in.Version)
	}
	d, ok := lib.Definition(in.DefinitionID, version)
	if !ok {
		return nil, coded(apitypes.NotFound("no such report"), apitypes.InPath, "definitionId", "definition_not_found", "")
	}
	body, err := definitionView(d, h.Exports != nil)
	if err != nil {
		h.log().Error("reports: a shipped definition could not be rendered", "definition", d.Def.Key(), "err", err)
		return nil, apitypes.Internal("")
	}
	return api.GetReportDefinition200{Body: body}, nil
}

// ---- library -> API ----

// alsoKnownAs lists the ManageEngine names the report's presets answer, in preset order. A preset in
// matched comes first, so a search shows the name it found at the head of the line (FR-02).
func alsoKnownAs(d report.Definition, matched []string) []api.ReportMeName {
	out := []api.ReportMeName{}
	add := func(wantMatched bool) {
		for _, p := range d.Presets {
			if slices.Contains(matched, p.ID) != wantMatched {
				continue
			}
			for _, n := range p.Names {
				out = append(out, api.ReportMeName{MeName: n, PresetID: p.ID})
			}
		}
	}
	add(true)
	add(false)
	return out
}

func summaryOf(rd run.Definition, matched []string) (api.ReportDefinitionSummary, error) {
	d := rd.Def
	kind, ok := freshnessKinds[rd.Dataset.Freshness]
	if !ok {
		return api.ReportDefinitionSummary{}, fmt.Errorf("dataset %s has no freshness kind", d.Dataset)
	}
	cat, ok := categoryNames[d.Category]
	if !ok {
		return api.ReportDefinitionSummary{}, fmt.Errorf("category %s has no API name", d.Category)
	}
	return api.ReportDefinitionSummary{ID: string(d.ID), Version: int64(d.Version), Name: d.Title, Description: d.Description,
		Category: cat, Dataset: string(d.Dataset), FreshnessKind: kind, AlsoKnownAs: alsoKnownAs(d, matched)}, nil
}

// freshnessKinds name the watermark a dataset's rows are as current as.
var freshnessKinds = map[report.FreshnessSource]string{
	report.FreshNCWatermark: "nc_watermark",
	report.FreshPolicyRead:  "policy_read",
	report.FreshPerDC:       "per_dc",
}

// exportFormats are the formats this installation can produce for d: none without an export service, and
// no PDF when the report (any of its presets) has more columns than a PDF page lays out.
func exportFormats(d report.Definition, exports bool) []api.ReportExportFormatValue {
	out := []api.ReportExportFormatValue{}
	if !exports {
		return out
	}
	widest := len(d.Columns)
	for _, p := range d.Presets {
		widest = max(widest, len(p.Columns))
	}
	for _, f := range export.FormatsFor(widest) {
		out = append(out, api.ReportExportFormatValue(f))
	}
	return out
}

func definitionView(rd run.Definition, exports bool) (api.ReportDefinition, error) {
	d := rd.Def
	s, err := summaryOf(rd, nil)
	if err != nil {
		return api.ReportDefinition{}, err
	}
	out := api.ReportDefinition{ID: s.ID, Version: s.Version, Name: s.Name, Description: s.Description, Category: s.Category,
		Dataset: s.Dataset, AlsoKnownAs: s.AlsoKnownAs, FreshnessKind: s.FreshnessKind,
		Presets: []api.ReportPreset{}, Columns: columnsOf(d, rd.Dataset),
		ExportFormats: exportFormats(d, exports), SubjectKind: "none", PerDc: d.PerDC != nil,
		MinScheduleIntervalHours: minIntervalOther}
	if d.PerDC != nil {
		out.MinScheduleIntervalHours = minIntervalPerDC
	}
	for _, p := range d.Presets {
		if p.Requires != nil {
			out.SubjectKind = "object" // the objects are named by GUID; which kind is the dataset's
		}
		pv, err := presetView(d, p)
		if err != nil {
			return api.ReportDefinition{}, fmt.Errorf("preset %s: %w", p.ID, err)
		}
		out.Presets = append(out.Presets, pv)
	}
	return out, nil
}

// columnsOf lists every column a run of the definition may show, filter or sort by: the default columns
// first, in order, then the rest of the dataset. A per-DC column is offered only to a per-DC report.
func columnsOf(d report.Definition, ds report.Dataset) []api.ReportColumnInfo {
	out := []api.ReportColumnInfo{}
	add := func(c report.Column, visible bool) {
		ci := columnInfo(c)
		ci.DefaultVisible = visible
		out = append(out, ci)
	}
	for _, id := range d.Columns {
		if c, ok := ds.Column(id); ok {
			add(c, true)
		}
	}
	for _, c := range ds.Columns {
		if slices.Contains(d.Columns, c.ID) || (c.IsPerDC() && d.PerDC == nil) {
			continue
		}
		add(c, false)
	}
	return out
}

func presetView(d report.Definition, p report.Preset) (api.ReportPreset, error) {
	pv := api.ReportPreset{ID: p.ID, Name: p.ID, Filters: []api.ReportFilterView{}, Columns: []string{}}
	if len(p.Names) > 0 {
		pv.Name = p.Names[0]
		n := p.Names[0]
		pv.MeName = &n
	}
	cols := d.Columns
	if p.Columns != nil {
		cols = p.Columns
	}
	for _, c := range cols {
		pv.Columns = append(pv.Columns, string(c))
	}
	if p.Where != nil {
		terms := []report.Expr{p.Where}
		if a, ok := p.Where.(report.And); ok {
			terms = a.Terms // a preset's filters are all required, so the top-level AND is the list
		}
		for _, t := range terms {
			fv, err := filterOf(t, d)
			if err != nil {
				return api.ReportPreset{}, err
			}
			pv.Filters = append(pv.Filters, fv)
		}
		pv.PeriodDays = periodDays(p.Where, d)
	}
	return pv, nil
}

// periodDays is the default of the first days parameter the preset's filter reads, the number the console
// shows as the preset's period.
func periodDays(e report.Expr, d report.Definition) *int64 {
	var name string
	var walk func(report.Expr)
	walk = func(e report.Expr) {
		if name != "" {
			return
		}
		switch x := e.(type) {
		case report.And:
			for _, t := range x.Terms {
				walk(t)
			}
		case report.Or:
			for _, t := range x.Terms {
				walk(t)
			}
		case report.Not:
			walk(x.Term)
		case report.Cmp:
			if x.Param != "" {
				if spec, ok := paramSpec(d, x.Param); ok && spec.Kind == report.ParamDays {
					name = x.Param
				}
			}
		}
	}
	walk(e)
	if spec, ok := paramSpec(d, name); ok && spec.Default != nil {
		n := spec.Default.Days()
		return &n
	}
	return nil
}

func paramSpec(d report.Definition, name string) (report.ParamSpec, bool) {
	for _, p := range d.Params {
		if p.Name == name {
			return p, true
		}
	}
	return report.ParamSpec{}, false
}

// filterOf renders a preset's expression as the API's condition/group tree. A parameter reference shows
// the parameter's default, which is what the preset opens with.
func filterOf(e report.Expr, d report.Definition) (api.ReportFilterView, error) {
	group := func(match api.ReportFilterMatchValue, terms ...report.Expr) (api.ReportFilterView, error) {
		g := &api.ReportFilterGroupView{Kind: "group", Match: match, Filters: []api.ReportFilterView{}}
		for _, t := range terms {
			fv, err := filterOf(t, d)
			if err != nil {
				return api.ReportFilterView{}, err
			}
			g.Filters = append(g.Filters, fv)
		}
		return api.ReportFilterView{Kind: "group", Group: g}, nil
	}
	switch x := e.(type) {
	case report.And:
		return group(api.ReportFilterMatchValueAll, x.Terms...)
	case report.Or:
		return group(api.ReportFilterMatchValueAny, x.Terms...)
	case report.Not:
		if or, ok := x.Term.(report.Or); ok {
			return group(api.ReportFilterMatchValueNone, or.Terms...)
		}
		return group(api.ReportFilterMatchValueNone, x.Term)
	case report.Cmp:
		op, ok := opNames[x.Op]
		if !ok {
			return api.ReportFilterView{}, fmt.Errorf("operator %s has no API name", x.Op)
		}
		vs := []api.ReportValue{}
		var raw []report.Value
		switch {
		case x.Param != "":
			spec, ok := paramSpec(d, x.Param)
			if !ok || spec.Default == nil {
				break // a required parameter has no default: the filter shows no value until the run sets one
			}
			switch spec.Kind {
			case report.ParamDays:
				raw = append(raw, report.IntV(spec.Default.Days()))
			case report.ParamEnum:
				raw = append(raw, report.EnumV(spec.Default.Enum()))
			default:
				return api.ReportFilterView{}, fmt.Errorf("parameter %s of this kind cannot be a filter value", x.Param)
			}
		case x.Values != nil:
			raw = x.Values
		case x.Value.Type() != report.TypeInvalid:
			raw = []report.Value{x.Value}
		}
		for _, v := range raw {
			av, err := valueView(v)
			if err != nil {
				return api.ReportFilterView{}, err
			}
			vs = append(vs, av)
		}
		return api.ReportFilterView{Kind: "condition", Condition: &api.ReportFilterConditionView{
			Kind: "condition", Column: string(x.Column), Operator: op, Values: vs}}, nil
	}
	return api.ReportFilterView{}, fmt.Errorf("unknown expression %T", e)
}

func valueView(v report.Value) (api.ReportValue, error) {
	switch v.Type() {
	case report.TypeText:
		return api.ReportValue{Kind: "text", Text: &api.ReportValueText{Kind: "text", Value: v.Text()}}, nil
	case report.TypeInt:
		return api.ReportValue{Kind: "integer", Integer: &api.ReportValueInteger{Kind: "integer", Value: v.Int()}}, nil
	case report.TypeBool:
		return api.ReportValue{Kind: "boolean", Boolean: &api.ReportValueBoolean{Kind: "boolean", Value: v.Bool()}}, nil
	case report.TypeTime:
		return api.ReportValue{Kind: "time", Time: &api.ReportValueTime{Kind: "time", Value: ts(v.Time())}}, nil
	case report.TypeEnum:
		return api.ReportValue{Kind: "enum", Enum: &api.ReportValueEnum{Kind: "enum", Value: v.Text()}}, nil
	}
	return api.ReportValue{}, fmt.Errorf("a %s value has no API form", v.Type())
}
