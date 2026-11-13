package library

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

// The shipped file format. One file holds one (ID, version). Decoding is strict: a member this type does
// not name is an error, so a typo in a definition stops start-up instead of being ignored (contract 3.6).
// Expressions use the same tagged JSON as a run request (report.UnmarshalExpr).

type fileDef struct {
	ID          string       `json:"id"`
	Version     int          `json:"version"`
	Category    string       `json:"category"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Dataset     string       `json:"dataset"`
	Columns     []string     `json:"columns"`
	Sort        []fileSort   `json:"sort"`
	Presets     []filePreset `json:"presets"`
	Params      []fileParam  `json:"params"`
	Caveats     []string     `json:"caveats"`
	PerDC       *filePerDC   `json:"perDC"`
}

// filePerDC marks a report that reads per-DC attributes live; Scope is "all" (read-only DCs included, the
// default of spec 6.5) or "writable".
type filePerDC struct {
	Scope string `json:"scope"`
}

type fileSort struct {
	Column string `json:"column"`
	Dir    string `json:"dir"`
}

type filePreset struct {
	ID       string         `json:"id"`
	Names    []string       `json:"names"`
	Where    jsontext.Value `json:"where"`
	Hidden   []fileHidden   `json:"hidden"`
	Columns  []string       `json:"columns"`
	Sort     []fileSort     `json:"sort"`
	Top      int            `json:"top"`
	Requires *fileSubjects  `json:"requires"`
}

type fileHidden struct {
	ID     string         `json:"id"`
	Label  string         `json:"label"`
	Where  jsontext.Value `json:"where"`
	Locked bool           `json:"locked"`
}

type fileSubjects struct {
	Min    int    `json:"min"`
	Max    int    `json:"max"`
	Column string `json:"column"`
	Kind   string `json:"kind"`
}

type fileParam struct {
	Name     string        `json:"name"`
	Kind     string        `json:"kind"`
	Default  *fileParamVal `json:"default"`
	Min      int64         `json:"min"`
	Max      int64         `json:"max"`
	Choices  []string      `json:"choices"`
	Required bool          `json:"required"`
}

type fileParamVal struct {
	Days *int64  `json:"days"`
	Enum *string `json:"enum"`
}

// Decode reads one shipped definition file. It checks the shape and the structure of the definition
// (report.Definition.Validate); the names are checked against the dataset by the loader.
func Decode(data []byte) (report.Definition, error) {
	var f fileDef
	if err := json.Unmarshal(data, &f, json.RejectUnknownMembers(true)); err != nil {
		return report.Definition{}, fmt.Errorf("library: definition file is not valid: %w", err)
	}
	d := report.Definition{
		ID:          report.DefinitionID(f.ID),
		Version:     f.Version,
		Category:    report.Category(f.Category),
		Title:       f.Title,
		Description: f.Description,
		Dataset:     report.DatasetID(f.Dataset),
	}
	for _, c := range f.Columns {
		d.Columns = append(d.Columns, report.ColumnID(c))
	}
	var err error
	if d.Sort, err = sortKeys(f.Sort); err != nil {
		return report.Definition{}, err
	}
	if f.PerDC != nil {
		switch f.PerDC.Scope {
		case "all":
			d.PerDC = &report.PerDCSpec{Scope: report.ScopeAll}
		case "writable":
			d.PerDC = &report.PerDCSpec{Scope: report.ScopeWritable}
		default:
			return report.Definition{}, errors.New("library: perDC scope is all or writable")
		}
	}
	for _, c := range f.Caveats {
		d.Caveats = append(d.Caveats, report.CaveatID(c))
	}
	for _, p := range f.Params {
		ps, err := param(p)
		if err != nil {
			return report.Definition{}, err
		}
		d.Params = append(d.Params, ps)
	}
	for _, p := range f.Presets {
		pr, err := preset(p)
		if err != nil {
			return report.Definition{}, err
		}
		d.Presets = append(d.Presets, pr)
	}
	if err := d.Validate(); err != nil {
		return report.Definition{}, err
	}
	return d, nil
}

func sortKeys(in []fileSort) ([]report.SortKey, error) {
	var out []report.SortKey
	for _, s := range in {
		dir, ok := report.ParseSortDir(s.Dir)
		if !ok {
			return nil, errors.New("library: a sort key has no direction asc or desc")
		}
		out = append(out, report.SortKey{Column: report.ColumnID(s.Column), Dir: dir})
	}
	return out, nil
}

func expr(raw jsontext.Value) (report.Expr, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	return report.UnmarshalExpr(raw)
}

func preset(p filePreset) (report.Preset, error) {
	out := report.Preset{ID: p.ID, Names: p.Names, Top: p.Top}
	var err error
	if out.Where, err = expr(p.Where); err != nil {
		return report.Preset{}, fmt.Errorf("library: preset %q where: %w", p.ID, err)
	}
	for _, h := range p.Hidden {
		w, err := expr(h.Where)
		if err != nil {
			return report.Preset{}, fmt.Errorf("library: preset %q hidden %q: %w", p.ID, h.ID, err)
		}
		out.Hidden = append(out.Hidden, report.HiddenGroup{ID: h.ID, Label: h.Label, Where: w, Locked: h.Locked})
	}
	for _, c := range p.Columns {
		out.Columns = append(out.Columns, report.ColumnID(c))
	}
	if out.Sort, err = sortKeys(p.Sort); err != nil {
		return report.Preset{}, err
	}
	if p.Requires != nil {
		out.Requires = &report.Subjects{Min: p.Requires.Min, Max: p.Requires.Max, Column: report.ColumnID(p.Requires.Column), Kind: p.Requires.Kind}
	}
	return out, nil
}

func param(p fileParam) (report.ParamSpec, error) {
	out := report.ParamSpec{Name: p.Name, Min: p.Min, Max: p.Max, Choices: p.Choices, Required: p.Required}
	switch p.Kind {
	case "days":
		out.Kind = report.ParamDays
	case "enum":
		out.Kind = report.ParamEnum
	case "guids":
		out.Kind = report.ParamGUIDList
	default:
		return report.ParamSpec{}, fmt.Errorf("library: parameter %q has an unknown kind", p.Name)
	}
	if p.Default != nil {
		switch {
		case p.Default.Days != nil && p.Default.Enum == nil && out.Kind == report.ParamDays:
			v := report.DaysP(*p.Default.Days)
			out.Default = &v
		case p.Default.Enum != nil && p.Default.Days == nil && out.Kind == report.ParamEnum:
			v := report.EnumP(*p.Default.Enum)
			out.Default = &v
		default:
			return report.ParamSpec{}, fmt.Errorf("library: the default of parameter %q does not fit its kind", p.Name)
		}
	}
	return out, nil
}
