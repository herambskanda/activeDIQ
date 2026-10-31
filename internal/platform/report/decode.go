package report

import (
	"bytes"
	"encoding/json"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// runParamKeys are the only members a run request body may carry. Anything else, such as
// "ldapFilter", "filter" or "sql", is an unknown parameter (FR-05, AC-05).
var runParamKeys = map[string]bool{
	"preset": true, "connections": true, "include": true, "exclude": true, "params": true,
	"filters": true, "columns": true, "sort": true, "showHidden": true, "subjects": true,
}

type rootJSON struct {
	Connection string `json:"connection"`
	Root       string `json:"root"`
	Depth      string `json:"depth"`
}

type sortJSON struct {
	Column ColumnID `json:"column"`
	Dir    string   `json:"dir"`
}

// DecodeRunParams decodes a run request body into typed RunParams and the preset ID. It is strict:
//   - a top-level member it does not know is CodeUnknownParameter, and so is a parameter name the
//     definition does not declare, whatever the value looks like (an LDAP filter string sent as a
//     parameter is refused before its value is read);
//   - every nested object refuses unknown fields; GUIDs must parse; filters decode through
//     UnmarshalExpr; trailing data is refused.
//
// Errors name a place and never echo request text. The result is not yet checked against a
// dataset: Resolve does that.
func DecodeRunParams(data []byte, def Definition) (RunParams, string, error) {
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&top); err != nil || dec.More() {
		return RunParams{}, "", verr(CodeInvalidQuery, "body")
	}
	for k := range top {
		if !runParamKeys[k] {
			return RunParams{}, "", verr(CodeUnknownParameter, safeKey(k))
		}
	}
	var (
		p      RunParams
		preset string
	)
	bad := func(path string) (RunParams, string, error) { return RunParams{}, "", verr(CodeBadValue, path) }
	strict := func(raw json.RawMessage, into any) bool {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		return d.Decode(into) == nil && !d.More()
	}
	if raw, ok := top["preset"]; ok {
		if !strict(raw, &preset) || (preset != "" && !presetIDPattern.MatchString(preset)) {
			return bad("preset")
		}
	}
	guids := func(raw json.RawMessage) ([]authz.ObjectID, bool) {
		var ss []string
		if !strict(raw, &ss) {
			return nil, false
		}
		out := make([]authz.ObjectID, 0, len(ss))
		for _, s := range ss {
			id, err := authz.ParseObjectID(s)
			if err != nil {
				return nil, false
			}
			out = append(out, id)
		}
		return out, true
	}
	var ok bool
	if raw, has := top["connections"]; has {
		if p.Connections, ok = guids(raw); !ok {
			return bad("connections")
		}
	}
	if raw, has := top["subjects"]; has {
		if p.Subjects, ok = guids(raw); !ok {
			return bad("subjects")
		}
	}
	for _, f := range []struct {
		key string
		dst *[]NarrowRoot
	}{{"include", &p.Include}, {"exclude", &p.Exclude}} {
		raw, has := top[f.key]
		if !has {
			continue
		}
		var rs []rootJSON
		if !strict(raw, &rs) {
			return bad(f.key)
		}
		for _, r := range rs {
			c, err1 := authz.ParseObjectID(r.Connection)
			o, err2 := authz.ParseObjectID(r.Root)
			d := map[string]Depth{"subtree": DepthSubtree, "one_level": DepthOneLevel}[r.Depth]
			if err1 != nil || err2 != nil || d == depthInvalid {
				return bad(f.key)
			}
			*f.dst = append(*f.dst, NarrowRoot{c, o, d})
		}
	}
	if raw, has := top["columns"]; has {
		if !strict(raw, &p.Columns) {
			return bad("columns")
		}
	}
	if raw, has := top["showHidden"]; has {
		if !strict(raw, &p.ShowHidden) {
			return bad("showHidden")
		}
	}
	if raw, has := top["sort"]; has {
		var ss []sortJSON
		if !strict(raw, &ss) {
			return bad("sort")
		}
		for _, s := range ss {
			d, ok := ParseSortDir(s.Dir)
			if !ok {
				return RunParams{}, "", verr(CodeBadSort, "sort")
			}
			p.Sort = append(p.Sort, SortKey{s.Column, d})
		}
	}
	if raw, has := top["filters"]; has {
		var parts []json.RawMessage
		if !strict(raw, &parts) {
			return bad("filters")
		}
		for _, part := range parts {
			e, err := UnmarshalExpr(part)
			if err != nil {
				return RunParams{}, "", err
			}
			p.Filters = append(p.Filters, e)
		}
	}
	if raw, has := top["params"]; has {
		var ps map[string]json.RawMessage
		if !strict(raw, &ps) {
			return bad("params")
		}
		p.Params = map[string]ParamValue{}
		// Names first, so an unknown name is refused whatever its value looks like.
		for name := range ps {
			if _, declared := def.param(name); !declared {
				return RunParams{}, "", verr(CodeUnknownParameter, "params."+safeKey(name))
			}
		}
		for name, raw := range ps {
			v, ok := decodeParamValue(raw)
			if !ok {
				return bad("params." + name)
			}
			p.Params[name] = v
		}
	}
	return p, preset, nil
}

func decodeParamValue(raw json.RawMessage) (ParamValue, bool) {
	var m struct {
		Days *int64   `json:"days"`
		Enum *string  `json:"enum"`
		GUID []string `json:"guids"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil || d.More() {
		return ParamValue{}, false
	}
	n := 0
	var v ParamValue
	if m.Days != nil {
		n++
		v = DaysP(*m.Days)
	}
	if m.Enum != nil {
		n++
		v = EnumP(*m.Enum)
	}
	if m.GUID != nil {
		n++
		ids := make([]authz.ObjectID, 0, len(m.GUID))
		for _, s := range m.GUID {
			id, err := authz.ParseObjectID(s)
			if err != nil {
				return ParamValue{}, false
			}
			ids = append(ids, id)
		}
		v = GUIDsP(ids...)
	}
	return v, n == 1
}
