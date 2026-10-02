package main

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// The OpenAPI dialect we write (ADR-0004 rule 2) as a typed model. ParseModel reads the bundle and
// fails on anything outside the rule 2 list before any code is emitted (A2).

const maxSafeInt = 1<<53 - 1

// Schema is one node of the closed dialect.
type Schema struct {
	Ref         string // component schema name when the node is a $ref
	Type        string // string, integer, boolean, object, array; empty for $ref and oneOf
	Nullable    bool   // type: [T, "null"]
	Format      string
	Pattern     string
	Enum        []string
	EnumOpen    bool
	Const       string
	HasConst    bool
	Props       map[string]*Schema
	Required    map[string]bool
	AddlProps   *Schema // a map's value schema
	AddlFalse   bool
	AddlTrue    bool
	Items       *Schema
	OneOf       []string // variant component names
	Discr       string   // discriminator property name
	Min, Max    *int64
	MinLen      *int
	MaxLen      *int
	MinItems    *int
	MaxItems    *int
	MaxProps    *int
	Secret      bool
	WriteOnly   bool
	Description string
	Tag         string // owning tag of a component, empty for shared
	Name        string // component name, empty for an inline node
	Where       string // for messages
}

func (s *Schema) isUnion() bool { return len(s.OneOf) > 0 }
func (s *Schema) isObject() bool {
	return s.Type == "object" && s.Props != nil && s.AddlProps == nil
}
func (s *Schema) isMap() bool  { return s.Type == "object" && s.AddlProps != nil }
func (s *Schema) isEnum() bool { return s.Type == "string" && s.Enum != nil }
func (s *Schema) isScalar() bool {
	return s.Ref == "" && (s.Type == "string" || s.Type == "integer" || s.Type == "boolean") && s.Enum == nil
}

// Param is a path, query or header parameter.
type Param struct {
	Name, In, Where string
	Required        bool
	Schema          *Schema
	Component       string
}

// Body is a request body.
type Body struct {
	Required bool
	Media    string
	Schema   *Schema // a $ref for JSON bodies, nil for binary
	Binary   bool
}

// Resp is one declared response.
type Resp struct {
	Status  int
	Media   string
	Schema  *Schema
	Binary  bool
	Headers []RespHeader
	Problem bool // 4xx/5xx
}

// RespHeader is a declared response header.
type RespHeader struct {
	Name     string
	Required bool
}

// Operation is one path+method of the bundle.
type Operation struct {
	ID, Tag, Method, Path string
	Summary               string
	Permission            string
	Scope                 string
	Stability, Sunset     string
	Anonymous             string
	Deprecated            bool
	Class                 string
	MaxBody               int64
	Params                []*Param
	Body                  *Body
	Responses             []*Resp
	Secret                bool
}

// Problem is one entry of the closed problem catalogue.
type Problem struct {
	Name, Slug, Title string
	Status            int
}

// Model is the validated bundle.
type Model struct {
	Schemas  map[string]*Schema
	Params   map[string]*Param
	Ops      []*Operation
	Tags     []string
	Problems []Problem
	// Reachability, computed by check: which schemas an Input or an Output can contain.
	Req, Resp map[string]bool
	Patch     map[string]bool // merge-patch body schemas
	SecretTy  map[string]bool // schemas whose closure reaches SecretInput

	problemRoots []string // schemas the problem catalogue responses carry
}

var bannedKeywords = map[string]string{
	"anyOf":                 "undecidable or expensive to decode strictly",
	"not":                   "undecidable or expensive to decode strictly",
	"if":                    "undecidable or expensive to decode strictly",
	"then":                  "undecidable or expensive to decode strictly",
	"else":                  "undecidable or expensive to decode strictly",
	"patternProperties":     "undecidable or expensive to decode strictly",
	"$dynamicRef":           "undecidable or expensive to decode strictly",
	"unevaluatedProperties": "undecidable or expensive to decode strictly",
	"allOf":                 "composition hides which members an object has; write the object out or move the shared part to shared/",
	"readOnly":              "use separate request and response schemas instead",
	"default":               "a default is a server behaviour, not a wire fact",
	"uniqueItems":           "not in the dialect",
	"multipleOf":            "not in the dialect",
}

var allowedKeywords = map[string]bool{
	"type": true, "properties": true, "required": true, "additionalProperties": true, "items": true,
	"oneOf": true, "discriminator": true, "const": true, "enum": true, "format": true, "pattern": true,
	"minLength": true, "maxLength": true, "minimum": true, "maximum": true, "minItems": true, "maxItems": true,
	"maxProperties": true, "description": true, "title": true, "examples": true, "deprecated": true,
	"writeOnly": true, "$ref": true, "x-activediq-secret": true, "x-activediq-enum": true, tagExtension: true,
}

var allowedFormats = map[string]bool{"uuid": true, "date": true, "date-time": true, "email": true}

var propNameRe = regexp.MustCompile(`^[a-z][A-Za-z0-9]*$`)

// parser carries the error list while one bundle is read.
type parser struct {
	el *errList
}

func (p *parser) fail(where, format string, a ...any) {
	p.el.addf("%s: %s", where, fmt.Sprintf(format, a...))
}

func asInt(v any) (int64, bool) {
	f, ok := v.(float64)
	if !ok || f != math.Trunc(f) || math.Abs(f) > 1<<62 {
		return 0, false
	}
	return int64(f), true
}

// parseSchema reads one schema node. top is true for a component's own node.
func (p *parser) parseSchema(raw any, where string, top bool) *Schema {
	d, ok := raw.(Doc)
	if !ok {
		p.fail(where, "a schema must be an object")
		return &Schema{Where: where}
	}
	s := &Schema{Where: where}
	for k := range d {
		if why, banned := bannedKeywords[k]; banned {
			p.fail(where, "keyword %q is banned: %s (ADR-0004 rule 2)", k, why)
		} else if strings.HasPrefix(k, "x-") && !allowedKeywords[k] {
			p.fail(where, "extension %q is not one of the rule 3 list", k)
		} else if !allowedKeywords[k] {
			p.fail(where, "keyword %q is outside the rule 2 dialect", k)
		}
	}
	s.Description, _ = d["description"].(string)
	if r, ok := d["$ref"].(string); ok {
		name, found := strings.CutPrefix(r, "#/components/schemas/")
		if !found {
			p.fail(where, "a schema $ref must point at components/schemas (found %q)", r)
		}
		s.Ref = name
		for k := range d {
			if !contains([]string{"$ref", "description", "title", "deprecated", "examples"}, k) {
				p.fail(where, "a $ref may carry only description, title, deprecated and examples beside it (found %q)", k)
			}
		}
		return s
	}
	if t, ok := d[tagExtension].(string); ok {
		s.Tag = t
	}
	s.Secret, _ = d["x-activediq-secret"].(bool)
	s.WriteOnly, _ = d["writeOnly"].(bool)
	if v, ok := d["x-activediq-enum"]; ok {
		if v == "open" {
			s.EnumOpen = true
		} else {
			p.fail(where, "x-activediq-enum must be \"open\"")
		}
	}

	switch t := d["type"].(type) {
	case string:
		s.Type = t
	case []any:
		var nonNull []string
		for _, e := range t {
			es, _ := e.(string)
			if es == "null" {
				s.Nullable = true
			} else {
				nonNull = append(nonNull, es)
			}
		}
		if len(t) != 2 || len(nonNull) != 1 || !s.Nullable {
			p.fail(where, "type may be a name or [T, \"null\"] and nothing else")
		} else {
			s.Type = nonNull[0]
		}
	case nil:
	default:
		p.fail(where, "type must be a string or [T, \"null\"]")
	}
	if s.Type != "" && !contains([]string{"string", "integer", "boolean", "object", "array"}, s.Type) {
		if s.Type == "number" {
			p.fail(where, "type number is banned: there are no floats in v1; an ADR-0004 amendment adds them when an operation needs one")
		} else {
			p.fail(where, "type %q is outside the dialect", s.Type)
		}
		s.Type = ""
	}

	if f, ok := d["format"].(string); ok {
		if !allowedFormats[f] {
			p.fail(where, "format %q is outside the rule 4 list (uuid, date, date-time, email)", f)
		}
		s.Format = f
		if s.Type != "string" {
			p.fail(where, "format applies to string only")
		}
	}
	if pat, ok := d["pattern"].(string); ok {
		s.Pattern = pat
		if _, err := regexp.Compile(pat); err != nil {
			p.fail(where, "pattern does not compile as RE2 (no lookaround, no backreferences): %v", err)
		}
		if s.Type != "string" {
			p.fail(where, "pattern applies to string only")
		}
	}
	if e, ok := d["enum"].([]any); ok {
		if s.Type != "string" {
			p.fail(where, "enum is for string values only")
		}
		seen := map[string]bool{}
		for _, v := range e {
			vs, isStr := v.(string)
			if !isStr || vs == "" {
				p.fail(where, "enum values must be non-empty strings")
				continue
			}
			if seen[vs] {
				p.fail(where, "enum value %q is listed twice", vs)
			}
			seen[vs] = true
			s.Enum = append(s.Enum, vs)
		}
		if len(s.Enum) == 0 {
			p.fail(where, "an enum needs at least one value")
		}
	}
	if c, ok := d["const"]; ok {
		cs, isStr := c.(string)
		if !isStr {
			p.fail(where, "const is for a string kind value only")
		}
		s.Const, s.HasConst = cs, true
	}
	getInt := func(key string) *int64 {
		v, ok := d[key]
		if !ok {
			return nil
		}
		n, isInt := asInt(v)
		if !isInt {
			p.fail(where, "%s must be an integer", key)
			return nil
		}
		return &n
	}
	toInt := func(n *int64) *int {
		if n == nil {
			return nil
		}
		i := int(*n)
		return &i
	}
	s.Min, s.Max = getInt("minimum"), getInt("maximum")
	s.MinLen, s.MaxLen = toInt(getInt("minLength")), toInt(getInt("maxLength"))
	s.MinItems, s.MaxItems = toInt(getInt("minItems")), toInt(getInt("maxItems"))
	s.MaxProps = toInt(getInt("maxProperties"))
	for _, k := range []string{"minLength", "maxLength"} {
		if _, ok := d[k]; ok && s.Type != "string" {
			p.fail(where, "%s applies to string only", k)
		}
	}
	for _, k := range []string{"minimum", "maximum"} {
		if _, ok := d[k]; ok && s.Type != "integer" {
			p.fail(where, "%s applies to integer only", k)
		}
	}
	if s.Type == "integer" {
		if s.Min == nil || s.Max == nil {
			p.fail(where, "an integer declares minimum and maximum (within ±(2^53−1)) so JavaScript cannot round it; use shared Int64String for larger values")
		} else if *s.Min < -maxSafeInt || *s.Max > maxSafeInt || *s.Min > *s.Max {
			p.fail(where, "integer bounds must satisfy −(2^53−1) ≤ minimum ≤ maximum ≤ 2^53−1")
		}
	}

	if r, ok := d["required"].([]any); ok {
		s.Required = map[string]bool{}
		for _, v := range r {
			n, _ := v.(string)
			s.Required[n] = true
		}
	} else if _, has := d["required"]; has {
		p.fail(where, "required must be a list of member names")
	}
	if props, ok := d["properties"].(Doc); ok {
		s.Props = map[string]*Schema{}
		for name, v := range props {
			if !propNameRe.MatchString(name) {
				p.fail(where, "member %q is not camelCase", name)
			}
			s.Props[name] = p.parseSchema(v, where+".properties."+name, false)
		}
		if len(s.Props) > 64 {
			p.fail(where, "an object has at most 64 members (one presence word); split it")
		}
		for r := range s.Required {
			if _, ok := s.Props[r]; !ok {
				p.fail(where, "required names %q, which is not a member", r)
			}
		}
	} else if _, has := d["properties"]; has {
		p.fail(where, "properties must be an object")
	}
	if ap, has := d["additionalProperties"]; has {
		switch v := ap.(type) {
		case bool:
			s.AddlFalse, s.AddlTrue = !v, v
		case Doc:
			s.AddlProps = p.parseSchema(v, where+".additionalProperties", false)
		default:
			p.fail(where, "additionalProperties must be false or a schema")
		}
	}
	if it, has := d["items"]; has {
		s.Items = p.parseSchema(it, where+".items", false)
		if s.Type != "array" {
			p.fail(where, "items applies to type array")
		}
	}
	if oo, has := d["oneOf"].([]any); has {
		for i, v := range oo {
			vs := p.parseSchema(v, fmt.Sprintf("%s.oneOf[%d]", where, i), false)
			if vs.Ref == "" {
				p.fail(where, "every oneOf variant must be a $ref to a named object")
				continue
			}
			s.OneOf = append(s.OneOf, vs.Ref)
		}
		disc, _ := d["discriminator"].(Doc)
		if disc == nil || disc["propertyName"] != "kind" {
			p.fail(where, "oneOf needs a discriminator whose propertyName is \"kind\"")
		} else {
			s.Discr = "kind"
			for k := range disc {
				if k != "propertyName" && k != "mapping" {
					p.fail(where, "discriminator key %q is outside the dialect", k)
				}
			}
		}
		if s.Type != "" {
			p.fail(where, "a oneOf schema declares no type of its own")
		}
	} else if _, has := d["oneOf"]; has {
		p.fail(where, "oneOf must be a list")
	} else if _, has := d["discriminator"]; has {
		p.fail(where, "discriminator without oneOf")
	}

	// Structure.
	switch s.Type {
	case "object":
		switch {
		case s.Props != nil && s.AddlProps != nil:
			p.fail(where, "an object with properties may not also declare additionalProperties: a map has no properties (ADR-0004 rule 2)")
		case s.Props == nil && s.AddlProps == nil:
			p.fail(where, "an object declares properties, or additionalProperties as a map")
		}
		if s.AddlTrue {
			p.fail(where, "additionalProperties: true is not allowed")
		}
	case "array":
		if s.Items == nil {
			p.fail(where, "an array declares items")
		}
	}
	if s.HasConst && !strings.HasSuffix(where, ".properties.kind") {
		p.fail(where, "const is allowed only on a member named kind")
	}
	if s.WriteOnly || s.Secret {
		if !(top && strings.HasSuffix(where, "components.schemas.SecretInput")) {
			p.fail(where, "writeOnly and x-activediq-secret belong to the shared SecretInput schema only")
		}
	}
	if !s.isUnion() && s.Type == "" {
		p.fail(where, "the schema has no type, $ref or oneOf")
	}
	if s.Nullable && !(s.Type == "string" || s.Type == "integer" || s.Type == "boolean") {
		p.fail(where, "only a string, integer or boolean member can be nullable")
	}
	// Inline composites inside a node are limited to scalars, $refs, and arrays or maps of those.
	checkInline := func(n *Schema, what string) {
		if n == nil || n.Ref != "" {
			return
		}
		if !(n.isScalar()) {
			p.fail(where, "%s must be a scalar or a $ref to a named schema", what)
		}
	}
	checkInline(s.Items, "array items")
	checkInline(s.AddlProps, "a map value")
	if !top {
		for name, m := range s.Props {
			switch {
			case m.Ref != "" || m.isScalar():
			case m.Type == "array" || m.isMap():
			default:
				p.fail(where+".properties."+name, "an inline %s is not allowed; define it under components/schemas and $ref it", describe(m))
			}
			if m.isEnum() {
				p.fail(where+".properties."+name, "an inline enum is not allowed; define it under components/schemas and $ref it")
			}
		}
	} else {
		for name, m := range s.Props {
			switch {
			case m.Ref != "" || m.isScalar():
			case m.Type == "array" || m.isMap():
			default:
				p.fail(where+".properties."+name, "an inline %s is not allowed; define it under components/schemas and $ref it", describe(m))
			}
		}
	}
	return s
}

func describe(s *Schema) string {
	switch {
	case s.isUnion():
		return "oneOf"
	case s.isEnum():
		return "enum"
	case s.Type == "object":
		return "object"
	}
	return "schema"
}

// ParseModel reads the bundle into the typed model and runs every dialect and reachability check.
func ParseModel(doc Doc) (*Model, error) {
	el := &errList{}
	p := &parser{el}
	m := &Model{Schemas: map[string]*Schema{}, Params: map[string]*Param{}, Req: map[string]bool{}, Resp: map[string]bool{}, Patch: map[string]bool{}, SecretTy: map[string]bool{}}
	comps, _ := doc["components"].(Doc)
	schemas, _ := comps["schemas"].(Doc)
	for name, raw := range schemas {
		s := p.parseSchema(raw, "components.schemas."+name, true)
		s.Name = name
		m.Schemas[name] = s
	}
	params, _ := comps["parameters"].(Doc)
	for name, raw := range params {
		pm := p.parseParam(raw, "components.parameters."+name, nil)
		if pm != nil {
			pm.Component = name
			m.Params[name] = pm
		}
	}
	m.parseProblems(p, comps)
	m.parseOps(p, doc)
	for _, t := range doc["tags"].([]any) {
		m.Tags = append(m.Tags, t.(Doc)["name"].(string))
	}
	m.check(p)
	if err := el.err(); err != nil {
		return nil, err
	}
	return m, nil
}

func (p *parser) parseParam(raw any, where string, m *Model) *Param {
	d, ok := raw.(Doc)
	if !ok {
		p.fail(where, "a parameter must be an object")
		return nil
	}
	if r, ok := d["$ref"].(string); ok {
		name, found := strings.CutPrefix(r, "#/components/parameters/")
		if !found || m == nil || m.Params[name] == nil {
			p.fail(where, "$ref %q is not a known components/parameters entry", r)
			return nil
		}
		return m.Params[name]
	}
	for k := range d {
		if !contains([]string{"name", "in", "required", "description", "deprecated", "schema", tagExtension}, k) {
			p.fail(where, "parameter key %q is outside the dialect", k)
		}
	}
	pm := &Param{Where: where}
	pm.Name, _ = d["name"].(string)
	pm.In, _ = d["in"].(string)
	pm.Required, _ = d["required"].(bool)
	switch pm.In {
	case "path":
		if !pm.Required {
			p.fail(where, "a path parameter is required")
		}
		if n := strings.ToLower(pm.Name); n == "dn" || n == "distinguishedname" {
			p.fail(where, "a directory object is addressed by objectGUID, never by DN (path parameter %q)", pm.Name)
		}
	case "query", "header":
	default:
		p.fail(where, "parameter location %q is not allowed (path, query, header)", pm.In)
	}
	if pm.Name == "" {
		p.fail(where, "a parameter has a name")
	}
	pm.Schema = p.parseSchema(d["schema"], where+".schema", false)
	if s := pm.Schema; s.Ref == "" {
		ok := s.isScalar() || s.isEnum() || (s.Type == "array" && s.Items != nil && s.Items.Ref == "" && s.Items.isScalar())
		if !ok {
			p.fail(where, "a parameter schema is a scalar, a $ref, or an array of scalars")
		}
	}
	return pm
}

func (m *Model) parseProblems(p *parser, comps Doc) {
	resps, _ := comps["responses"].(Doc)
	names := make([]string, 0, len(resps))
	for n := range resps {
		names = append(names, n)
	}
	sort.Strings(names)
	seen := map[string]string{}
	for _, name := range names {
		where := "components.responses." + name
		rd, _ := resps[name].(Doc)
		content, _ := rd["content"].(Doc)
		pj, _ := content["application/problem+json"].(Doc)
		if pj == nil {
			continue // not a catalogue entry
		}
		if sc, _ := pj["schema"].(Doc); sc != nil {
			if r, ok := sc["$ref"].(string); ok {
				m.problemRoots = append(m.problemRoots, strings.TrimPrefix(r, "#/components/schemas/"))
			}
		}
		ex, _ := pj["example"].(Doc)
		typ, _ := ex["type"].(string)
		title, _ := ex["title"].(string)
		status, sok := asInt(ex["status"])
		slug, ok := strings.CutPrefix(typ, "/problems/")
		if !ok || !regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`).MatchString(slug) || title == "" || !sok || status < 400 || status > 599 {
			p.fail(where, "a problem response carries an example with type /problems/<slug>, a title and a 4xx or 5xx status")
			continue
		}
		if prev, dup := seen[slug]; dup {
			p.fail(where, "problem slug %q is also declared by %s", slug, prev)
			continue
		}
		seen[slug] = name
		m.Problems = append(m.Problems, Problem{Name: name, Slug: slug, Title: title, Status: int(status)})
	}
	sort.Slice(m.Problems, func(i, j int) bool { return m.Problems[i].Slug < m.Problems[j].Slug })
}
