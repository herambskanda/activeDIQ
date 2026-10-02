package main

import (
	"sort"
	"strconv"
	"strings"
)

const (
	pJSON    = "encoding/json/v2"
	pJSONTxt = "encoding/json/jsontext"
)

func (u *unit) resolve(s *Schema) *Schema {
	if s.Ref != "" {
		return u.m.Schemas[s.Ref]
	}
	return s
}

// sliceLike reports whether a member schema is an array or map, which are optional by being nil.
func (u *unit) sliceLike(s *Schema) bool {
	r := u.resolve(s)
	return r.Type == "array" || r.isMap()
}

// goType is the Go type of a schema node, never a pointer.
func (f *gofile) goType(s *Schema) string {
	if s.Ref != "" {
		return f.ref(s.Ref)
	}
	switch {
	case s.Type == "array":
		return "[]" + f.goType(s.Items)
	case s.isMap():
		return "map[string]" + f.goType(s.AddlProps)
	case s.Type == "string":
		switch s.Format {
		case "uuid":
			return f.apit("UUID")
		case "date":
			return f.apit("Date")
		case "date-time":
			return f.apit("Timestamp")
		}
		return "string"
	case s.Type == "integer":
		return "int64"
	case s.Type == "boolean":
		return "bool"
	}
	panic("goType: unsupported schema at " + s.Where)
}

// field is one member of a generated struct.
type field struct {
	JSON, Go string
	Idx      int
	Prop     *Schema
	Req      bool
	Kind     string // plain, nullptr, optptr, optslice, opt
	Typ      string
}

func (u *unit) fields(f *gofile, s *Schema) []field {
	names := sortedKeys(s.Props)
	patch := u.m.Patch[s.Name]
	out := make([]field, 0, len(names))
	for i, n := range names {
		p := s.Props[n]
		fd := field{JSON: n, Go: goIdent(n), Idx: i, Prop: p, Req: s.Required[n]}
		base := f.goType(p)
		switch {
		case fd.Req && p.Nullable:
			fd.Kind, fd.Typ = "nullptr", "*"+base
		case fd.Req:
			fd.Kind, fd.Typ = "plain", base
		case patch:
			fd.Kind, fd.Typ = "opt", f.apit("Opt")+"["+base+"]"
		case u.sliceLike(p):
			fd.Kind, fd.Typ = "optslice", base
		default:
			fd.Kind, fd.Typ = "optptr", "*"+base
		}
		out = append(out, fd)
	}
	return out
}

func (u *unit) emitSchema(f *gofile, s *Schema) {
	doc := func() {
		desc := strings.TrimSpace(s.Description)
		if desc == "" {
			f.p("// %s is the %s schema.\n", s.Name, s.Name)
			return
		}
		lines := strings.Split(desc, "\n")
		for i, l := range lines {
			if i == 0 && !strings.HasPrefix(l, s.Name) {
				l = s.Name + ": " + l
			}
			f.p("// %s\n", strings.TrimSpace(l))
		}
	}
	switch {
	case s.isUnion():
		doc()
		u.emitUnion(f, s)
	case s.isObject():
		doc()
		u.emitObject(f, s)
	case s.isMap():
		doc()
		u.emitMap(f, s)
	case s.Type == "array":
		doc()
		u.emitArray(f, s)
	case s.isEnum():
		doc()
		u.emitEnum(f, s)
	default:
		doc()
		switch {
		case s.Format == "uuid" || s.Format == "date" || s.Format == "date-time":
			f.p("type %s = %s\n\n", s.Name, f.goType(&Schema{Type: "string", Format: s.Format}))
		case s.Type == "string":
			f.p("type %s string\n\n", s.Name)
		case s.Type == "integer":
			f.p("type %s int64\n\n", s.Name)
		case s.Type == "boolean":
			f.p("type %s bool\n\n", s.Name)
		}
	}
}

func (u *unit) emitEnum(f *gofile, s *Schema) {
	f.p("type %s string\n\nconst (\n", s.Name)
	seen := map[string]string{}
	for _, v := range s.Enum {
		c := s.Name + goIdent(v)
		if prev, dup := seen[c]; dup {
			u.errs.addf("%s: enum values %q and %q give the same Go constant %s", s.Where, prev, v, c)
		}
		seen[c] = v
		u.claim(c, "enum value "+s.Name+"."+v)
		f.p("\t%s %s = %q\n", c, s.Name, v)
	}
	f.p(")\n\n")
	if s.EnumOpen {
		f.p("// Valid reports whether v is a value this build knows. Clients and responses may carry others\n// (the enum is open), so no generated code rejects an unknown value.\n")
	} else {
		f.p("// Valid reports whether v is one of the closed set of values.\n")
	}
	f.p("func (v %s) Valid() bool {\n\tswitch v {\n\tcase ", s.Name)
	cs := make([]string, len(s.Enum))
	for i, v := range s.Enum {
		cs[i] = s.Name + goIdent(v)
	}
	f.p("%s:\n\t\treturn true\n\t}\n\treturn false\n}\n\n", strings.Join(cs, ", "))
	if !s.EnumOpen {
		f.p("// Validate records a violation when v is not in the set.\nfunc (v %s) Validate(at %s.Pointer, errs *%s) {\n\tif !v.Valid() {\n\t\terrs.AddBody(at, %s, %q)\n\t}\n}\n\n",
			s.Name, strings.TrimSuffix(f.use(pJSONTxt), "."), f.apit("Errors"), f.apit("CodeEnum"), "value is not one of the allowed values")
	}
}

func (u *unit) emitObject(f *gofile, s *Schema) {
	fs := u.fields(f, s)
	jt := strings.TrimSuffix(f.use(pJSONTxt), ".")
	js := strings.TrimSuffix(f.use(pJSON), ".")
	f.p("type %s struct {\n", s.Name)
	for _, fd := range fs {
		tag := fd.JSON
		if !fd.Req {
			tag += ",omitzero"
		}
		if d := strings.TrimSpace(fd.Prop.Description); d != "" {
			f.p("\t// %s\n", strings.ReplaceAll(d, "\n", " "))
		}
		u.claimField(s, fd)
		f.p("\t%s %s `json:%q`\n", fd.Go, fd.Typ, tag)
	}
	if len(fs) > 0 {
		f.p("\n")
	}
	f.p("\tp %s\n}\n\n", f.apit("Presence"))

	// Decoder.
	f.p("// UnmarshalJSONFrom decodes the object strictly: member names match exactly and an unknown\n// member is an error. Nested values decode through the caller's options.\n")
	f.p("func (v *%s) UnmarshalJSONFrom(d *%s.Decoder) error {\n\t*v = %s{}\n\tv.p.Begin()\n\tif err := %s; err != nil {\n\t\treturn err\n\t}\n\tfor {\n\t\tname, ok, err := %s\n\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif !ok {\n\t\t\treturn nil\n\t\t}\n\t\tswitch name {\n",
		s.Name, jt, s.Name, f.apit("ObjectStart(d)"), f.apit("NextMember(d)"))
	for _, fd := range fs {
		f.p("\t\tcase %q:\n", fd.JSON)
		switch fd.Kind {
		case "plain", "optptr", "optslice":
			f.p("\t\t\tnull, err := %s\n\t\t\tif err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t\tv.p.Mark(%d, null)\n\t\t\tif null {\n\t\t\t\tcontinue\n\t\t\t}\n", f.apit("TakeNull(d)"), fd.Idx)
		default:
			f.p("\t\t\tv.p.Mark(%d, false)\n", fd.Idx)
		}
		rp := fd.Prop
		switch {
		case fd.Kind != "opt" && rp.Type == "array" && rp.Ref == "":
			f.p("\t\t\tif err := %s(d, &v.%s); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n", f.apit("DecodeArray"), fd.Go)
		case fd.Kind != "opt" && rp.isMap() && rp.Ref == "":
			f.p("\t\t\tif err := %s(d, &v.%s); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n", f.apit("DecodeMap"), fd.Go)
		default:
			f.p("\t\t\tif err := %s.UnmarshalDecode(d, &v.%s); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n", js, fd.Go)
		}
	}
	f.p("\t\tdefault:\n\t\t\treturn %s\n\t\t}\n\t}\n}\n\n", f.apit("UnknownMember(d)"))

	// Validator.
	f.p("// Validate records every violation of the object's schema under at: missing required members,\n// null on a non-nullable member, bounds, patterns and closed enums.\n")
	f.p("func (v *%s) Validate(at %s.Pointer, errs *%s) {\n", s.Name, jt, f.apit("Errors"))
	if len(fs) == 0 {
		f.p("\t_, _ = at, errs\n")
	}
	for _, fd := range fs {
		u.emitFieldValidation(f, s, fd)
	}
	f.p("}\n\n")

	if u.m.SecretTy[s.Name] {
		f.p("// DestroySecrets destroys every secret the object holds.\nfunc (v *%s) DestroySecrets() {\n", s.Name)
		for _, fd := range fs {
			if u.reachesSecret(fd.Prop) {
				switch fd.Kind {
				case "nullptr", "optptr":
					f.p("\tif v.%s != nil {\n", fd.Go)
					u.emitDestroy(f, "(*v."+fd.Go+")", fd.Prop, 2)
					f.p("\t}\n")
				case "opt":
					f.p("\tif p := v.%s.Ptr(); p != nil {\n", fd.Go)
					u.emitDestroy(f, "(*p)", fd.Prop, 2)
					f.p("\t}\n")
				default:
					u.emitDestroy(f, "v."+fd.Go, fd.Prop, 1)
				}
			}
		}
		f.p("}\n\n")
	}
}

func (u *unit) claimField(s *Schema, fd field) {
	// Field names are scoped to their struct; a collision is two members mapping to one Go name.
	for _, o := range sortedKeys(s.Props) {
		if o != fd.JSON && goIdent(o) == fd.Go && o < fd.JSON {
			u.errs.addf("%s: members %q and %q give the same Go field name %s", s.Where, o, fd.JSON, fd.Go)
		}
	}
}

func (u *unit) reachesSecret(s *Schema) bool {
	for _, r := range refsOf(s) {
		if u.m.SecretTy[r] {
			return true
		}
	}
	return false
}

// emitDestroy writes the clean-up of one value of schema s held in expr.
func (u *unit) emitDestroy(f *gofile, expr string, s *Schema, depth int) {
	ind := strings.Repeat("\t", depth)
	switch {
	case s.Ref != "":
		if b := u.binding(s.Ref); b != nil {
			if b.Secret {
				f.p("%s%s.Destroy()\n", ind, expr)
			}
		} else if u.m.SecretTy[s.Ref] {
			f.p("%s%s.DestroySecrets()\n", ind, expr)
		}
	case s.Type == "array":
		f.p("%sfor i := range %s {\n", ind, expr)
		u.emitDestroy(f, expr+"[i]", s.Items, depth+1)
		f.p("%s}\n", ind)
	case s.isMap():
		f.p("%sfor k := range %s {\n%s\te := %s[k]\n", ind, expr, ind, expr)
		u.emitDestroy(f, "e", s.AddlProps, depth+1)
		f.p("%s\t%s[k] = e\n%s}\n", ind, expr, ind)
	}
}

// emitFieldValidation writes the validator block of one member. What each kind of member checks:
//
//	plain    required, not nullable (T)       missing, null
//	nullptr  required, nullable (*T)          missing
//	optptr   optional (*T) and optslice       null (absent and null both leave nil, so the presence bits tell them apart)
//	opt      merge-patch (Opt[T])             null, unless the member declares it
//
// and then the value checks, guarded so that they run only on a value the client sent.
func (u *unit) emitFieldValidation(f *gofile, s *Schema, fd field) {
	at := "at"
	idx := strconv.Itoa(fd.Idx)
	f.p("\t// %s\n", fd.JSON)
	var guard string // when to run the value checks
	switch fd.Kind {
	case "plain":
		f.p("\tif v.p.Decoded() {\n\t\tif !v.p.Has(%s) {\n\t\t\terrs.Required(at, %q)\n\t\t}\n\t\tif v.p.IsNull(%s) {\n\t\t\terrs.NullNotAllowed(at, %q)\n\t\t}\n\t}\n", idx, fd.JSON, idx, fd.JSON)
		guard = "!v.p.Decoded() || (v.p.Has(" + idx + ") && !v.p.IsNull(" + idx + "))"
	case "nullptr":
		f.p("\tif v.p.Decoded() && !v.p.Has(%s) {\n\t\terrs.Required(at, %q)\n\t}\n", idx, fd.JSON)
		guard = "v." + fd.Go + " != nil"
	case "optptr", "optslice":
		f.p("\tif v.p.Decoded() && v.p.IsNull(%s) {\n\t\terrs.NullNotAllowed(at, %q)\n\t}\n", idx, fd.JSON)
		guard = "v." + fd.Go + " != nil"
	case "opt":
		if !fd.Prop.Nullable {
			f.p("\tif v.%s.IsNull() {\n\t\terrs.NullNotAllowed(at, %q)\n\t}\n", fd.Go, fd.JSON)
		}
	}
	if !u.needsChecks(fd.Prop) && !fd.Prop.HasConst {
		return
	}
	ptr := at + ".AppendToken(" + strconv.Quote(fd.JSON) + ")"
	expr := "v." + fd.Go
	switch fd.Kind {
	case "nullptr", "optptr":
		expr = "(*v." + fd.Go + ")"
	case "opt":
		guard = "p := v." + fd.Go + ".Ptr(); p != nil"
		expr = "(*p)"
	}
	f.p("\tif %s {\n", guard)
	u.emitValueChecks(f, expr, fd.Prop, ptr, apiBody, 2)
	f.p("\t}\n")
}

const apiBody = "body"

// needsChecks reports whether a value of schema s has anything to validate.
func (u *unit) needsChecks(s *Schema) bool {
	if s.Ref != "" {
		if b := u.binding(s.Ref); b != nil {
			return false
		}
		r := u.m.Schemas[s.Ref]
		switch {
		case r.isObject(), r.isUnion(), r.isMap(), r.Type == "array":
			return true
		case r.isEnum():
			return !r.EnumOpen
		}
		return u.scalarChecks(r)
	}
	switch {
	case s.Type == "array", s.isMap():
		return true
	case s.isEnum():
		return !s.EnumOpen
	}
	return u.scalarChecks(s)
}

func (u *unit) scalarChecks(s *Schema) bool {
	switch s.Type {
	case "string":
		return s.MinLen != nil || s.MaxLen != nil || s.Pattern != "" || s.Format == "email"
	case "integer":
		return true
	}
	return false
}

// emitValueChecks writes the checks of one value of schema s held in expr. at is a Go expression
// for its location: a JSON pointer in the body, a parameter name elsewhere.
func (u *unit) emitValueChecks(f *gofile, expr string, s *Schema, at, in string, depth int) {
	ind := strings.Repeat("\t", depth)
	inConst := f.apit("InBody")
	switch in {
	case "path":
		inConst = f.apit("InPath")
	case "query":
		inConst = f.apit("InQuery")
	case "header":
		inConst = f.apit("InHeader")
	}
	loc := at
	if in != apiBody {
		loc = f.use(pJSONTxt) + "Pointer(" + at + ")"
	}
	r := s
	if s.Ref != "" {
		if u.binding(s.Ref) != nil {
			return
		}
		r = u.m.Schemas[s.Ref]
		switch {
		case r.isObject(), r.isUnion(), r.isMap(), r.Type == "array":
			if in == apiBody {
				f.p("%s%s.Validate(%s, errs)\n", ind, expr, at)
			}
			return
		}
	}
	switch {
	case r.Type == "array":
		f.p("%s%s(errs, %s, %s, len(%s), %s, %s, %s)\n", ind, f.apit("CheckCount"), inConst, loc, expr, intOr(r.MinItems, 0), intOr(r.MaxItems, -1), f.apit("CodeMaxItems"))
		if u.needsChecks(r.Items) {
			f.p("%sfor i := range %s {\n", ind, expr)
			u.emitValueChecks(f, expr+"[i]", r.Items, f.apit("Index")+"("+loc+", i)", in, depth+1)
			f.p("%s}\n", ind)
		}
	case r.isMap():
		f.p("%s%s(errs, %s, %s, len(%s), 0, %s, %s)\n", ind, f.apit("CheckCount"), inConst, loc, expr, intOr(r.MaxProps, -1), f.apit("CodeMaxProperties"))
		if u.needsChecks(r.AddlProps) {
			f.p("%sfor k := range %s {\n%s\te := %s[k]\n", ind, expr, ind, expr)
			u.emitValueChecks(f, "e", r.AddlProps, loc+".AppendToken(k)", in, depth+1)
			f.p("%s\t_ = e\n%s}\n", ind, ind)
		}
	case r.isEnum():
		if !r.EnumOpen {
			f.p("%sif !%s.Valid() {\n%s\terrs.Add(%s, %s, %s, %q)\n%s}\n", ind, expr, ind, inConst, loc, f.apit("CodeEnum"), "value is not one of the allowed values", ind)
		}
	case r.Type == "string":
		if r.MinLen != nil || r.MaxLen != nil {
			f.p("%s%s(errs, %s, %s, string(%s), %s, %s)\n", ind, f.apit("CheckLen"), inConst, loc, expr, intOr(r.MinLen, 0), intOr(r.MaxLen, -1))
		}
		if r.Pattern != "" {
			f.p("%sif !%s.MatchString(string(%s)) {\n%s\terrs.Add(%s, %s, %s, %q)\n%s}\n", ind, u.pattern(f, r.Pattern), expr, ind, inConst, loc, f.apit("CodePattern"), "value does not match the required pattern", ind)
		}
		if r.Format == "email" {
			f.p("%sif !%s(string(%s)) {\n%s\terrs.Add(%s, %s, %s, %q)\n%s}\n", ind, f.apit("CheckEmail"), expr, ind, inConst, loc, f.apit("CodeFormat"), "expected an e-mail address", ind)
		}
	case r.Type == "integer":
		f.p("%s%s(errs, %s, %s, int64(%s), %d, %d)\n", ind, f.apit("CheckInt"), inConst, loc, expr, *r.Min, *r.Max)
	}
	if s.HasConst {
		f.p("%sif %s != %q {\n%s\terrs.Add(%s, %s, %s, %q)\n%s}\n", ind, expr, s.Const, ind, inConst, loc, f.apit("CodeConst"), "wrong value", ind)
	}
}

func intOr(p *int, def int) string {
	if p == nil {
		return strconv.Itoa(def)
	}
	return strconv.Itoa(*p)
}

// pattern returns the name of the package-level regexp for a pattern.
func (u *unit) pattern(f *gofile, pat string) string {
	f.use("regexp")
	if n, ok := u.pats[pat]; ok {
		return n
	}
	n := "pattern" + strconv.Itoa(len(u.pats)+1)
	u.pats[pat] = n
	u.patSeq = append(u.patSeq, pat)
	return n
}

// emitPatterns appends the regexp variables used since the previous call. A package's files share
// one set of pattern variables, each declared once, in the file that first needed it.
func (u *unit) emitPatterns(f *gofile) {
	fresh := u.patSeq[u.patDone:]
	if len(fresh) == 0 {
		return
	}
	u.patDone = len(u.patSeq)
	f.use("regexp")
	f.p("var (\n")
	for _, pat := range fresh {
		f.p("\t%s = regexp.MustCompile(%q)\n", u.pats[pat], pat)
	}
	f.p(")\n\n")
}

func (u *unit) emitMap(f *gofile, s *Schema) {
	jt := strings.TrimSuffix(f.use(pJSONTxt), ".")
	f.p("type %s map[string]%s\n\n", s.Name, f.goType(s.AddlProps))
	f.p("func (m *%s) UnmarshalJSONFrom(d *%s.Decoder) error {\n\tvar x map[string]%s\n\tif err := %s(d, &x); err != nil {\n\t\treturn err\n\t}\n\t*m = x\n\treturn nil\n}\n\n",
		s.Name, jt, f.goType(s.AddlProps), f.apit("DecodeMap"))
	f.p("// Validate checks the property count and every value.\nfunc (m %s) Validate(at %s.Pointer, errs *%s) {\n", s.Name, jt, f.apit("Errors"))
	u.emitValueChecks(f, "m", &Schema{Type: "object", AddlProps: s.AddlProps, MaxProps: s.MaxProps, Where: s.Where}, "at", apiBody, 1)
	f.p("}\n\n")
	if u.m.SecretTy[s.Name] {
		f.p("// DestroySecrets destroys every secret in the map.\nfunc (m %s) DestroySecrets() {\n", s.Name)
		u.emitDestroy(f, "m", &Schema{Type: "object", AddlProps: s.AddlProps}, 1)
		f.p("}\n\n")
	}
}

func (u *unit) emitArray(f *gofile, s *Schema) {
	jt := strings.TrimSuffix(f.use(pJSONTxt), ".")
	f.p("type %s []%s\n\n", s.Name, f.goType(s.Items))
	f.p("func (a *%s) UnmarshalJSONFrom(d *%s.Decoder) error {\n\tvar x []%s\n\tif err := %s(d, &x); err != nil {\n\t\treturn err\n\t}\n\t*a = x\n\treturn nil\n}\n\n",
		s.Name, jt, f.goType(s.Items), f.apit("DecodeArray"))
	f.p("// Validate checks the item count and every item.\nfunc (a %s) Validate(at %s.Pointer, errs *%s) {\n", s.Name, jt, f.apit("Errors"))
	u.emitValueChecks(f, "a", &Schema{Type: "array", Items: s.Items, MinItems: s.MinItems, MaxItems: s.MaxItems, Where: s.Where}, "at", apiBody, 1)
	f.p("}\n\n")
	if u.m.SecretTy[s.Name] {
		f.p("// DestroySecrets destroys every secret in the array.\nfunc (a %s) DestroySecrets() {\n", s.Name)
		u.emitDestroy(f, "a", &Schema{Type: "array", Items: s.Items}, 1)
		f.p("}\n\n")
	}
}

func (u *unit) emitUnion(f *gofile, s *Schema) {
	jt := strings.TrimSuffix(f.use(pJSONTxt), ".")
	js := strings.TrimSuffix(f.use(pJSON), ".")
	type variant struct{ Kind, Go, Type string }
	var vs []variant
	for _, v := range s.OneOf {
		vschema := u.m.Schemas[v]
		k := vschema.Props["kind"].Const
		vs = append(vs, variant{Kind: k, Go: goIdent(k), Type: f.ref(v)})
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i].Kind < vs[j].Kind })
	f.p("type %s struct {\n\t// Kind is the discriminator; exactly one variant pointer is set, the one Kind names.\n\tKind string\n", s.Name)
	for _, v := range vs {
		if v.Go == "Kind" {
			u.errs.addf("%s: a variant kind %q collides with the Kind field", s.Where, v.Kind)
		}
		f.p("\t%s *%s\n", v.Go, v.Type)
	}
	f.p("}\n\n")
	f.p("// UnmarshalJSONFrom reads the value, takes its kind, and decodes the variant with the caller's\n// options, so the variant's own strict decoder applies.\nfunc (u *%s) UnmarshalJSONFrom(d *%s.Decoder) error {\n\t*u = %s{}\n\tval, err := d.ReadValue()\n\tif err != nil {\n\t\treturn err\n\t}\n\tprefix := d.StackPointer()\n\tkind, err := %s(prefix, val)\n\tif err != nil {\n\t\treturn err\n\t}\n\tswitch kind {\n",
		s.Name, jt, s.Name, f.apit("UnionKind"))
	for _, v := range vs {
		f.p("\tcase %q:\n\t\tvar x %s\n\t\tif err := %s.Unmarshal(val, &x, d.Options()); err != nil {\n\t\t\treturn %s(prefix, err)\n\t\t}\n\t\tu.Kind, u.%s = kind, &x\n", v.Kind, v.Type, js, f.apit("Rebase"), v.Go)
	}
	f.p("\tdefault:\n\t\treturn %s\n\t}\n\treturn nil\n}\n\n", f.apit("UnknownKind(prefix)"))
	f.p("// MarshalJSONTo writes the one variant that is set, with its kind.\nfunc (u %s) MarshalJSONTo(e *%s.Encoder) error {\n\tn := 0\n", s.Name, jt)
	for _, v := range vs {
		f.p("\tif u.%s != nil {\n\t\tn++\n\t}\n", v.Go)
	}
	f.p("\tif n != 1 {\n\t\treturn %s\n\t}\n\tswitch {\n", f.apit("ErrUnionVariants"))
	for _, v := range vs {
		f.p("\tcase u.%s != nil:\n\t\tc := *u.%s\n\t\tc.Kind = %q\n\t\treturn %s.MarshalEncode(e, &c)\n", v.Go, v.Go, v.Kind, js)
	}
	f.p("\t}\n\treturn nil\n}\n\n")
	f.p("// Validate validates the variant that is set.\nfunc (u *%s) Validate(at %s.Pointer, errs *%s) {\n\tswitch u.Kind {\n", s.Name, jt, f.apit("Errors"))
	for _, v := range vs {
		f.p("\tcase %q:\n\t\tif u.%s == nil {\n\t\t\terrs.AddBody(at, %s, \"kind names a variant that is not set\")\n\t\t\treturn\n\t\t}\n\t\tu.%s.Validate(at, errs)\n", v.Kind, v.Go, f.apit("CodeKind"), v.Go)
	}
	f.p("\tdefault:\n\t\terrs.AddBody(at.AppendToken(\"kind\"), %s, \"unknown kind\")\n\t}\n}\n\n", f.apit("CodeKind"))
	if u.m.SecretTy[s.Name] {
		f.p("// DestroySecrets destroys the secrets of the variant that is set.\nfunc (u *%s) DestroySecrets() {\n", s.Name)
		for _, v := range s.OneOf {
			if u.m.SecretTy[v] {
				f.p("\tif u.%s != nil {\n\t\tu.%s.DestroySecrets()\n\t}\n", goIdent(u.m.Schemas[v].Props["kind"].Const), goIdent(u.m.Schemas[v].Props["kind"].Const))
			}
		}
		f.p("}\n\n")
	}
}
