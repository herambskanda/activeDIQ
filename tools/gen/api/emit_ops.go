package main

import (
	"fmt"
	"strconv"
	"strings"
)

// emitHandlers writes handlers.gen.go for one tag: Input and Output types, Handlers, Bind.
func (u *unit) emitHandlers() ([]byte, error) {
	f := u.newFile()
	ah := strings.TrimSuffix(f.use(u.cfg.ApihostImport), ".")
	ctx := strings.TrimSuffix(f.use("context"), ".")
	var ops []*Operation
	for _, op := range u.m.Ops {
		if op.Tag == u.tag {
			ops = append(ops, op)
		}
	}
	for _, op := range ops {
		u.emitOperation(f, op)
	}
	f.p("// Handlers is the tag's handler interface: one method per operation. A handler never sees\n// *http.Request, http.ResponseWriter or the raw body (ADR-0004 rule 5).\ntype Handlers interface {\n")
	for _, op := range ops {
		n := goIdent(op.ID)
		f.p("\t%s(ctx %s.Context, in %sInput) (%sOutput, error)\n", n, ctx, n, n)
	}
	f.p("}\n\n")
	f.p("// Bind adapts the handlers to the route rows apihost mounts. It is the only caller of apihost's\n// route constructors.\nfunc Bind(h Handlers) %s.TagHandlers {\n\treturn %s.NewTagHandlers(%q", ah, ah, u.tag)
	for _, op := range ops {
		n := goIdent(op.ID)
		body := "BodyNone"
		media := ""
		switch {
		case op.Body != nil && op.Body.Binary:
			body, media = "BodyBinary", op.Body.Media
		case op.Body != nil && op.Body.Media == mediaPatch:
			body, media = "BodyMergePatch", op.Body.Media
		case op.Body != nil:
			body, media = "BodyJSON", op.Body.Media
		}
		f.p(",\n\t\t%s.NewRoute(%s.RouteMeta{\n\t\t\tOperationID: %q, Tag: %q, Method: %q, Path: %q,\n\t\t\tPermission: %q, Anonymous: %q, Scope: %q, Stability: %q, Deprecated: %v, Sunset: %q,\n\t\t\tClass: %q, MaxBody: %d, Body: %s.%s, MediaType: %q, Secret: %v,\n\t\t},\n",
			ah, ah, op.ID, op.Tag, op.Method, op.Path, op.Permission, op.Anonymous, op.Scope, op.Stability, op.Deprecated, op.Sunset, op.Class, op.MaxBody, ah, body, media, op.Secret)
		f.p("\t\t\tfunc() %s.Input { return new(%sInput) },\n\t\t\tfunc(ctx %s.Context, in %s.Input) (%s.Response, error) {\n\t\t\t\tout, err := h.%s(ctx, *in.(*%sInput))\n\t\t\t\tif err != nil {\n\t\t\t\t\treturn nil, err\n\t\t\t\t}\n\t\t\t\tif out == nil {\n\t\t\t\t\treturn nil, %s.Errorf(\"%s returned no output and no error\")\n\t\t\t\t}\n\t\t\t\treturn out, nil\n\t\t\t})",
			ah, n, ctx, ah, ah, n, n, strings.TrimSuffix(f.use("fmt"), "."), n)
	}
	f.p(",\n\t)\n}\n")
	u.emitPatterns(f)
	b, err := f.bytes()
	return b, err
}

func (u *unit) emitOperation(f *gofile, op *Operation) {
	n := goIdent(op.ID)
	u.claim(n+"Input", "operation "+op.ID)
	u.claim(n+"Output", "operation "+op.ID)
	ah := strings.TrimSuffix(f.use(u.cfg.ApihostImport), ".")
	jt := strings.TrimSuffix(f.use(pJSONTxt), ".")
	type pfield struct {
		Go   string
		P    *Param
		Typ  string // element type
		List bool
	}
	var pfs []pfield
	seen := map[string]string{"Body": "the request body"}
	for _, pm := range op.Params {
		g := goIdent(pm.Name)
		if prev, dup := seen[g]; dup {
			u.errs.addf("%s %s: parameter %q and %s both give the Go field %s", op.Method, op.Path, pm.Name, prev, g)
		}
		seen[g] = "parameter " + pm.Name
		pf := pfield{Go: g, P: pm}
		sc := pm.Schema
		if sc.Type == "array" && sc.Ref == "" {
			pf.List, pf.Typ = true, f.goType(sc.Items)
		} else {
			pf.Typ = f.goType(sc)
		}
		pfs = append(pfs, pf)
	}

	f.p("// %sInput is the decoded input of %s: path, query and header parameters, then the body.\ntype %sInput struct {\n", n, op.ID, n)
	for _, pf := range pfs {
		t := pf.Typ
		switch {
		case pf.List:
			t = "[]" + pf.Typ
		case !pf.P.Required:
			t = "*" + pf.Typ
		}
		f.p("\t%s %s // %s %q\n", pf.Go, t, pf.P.In, pf.P.Name)
	}
	switch {
	case op.Body == nil:
	case op.Body.Binary:
		f.p("\tUpload %s.Upload\n", ah)
	case op.Body.Required:
		f.p("\tBody %s\n", f.goType(op.Body.Schema))
	default:
		f.p("\tBody *%s\n", f.goType(op.Body.Schema))
	}
	f.p("}\n\n")

	// BindRequest.
	f.p("func (in *%sInput) BindRequest(r *%s.Request, errs *%s) {\n\t_ = r\n", n, ah, f.apit("Errors"))
	for _, pf := range pfs {
		u.emitBind(f, pf.Go, pf.P, pf.List)
	}
	if op.Body != nil && op.Body.Binary {
		f.p("\tin.Upload = r.Upload\n")
	}
	f.p("}\n\n")

	// BodyTarget.
	if op.Body != nil && !op.Body.Binary {
		f.p("func (in *%sInput) BodyTarget() any { return &in.Body }\n\n", n)
	} else {
		f.p("func (in *%sInput) BodyTarget() any { return nil }\n\n", n)
	}

	// Validate.
	f.p("func (in *%sInput) Validate(errs *%s) {\n\t_ = errs\n", n, f.apit("Errors"))
	for _, pf := range pfs {
		sc := pf.P.Schema
		expr := "in." + pf.Go
		at := strconv.Quote(pf.P.Name)
		switch {
		case pf.List:
			if u.needsChecks(sc) {
				f.p("\t{\n")
				u.emitValueChecks(f, expr, sc, at, pf.P.In, 2)
				f.p("\t}\n")
			}
		case !pf.P.Required:
			if u.needsChecks(sc) {
				f.p("\tif %s != nil {\n", expr)
				u.emitValueChecks(f, "(*"+expr+")", sc, at, pf.P.In, 2)
				f.p("\t}\n")
			}
		default:
			if u.needsChecks(sc) {
				f.p("\t{\n")
				u.emitValueChecks(f, expr, sc, at, pf.P.In, 2)
				f.p("\t}\n")
			}
		}
	}
	if op.Body != nil && !op.Body.Binary {
		if op.Body.Required {
			f.p("\tin.Body.Validate(%s.Pointer(\"\"), errs)\n", jt)
		} else {
			f.p("\tif in.Body != nil {\n\t\tin.Body.Validate(%s.Pointer(\"\"), errs)\n\t}\n", jt)
		}
	}
	f.p("}\n\n")

	// DestroySecrets.
	f.p("func (in *%sInput) DestroySecrets() {", n)
	if op.Secret {
		if op.Body.Required {
			f.p("\n\tin.Body.DestroySecrets()\n")
		} else {
			f.p("\n\tif in.Body != nil {\n\t\tin.Body.DestroySecrets()\n\t}\n")
		}
	}
	f.p("}\n\n")

	// Output.
	f.p("// %sOutput is one of the responses %s declares. Errors are returned as the error value.\ntype %sOutput interface {\n\t%s.Response\n\tis%sOutput()\n}\n\n", n, op.ID, n, ah, n)
	for _, r := range op.Responses {
		if r.Problem {
			continue
		}
		rn := n + strconv.Itoa(r.Status)
		u.claim(rn, "operation "+op.ID+" response")
		f.p("// %s is the %d response.\ntype %s struct {\n", rn, r.Status, rn)
		switch {
		case r.Binary:
			f.p("\tBody %s.Stream\n", ah)
		case r.Schema != nil:
			f.p("\tBody %s\n", f.goType(r.Schema))
		}
		for _, h := range r.Headers {
			f.p("\t%s string // header %s\n", goIdent(h.Name), h.Name)
		}
		f.p("}\n\nfunc (%s) StatusCode() int { return %d }\n", rn, r.Status)
		switch {
		case r.Binary || r.Schema != nil:
			f.p("func (o %s) ResponseBody() any { return o.Body }\n", rn)
		default:
			f.p("func (%s) ResponseBody() any { return nil }\n", rn)
		}
		if len(r.Headers) == 0 {
			f.p("func (%s) ResponseHeaders() map[string]string { return nil }\n", rn)
		} else {
			f.p("func (o %s) ResponseHeaders() map[string]string {\n\th := map[string]string{}\n", rn)
			for _, h := range r.Headers {
				f.p("\tif o.%s != \"\" {\n\t\th[%q] = o.%s\n\t}\n", goIdent(h.Name), h.Name, goIdent(h.Name))
			}
			f.p("\treturn h\n}\n")
		}
		f.p("func (%s) is%sOutput() {}\n\n", rn, n)
	}
}

// emitBind writes the parsing of one parameter into the Input.
func (u *unit) emitBind(f *gofile, goField string, pm *Param, list bool) {
	loc := map[string]string{"path": "InPath", "query": "InQuery", "header": "InHeader"}[pm.In]
	inC := f.apit(loc)
	name := strconv.Quote(pm.Name)
	f.p("\t{\n")
	switch pm.In {
	case "path":
		f.p("\t\tvs := []string{r.PathValue(%s)}\n", name)
	case "query":
		f.p("\t\tvs := r.Query[%s]\n", name)
	default:
		f.p("\t\tvs := r.Header.Values(%s)\n", name)
	}
	elem := pm.Schema
	if list {
		elem = pm.Schema.Items
	}
	res := u.resolve(elem)
	typ := f.goType(elem)
	conv := func(src, dst string) {
		bad := func(detail string) string {
			return fmt.Sprintf("errs.Add(%s, %s, %s, %q)", inC, "jsontextPointer("+name+")", f.apit("CodeType"), detail)
		}
		bad2 := strings.Replace(bad("expected a valid value"), "jsontextPointer(", f.use(pJSONTxt)+"Pointer(", 1)
		var parse string
		switch {
		case res.isEnum() || (res.Type == "string" && res.Format == ""), res.Type == "string" && res.Format == "email":
			f.p("\t\t\t%s = %s(%s)\n", dst, typ, src)
			return
		case res.Type == "string" && res.Format == "uuid":
			parse = f.apit("ParseUUID")
		case res.Type == "string" && res.Format == "date":
			parse = f.apit("ParseDate")
		case res.Type == "string" && res.Format == "date-time":
			parse = f.apit("ParseTimestamp")
		case res.Type == "integer":
			parse = f.apit("ParseInt")
		case res.Type == "boolean":
			parse = f.apit("ParseBool")
		case elem.Ref != "" && u.binding(elem.Ref) != nil && u.binding(elem.Ref).Type == "Int64String":
			parse = f.apit("ParseInt64String")
		default:
			f.p("\t\t\t%s = %s(%s)\n", dst, typ, src)
			return
		}
		f.p("\t\t\tif x, err := %s(%s); err != nil {\n\t\t\t\t%s\n\t\t\t} else {\n\t\t\t\t%s = %s(x)\n\t\t\t}\n", parse, src, bad2, dst, typ)
	}
	ptrAt := f.use(pJSONTxt) + "Pointer(" + name + ")"
	switch {
	case list:
		f.p("\t\tfor _, s := range vs {\n")
		f.p("\t\t\tvar e %s\n", typ)
		conv("s", "e")
		f.p("\t\t\tin.%s = append(in.%s, e)\n\t\t}\n", goField, goField)
		if pm.Required {
			f.p("\t\tif len(vs) == 0 {\n\t\t\terrs.Add(%s, %s, %s, \"required parameter is missing\")\n\t\t}\n", inC, ptrAt, f.apit("CodeRequired"))
		}
	default:
		f.p("\t\tswitch {\n\t\tcase len(vs) > 1:\n\t\t\terrs.Add(%s, %s, %s, \"parameter must not repeat\")\n", inC, ptrAt, f.apit("CodeType"))
		f.p("\t\tcase len(vs) == 1 && vs[0] != \"\":\n")
		if pm.Required {
			f.p("\t\t\ts := vs[0]\n")
			conv("s", "in."+goField)
		} else {
			f.p("\t\t\ts := vs[0]\n\t\t\tvar e %s\n", typ)
			conv("s", "e")
			f.p("\t\t\tin.%s = &e\n", goField)
		}
		if pm.Required {
			f.p("\t\tdefault:\n\t\t\terrs.Add(%s, %s, %s, \"required parameter is missing\")\n", inC, ptrAt, f.apit("CodeRequired"))
		}
		f.p("\t\t}\n")
	}
	f.p("\t}\n")
}
