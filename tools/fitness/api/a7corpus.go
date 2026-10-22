package main

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// corpusCase is one request of the A7 corpus. The handler is never called for a case that must be
// rejected; for a must-accept case a stub stands in for it.
type corpusCase struct {
	Name        string
	Body        []byte
	CT          string // "" means the route's media type
	DeclaredLen int64  // 0 means the body's length
	WantStatus  int
	WantType    string
	WantPtrs    []string // validation: one reported pointer must be one of these
	Schema      bool     // schema-level: also run in ajv
	Accept      bool
}

const (
	typValidation = apitypes.ProblemTypeValidation
	typMalformed  = apitypes.ProblemTypeMalformedRequest
)

// buildCases is the corpus of one operation, from the cases lists of ADR-0004.
func buildCases(root map[string]any, schema any, meta apihost.RouteMeta) ([]corpusCase, error) {
	base, err := genInstance(root, schema, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot generate a valid instance: %w", err)
	}
	var cases []corpusCase
	seen := map[string]bool{}
	add := func(c corpusCase) {
		k := c.Name + "\x00" + string(c.Body)
		if !seen[k] {
			seen[k] = true
			cases = append(cases, c)
		}
	}
	insts := []*instance{base}
	for _, u := range base.unions {
		for i := 1; i < base.unionN[u]; i++ {
			v, err := genInstance(root, schema, map[string]int{u: i})
			if err != nil {
				return nil, fmt.Errorf("variant %d of the union at %s: %w", i, orRoot(u), err)
			}
			insts = append(insts, v)
		}
	}
	add(corpusCase{Name: "valid instance", Body: encode(base.value), Schema: true, Accept: true, WantStatus: 200})
	for vi, inst := range insts {
		tag := ""
		if vi > 0 {
			tag = fmt.Sprintf(" (variant set %d)", vi)
		}
		for _, n := range inst.nodes {
			if n.kind == nodeUnion {
				for _, mode := range []string{"kind missing", "kind unknown", "kind in the wrong case"} {
					v := clone(inst.value)
					obj, ok := at(v, n.ptr).(map[string]any)
					if !ok {
						continue
					}
					kv, has := obj["kind"]
					if !has {
						continue
					}
					switch mode {
					case "kind missing":
						delete(obj, "kind")
					case "kind unknown":
						obj["kind"] = "zz-unknown"
					default:
						delete(obj, "kind")
						obj["Kind"] = kv
					}
					v = setAt(v, n.ptr, obj)
					add(corpusCase{Name: fmt.Sprintf("union %s: %s%s", orRoot(n.ptr), mode, tag), Body: encode(v), WantStatus: 400, WantType: typValidation, WantPtrs: []string{n.ptr, n.ptr + "/kind", n.ptr + "/Kind"}, Schema: true})
				}
				continue
			}
			add(corpusCase{Name: fmt.Sprintf("object %s: unknown member%s", orRoot(n.ptr), tag), Body: withMember(inst.value, n.ptr, "zzUnknown", 1), WantStatus: 400, WantType: typValidation, WantPtrs: []string{n.ptr, n.ptr + "/zzUnknown"}, Schema: true})
			if len(n.members) > 0 {
				m := n.members[0]
				wrong := strings.ToUpper(m[:1]) + m[1:]
				if wrong == m {
					wrong = strings.ToLower(m[:1]) + m[1:]
				}
				if wrong != m {
					v := clone(inst.value)
					obj := at(v, n.ptr).(map[string]any)
					val := obj[m]
					delete(obj, m)
					obj[wrong] = val
					add(corpusCase{Name: fmt.Sprintf("object %s: member %q in the wrong case%s", orRoot(n.ptr), m, tag), Body: encode(setAt(v, n.ptr, obj)), WantStatus: 400, WantType: typValidation, WantPtrs: []string{n.ptr, n.ptr + "/" + escPtr(wrong), n.ptr + "/" + escPtr(m)}, Schema: true})
				}
				add(corpusCase{Name: fmt.Sprintf("object %s: duplicate member%s", orRoot(n.ptr), tag), Body: duplicateMember(inst.value, n.ptr, m), WantStatus: 400, WantType: typMalformed})
			}
			for _, m := range n.members {
				if n.required[m] {
					v := clone(inst.value)
					obj := at(v, n.ptr).(map[string]any)
					delete(obj, m)
					add(corpusCase{Name: fmt.Sprintf("object %s: required member %q missing%s", orRoot(n.ptr), m, tag), Body: encode(setAt(v, n.ptr, obj)), WantStatus: 400, WantType: typValidation, WantPtrs: []string{n.ptr, n.ptr + "/" + escPtr(m)}, Schema: true})
				}
				if !n.nullable[m] {
					v := clone(inst.value)
					obj := at(v, n.ptr).(map[string]any)
					obj[m] = nil
					add(corpusCase{Name: fmt.Sprintf("object %s: null for non-nullable member %q%s", orRoot(n.ptr), m, tag), Body: encode(setAt(v, n.ptr, obj)), WantStatus: 400, WantType: typValidation, WantPtrs: []string{n.ptr, n.ptr + "/" + escPtr(m)}, Schema: true})
				}
			}
		}
	}

	// The whole body.
	for _, c := range []struct {
		name string
		body []byte
	}{
		{"invalid UTF-8 (\\xff)", []byte("{\"zz\":\"\xff\"}")},
		{"lone high surrogate escape", []byte(`{"zz":"\ud800"}`)},
		{"lone low surrogate escape", []byte(`{"zz":"\udc00"}`)},
		{"NUL escape in a value", []byte(`{"zz":"a\u0000b"}`)},
		{"NUL escape in a member name", []byte(`{"z\u0000z":"a"}`)},
		{"trailing data", append(encode(base.value), []byte(` {}`)...)},
		{"depth 33", []byte(strings.Repeat("[", 33) + strings.Repeat("]", 33))},
	} {
		add(corpusCase{Name: "body: " + c.name, Body: c.body, WantStatus: 400, WantType: typMalformed})
	}
	add(corpusCase{Name: "body: oversize", Body: bytes.Repeat([]byte(" "), int(meta.MaxBody)+1), WantStatus: 413, WantType: apitypes.ProblemTypePayloadTooLarge})
	add(corpusCase{Name: "body: Content-Length above the cap", Body: encode(base.value), DeclaredLen: meta.MaxBody + 1, WantStatus: 413, WantType: apitypes.ProblemTypePayloadTooLarge})
	add(corpusCase{Name: "body: wrong Content-Type", Body: encode(base.value), CT: "text/plain", WantStatus: 415, WantType: apitypes.ProblemTypeUnsupportedMediaType})

	// Must accept: an escaped backslash before u0000 is text, not a NUL.
	if base.free != "" {
		v := clone(base.value)
		add(corpusCase{Name: "must accept: escaped backslash before u0000", Body: bytes.Replace(encode(setAt(v, base.free, "\x01")), []byte(`"\u0001"`), []byte(`"a\\u0000b"`), 1), Accept: true, WantStatus: 200})
	}
	return cases, nil
}

func setAt(root any, ptr string, v any) any {
	if ptr == "" {
		return v
	}
	i := strings.LastIndex(ptr, "/")
	parent := at(root, ptr[:i])
	key := strings.ReplaceAll(strings.ReplaceAll(ptr[i+1:], "~1", "/"), "~0", "~")
	switch p := parent.(type) {
	case map[string]any:
		p[key] = v
	case []any:
		var n int
		fmt.Sscanf(key, "%d", &n)
		p[n] = v
	}
	return root
}

func withMember(value any, ptr, name string, v any) []byte {
	c := clone(value)
	obj, _ := at(c, ptr).(map[string]any)
	if obj == nil {
		return encode(c)
	}
	obj[name] = v
	return encode(setAt(c, ptr, obj))
}

// duplicateMember writes member m twice in the object at ptr, by text: no map can hold it.
func duplicateMember(value any, ptr, m string) []byte {
	c := clone(value)
	obj := at(c, ptr).(map[string]any)
	val := obj[m]
	obj["zz_dup"] = 0
	b := encode(setAt(c, ptr, obj))
	dup := append(append(encode(m), ':'), encode(val)...)
	return bytes.Replace(b, []byte(`"zz_dup":0`), dup, 1)
}

// stubResponse is what a must-accept case's stub handler returns.
type stubResponse struct{}

func (stubResponse) StatusCode() int                    { return 204 }
func (stubResponse) ResponseBody() any                  { return nil }
func (stubResponse) ResponseHeaders() map[string]string { return nil }

// corpusPorts authenticate a token principal and allow everything: the corpus tests decoding, not
// authorisation (A4 tests that).
type corpusPorts struct{ probePorts }

func (corpusPorts) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (c corpusPorts) ports() apihost.Ports {
	return apihost.Ports{Authn: c, Authz: c, Limits: c, StepUp: c}
}

// checkA7Runtime runs the type closure, the corpus and the ajv cross-check over the routes of every
// profile.
func checkA7Runtime(t *tree) []Violation {
	env, vs := loadRuntime(t, "A7")
	if env == nil {
		return vs
	}
	return runA7(env)
}

func runA7(env *runtimeEnv) []Violation {
	var vs []Violation
	var root map[string]any
	if err := json.Unmarshal(env.bundle, &root); err != nil {
		return []Violation{fail("A7", bundleRel, "the bundle does not parse: %v (ADR-0004 rule 7)", err)}
	}
	done := map[string]bool{}
	for _, prof := range env.profiles {
		tags, err := env.tags(prof)
		if err != nil {
			vs = append(vs, fail("A7", "profile "+prof, "the module list could not be read: %v (ADR-0004 A7)", err))
			continue
		}
		for _, th := range tags {
			for _, rt := range th.Routes() {
				if id := rt.Meta().OperationID; !done[id] {
					done[id] = true
					vs = append(vs, a7Route(env, root, prof, tags, rt)...)
				}
			}
		}
		// The Output side of the closure: the route table does not list response types, so it is
		// walked over the bodies the conformance harness saw handlers return.
		if rec, _ := probeAll(env, prof); rec != nil {
			vs = append(vs, observedClosure(env, prof, rec)...)
		}
	}
	return vs
}

func a7Route(env *runtimeEnv, root map[string]any, prof string, tags []apihost.TagHandlers, rt apihost.Route) []Violation {
	meta := rt.Meta()
	where := fmt.Sprintf("profile %s, %s", prof, meta.OperationID)
	var vs []Violation
	add := func(f string, a ...any) { vs = append(vs, fail("A7", where, f+" (ADR-0004 A7)", a...)) }

	// Type closure: the Input and its body target.
	in := rt.NewInput()
	for _, m := range closure(reflect.TypeOf(in)) {
		add("type closure: %s", m)
	}
	if bt := in.BodyTarget(); bt != nil {
		for _, m := range closure(reflect.TypeOf(bt)) {
			add("type closure (body): %s", m)
		}
	}
	if meta.Body != apihost.BodyJSON && meta.Body != apihost.BodyMergePatch {
		return vs
	}
	if in.BodyTarget() == nil {
		add("the operation has a JSON body but its Input has no body target")
		return vs
	}

	schema, ptr, ok := requestSchema(root, meta.Path, meta.Method, meta.MediaType)
	if !ok {
		add("the bundle has no %s request schema for %s %s", meta.MediaType, meta.Method, meta.Path)
		return vs
	}
	cases, err := buildCases(root, schema, meta)
	if err != nil {
		add("corpus: %v", err)
		return vs
	}

	// A router whose handler for this operation is a counting stub.
	calls := 0
	var wrapped []apihost.TagHandlers
	for _, th := range tags {
		var rows []apihost.Route
		for _, r := range th.Routes() {
			if r.Meta().OperationID == meta.OperationID {
				r = apihost.NewRoute(r.Meta(), r.NewInput, func(context.Context, apihost.Input) (apihost.Response, error) {
					calls++
					return stubResponse{}, nil
				})
			}
			rows = append(rows, r)
		}
		wrapped = append(wrapped, apihost.NewTagHandlers(th.Tag(), rows...))
	}
	srv, err := apihost.Build(env.doc, wrapped, env.policy, catalogueOf(env.doc), corpusPorts{}.ports(), apihost.WithBodyBudget(1<<30), quiet)
	if err != nil {
		add("apihost.Build refuses the contract: %v", err)
		return vs
	}
	var host string
	for _, r := range srv.Routes() {
		if r.OperationID == meta.OperationID {
			host = r.Host
		}
	}
	if host == "" {
		host = "api.fitness.invalid"
	}

	goAccept := map[string]bool{}
	for _, c := range cases {
		before := calls
		rec := runCase(srv, meta, host, c)
		called := calls > before
		var p struct {
			Type   string `json:"type"`
			Errors []struct {
				Pointer string `json:"pointer"`
			} `json:"errors"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &p)
		switch {
		case c.Accept:
			if rec.Code >= 400 || !called {
				add("corpus %q: want the request accepted and the handler reached, got %d %s", c.Name, rec.Code, p.Type)
			}
		default:
			if called {
				add("corpus %q: the handler was called for a request that must be rejected", c.Name)
			}
			if rec.Code != c.WantStatus || p.Type != c.WantType {
				add("corpus %q: want %d %s, got %d %q", c.Name, c.WantStatus, c.WantType, rec.Code, p.Type)
			} else if len(c.WantPtrs) > 0 && !hasPointer(p.Errors, c.WantPtrs) {
				add("corpus %q: no error at the expected JSON pointer (one of %q), got %v", c.Name, c.WantPtrs, p.Errors)
			}
		}
		if c.Schema {
			goAccept[c.Name] = !(rec.Code >= 400)
		}
	}

	// Cross-check with ajv on the same bundle.
	var ajvCases []ajvCase
	for _, c := range cases {
		if c.Schema {
			ajvCases = append(ajvCases, ajvCase{Name: c.Name, Body: string(c.Body)})
		}
	}
	res, err := ajvRun(env.root, env.bundle, ptr, ajvCases)
	if err != nil {
		add("ajv cross-check could not run: %v", err)
		return vs
	}
	names := make([]string, 0, len(goAccept))
	for n := range goAccept {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a, ok := res[n]
		if !ok {
			add("ajv returned no verdict for %q", n)
		} else if a != goAccept[n] {
			add("cross-check disagreement on %q: Go decoder accepts=%v, ajv accepts=%v (a generator bug or a dialect gap)", n, goAccept[n], a)
		}
	}
	return vs
}

func hasPointer(errs []struct {
	Pointer string `json:"pointer"`
}, want []string) bool {
	for _, e := range errs {
		for _, w := range want {
			if e.Pointer == w {
				return true
			}
		}
	}
	return false
}

func runCase(srv http.Handler, meta apihost.RouteMeta, host string, c corpusCase) *httptest.ResponseRecorder {
	req := httptest.NewRequest(meta.Method, concretePath("/api/v1"+meta.Path), bytes.NewReader(c.Body))
	req.Host = host
	req.RemoteAddr = "192.0.2.1:1234"
	ct := c.CT
	if ct == "" {
		ct = meta.MediaType
	}
	req.Header.Set("Content-Type", ct)
	req.Header.Set(principalHeader, "nobody")
	if c.DeclaredLen > 0 {
		req.ContentLength = c.DeclaredLen
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// ajvCase is one schema-level case for the cross-check.
type ajvCase struct{ Name, Body string }

// ajvRun runs the cases through ajv (2020-12, strict) against the bundle. It is a variable so a
// test can stand in a disagreeing validator.
var ajvRun = runAjv

func runAjv(root string, bundle []byte, ptr string, cases []ajvCase) (map[string]bool, error) {
	if _, err := exec.LookPath("node"); err != nil {
		return nil, fmt.Errorf("node is not installed: the A7 cross-check needs it (ADR-0004 A7)")
	}
	in, _ := json.Marshal(map[string]any{"bundle": jsontext.Value(bundle), "pointer": ptr, "cases": cases})
	// ajv comes from the pinned web dependencies.
	cmd := exec.Command("node", "--input-type=module", "-e", ajvScript, "--", filepath.Join(root, "web"))
	cmd.Stdin = bytes.NewReader(in)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("%v: %s (is `make web-install` done? ajv is a web dependency)", err, strings.TrimSpace(errb.String()))
		}
	case <-time.After(2 * time.Minute):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("ajv timed out")
	}
	var res struct {
		Results map[string]bool `json:"results"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return nil, fmt.Errorf("ajv output: %v", err)
	}
	return res.Results, nil
}

// ajvScript is the cross-check (ADR-0004 A7): it validates the schema-level corpus with ajv
// (2020-12, strict) on the bundle. It reads {bundle, pointer, cases:[{Name, Body}]} on stdin and
// prints {results:{name:accepted}}; argv[1] is the web directory, whose node_modules holds the
// pinned ajv. It lives in a Go string so the repository has no JavaScript outside web/
// (ADR-0001 rule 1).
const ajvScript = `// A7 cross-check (ADR-0004): validate the schema-level corpus with ajv (2020-12, strict) on the
// bundle. Reads {bundle, pointer, cases:[{Name, Body}]} on stdin, prints {results:{name:accepted}}.
// argv[2] is the web directory, whose node_modules holds the pinned ajv.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import path from "node:path";

const require = createRequire(path.join(path.resolve(process.argv[1]), "package.json"));
const Ajv2020 = require("ajv/dist/2020").default;

const input = JSON.parse(readFileSync(0, "utf8"));
const bundle = input.bundle;

// OpenAPI and activeDIQ annotations are not validation keywords; strict mode needs them declared.
const keywords = new Set(["example", "discriminator", "externalDocs", "xml"]);
(function scan(v) {
  if (Array.isArray(v)) return v.forEach(scan);
  if (v && typeof v === "object") {
    for (const [k, x] of Object.entries(v)) {
      if (k.startsWith("x-")) keywords.add(k);
      scan(x);
    }
  }
})(bundle);

// The bundle root is an OpenAPI document, not a schema: compile the request schema alone, with the
// component schemas as $defs.
const rewrite = (v) => {
  if (Array.isArray(v)) return v.map(rewrite);
  if (v && typeof v === "object") {
    return Object.fromEntries(
      Object.entries(v).map(([k, x]) =>
        k === "$ref" && typeof x === "string" ? [k, x.replace("#/components/schemas/", "#/$defs/")] : [k, rewrite(x)],
      ),
    );
  }
  return v;
};
let sub = bundle;
for (const seg of input.pointer.replace(/^#\//, "").split("/")) {
  sub = sub[seg.replaceAll("~1", "/").replaceAll("~0", "~")];
}
const schema = { ...rewrite(sub), $defs: rewrite(bundle.components?.schemas ?? {}) };

const ajv = new Ajv2020({ strict: true, allErrors: true, validateFormats: false });
for (const k of keywords) ajv.addKeyword({ keyword: k });
const validate = ajv.compile(schema);

const results = {};
for (const c of input.cases) {
  let value;
  try {
    value = JSON.parse(c.Body);
  } catch {
    results[c.Name] = false;
    continue;
  }
  results[c.Name] = validate(value) === true;
}
process.stdout.write(JSON.stringify({ results }));
`
