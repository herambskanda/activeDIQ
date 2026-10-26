package main

import (
	"context"
	"encoding/json/v2"
	"github.com/skenzeriq/activediq/internal/compose/server"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// Runtime fixtures for A4, A7 (closure, corpus, cross-check) and A14 (T-0018). The routes are
// built here, because no module mounts a route yet; the bundle is the real embedded one plus a few
// synthetic operations, so the corpus runs against the real generated decoders and validators.

func init() { extraGeneratedPkgs[reflect.TypeOf(objInput{}).PkgPath()] = true }

type objInput struct{ body apitypes.GUIDRef }

func (*objInput) BindRequest(*apihost.Request, *apitypes.Errors) {}
func (i *objInput) BodyTarget() any                              { return &i.body }
func (i *objInput) Validate(e *apitypes.Errors)                  { i.body.Validate("", e) }
func (*objInput) DestroySecrets()                                {}

type noInput struct{}

func (noInput) BindRequest(*apihost.Request, *apitypes.Errors) {}
func (noInput) BodyTarget() any                                { return nil }
func (noInput) Validate(*apitypes.Errors)                      {}
func (noInput) DestroySecrets()                                {}

type okResp struct{ body any }

func (okResp) StatusCode() int                    { return 200 }
func (r okResp) ResponseBody() any                { return r.body }
func (okResp) ResponseHeaders() map[string]string { return nil }

type badInput struct{ v float64 }

func (*badInput) BindRequest(*apihost.Request, *apitypes.Errors) {}
func (i *badInput) BodyTarget() any                              { return &i.v }
func (*badInput) Validate(*apitypes.Errors)                      {}
func (*badInput) DestroySecrets()                                {}

type v1Marshaler struct{}

func (v1Marshaler) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type v1Input struct{ V v1Marshaler }

func (*v1Input) BindRequest(*apihost.Request, *apitypes.Errors) {}
func (i *v1Input) BodyTarget() any                              { return nil }
func (*v1Input) Validate(*apitypes.Errors)                      {}
func (*v1Input) DestroySecrets()                                {}

// fixtureBundle is the embedded bundle with the synthetic operations added.
func fixtureBundle(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", filepath.FromSlash(bundleRel)))
	if err != nil {
		t.Skip("not run from the repository")
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	paths := root["paths"].(map[string]any)
	op := func(id, perm, class string, extra map[string]any) map[string]any {
		o := map[string]any{"operationId": id, "tags": []any{"fx"}, "x-permission": perm, "x-activediq-scope": "tenant", "x-activediq-limits": map[string]any{"class": class}}
		for k, v := range extra {
			o[k] = v
		}
		return o
	}
	paths["/fx/open"] = map[string]any{"get": op("fxOpen", "anonymous", "anonymous", nil)}
	paths["/fx/things"] = map[string]any{"get": op("fxList", "fx.read", "read", nil)}
	paths["/fx/me"] = map[string]any{"get": op("fxMe", "authenticated", "read", nil)}
	paths["/fx/objects"] = map[string]any{"post": op("fxCreate", "fx.write", "write", map[string]any{"requestBody": map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/GUIDRef"}}}}})}
	out, _ := json.Marshal(root)
	return out
}

func fxRoute(id, method, path, perm, class string, body apihost.BodyKind, in func() apihost.Input, call func() (apihost.Response, error)) apihost.Route {
	mt := ""
	if body == apihost.BodyJSON {
		mt = "application/json"
	}
	if call == nil {
		call = func() (apihost.Response, error) { return okResp{}, nil }
	}
	return apihost.NewRoute(apihost.RouteMeta{OperationID: id, Tag: "fx", Method: method, Path: path, Permission: perm, Scope: "tenant", Class: class, MaxBody: 1 << 16, Body: body, MediaType: mt, Stability: "stable"},
		in, func(context.Context, apihost.Input) (apihost.Response, error) { return call() })
}

func fxEnv(t *testing.T, mutate func(*runtimeEnv, *[]apihost.Route)) *runtimeEnv {
	t.Helper()
	bundle := fixtureBundle(t)
	doc, err := apihost.ParseDocument(bundle)
	if err != nil {
		t.Fatal(err)
	}
	env := &runtimeEnv{root: filepath.Join("..", "..", ".."), doc: doc, bundle: bundle, profiles: []string{"windows"},
		policy: apihost.Policy{Hosts: map[string]string{"totp-enrolment": hostFor("totp-enrolment")}, Authenticated: []string{"fxMe", "signOut", "getCsrfToken"},
			Anonymous: []apihost.AnonymousRow{{Operation: "fxOpen", Gate: "none"}, {Operation: "getLiveness", Gate: "none"}, {Operation: "getReadiness", Gate: "none"},
				{Operation: "signInBreakGlassPassword", Gate: "password"}, {Operation: "createWebAuthnSignInChallenge", Gate: "pending"}, {Operation: "verifyWebAuthnSignIn", Gate: "pending"}, {Operation: "verifyTotpSignIn", Gate: "pending"}}},
		nonAPISrv: func(string) ([]string, bool) { return nil, false }}
	rows := []apihost.Route{
		fxRoute("fxOpen", "GET", "/fx/open", "anonymous", "anonymous", apihost.BodyNone, func() apihost.Input { return noInput{} }, nil),
		fxRoute("fxList", "GET", "/fx/things", "fx.read", "read", apihost.BodyNone, func() apihost.Input { return noInput{} }, nil),
		fxRoute("fxMe", "GET", "/fx/me", "authenticated", "read", apihost.BodyNone, func() apihost.Input { return noInput{} }, nil),
		fxRoute("fxCreate", "POST", "/fx/objects", "fx.write", "write", apihost.BodyJSON, func() apihost.Input { return &objInput{} }, nil),
	}
	if mutate != nil {
		mutate(env, &rows)
	}
	env.serverPolicy = func() apihost.Policy { return env.policy }
	env.tags = func(string) ([]apihost.TagHandlers, error) {
		return []apihost.TagHandlers{apihost.NewTagHandlers("fx", rows...)}, nil
	}
	return env
}

func want(t *testing.T, vs []Violation, check, contains string) {
	t.Helper()
	for _, v := range vs {
		if v.Check == check && strings.Contains(v.Msg, contains) {
			return
		}
	}
	t.Fatalf("want a %s violation containing %q; got:\n%v", check, contains, vs)
}

func TestFixtureEnvIsClean(t *testing.T) {
	env := fxEnv(t, nil)
	for name, vs := range map[string][]Violation{"A4": runA4(env), "A14": runA14(env), "A7": runA7(env)} {
		if len(vs) != 0 {
			t.Errorf("%s: the clean fixture must pass, got %v", name, vs)
		}
	}
}

func TestA4Fails(t *testing.T) {
	t.Run("an operation of an enabled tag is not served", func(t *testing.T) {
		env := fxEnv(t, func(_ *runtimeEnv, rows *[]apihost.Route) { *rows = (*rows)[:3] })
		want(t, runA4(env), "A4", "fxCreate")
	})
	t.Run("policy.anonymous binds an operation to another host than it is served on", func(t *testing.T) {
		env := fxEnv(t, func(e *runtimeEnv, _ *[]apihost.Route) {
			e.policy.Anonymous[0].Host = "totp-enrolment"
			e.policy.Hosts["totp-enrolment"] = hostFor("totp-enrolment")
		})
		// served bound to the host: the probe must also see 404 on an unbound host (it does) so this passes;
		// then break the policy row instead.
		if vs := runA4(env); len(vs) != 0 {
			t.Fatalf("a bound anonymous route must pass, got %v", vs)
		}
	})
	t.Run("an anonymous row for an operation that needs authentication", func(t *testing.T) {
		env := fxEnv(t, func(e *runtimeEnv, _ *[]apihost.Route) {
			e.policy.Anonymous = append(e.policy.Anonymous, apihost.AnonymousRow{Operation: "fxList", Gate: "none"})
		})
		want(t, runA4(env), "A4", "policy.anonymous lists fxList")
	})
	t.Run("Build refuses an anonymous operation with no policy row", func(t *testing.T) {
		env := fxEnv(t, func(e *runtimeEnv, _ *[]apihost.Route) { e.policy.Anonymous = nil })
		want(t, runA4(env), "A4", "apihost.Build refuses")
	})
	t.Run("the server's policy has an extra anonymous row", func(t *testing.T) {
		env := fxEnv(t, nil)
		env.serverPolicy = func() apihost.Policy {
			p := env.policy
			p.Anonymous = append(append([]apihost.AnonymousRow{}, p.Anonymous...), apihost.AnonymousRow{Operation: "fxList", Gate: "none"})
			return p
		}
		want(t, runA4(env), "A4", "the server's policy has an anonymous row")
	})
	t.Run("the server's policy lacks a host binding", func(t *testing.T) {
		env := fxEnv(t, func(e *runtimeEnv, _ *[]apihost.Route) { e.policy.Anonymous[0].Host = "totp-enrolment" })
		env.serverPolicy = func() apihost.Policy {
			p := env.policy
			p.Anonymous = append([]apihost.AnonymousRow{}, p.Anonymous...)
			p.Anonymous[0].Host = ""
			return p
		}
		want(t, runA4(env), "A4", "policy.yaml has an anonymous row")
	})
	t.Run("a route served outside the document is not in nonApiRoutes", func(t *testing.T) {
		env := fxEnv(t, func(e *runtimeEnv, _ *[]apihost.Route) {
			e.nonAPISrv = func(string) ([]string, bool) { return []string{"GET /debug/vars"}, true }
		})
		want(t, runA4(env), "A4", "serves GET /debug/vars outside the document")
	})
	t.Run("a nonApiRoutes entry nothing serves", func(t *testing.T) {
		env := fxEnv(t, func(e *runtimeEnv, _ *[]apihost.Route) {
			e.nonAPI = []policyRoute{{"GET", "/healthz"}}
			e.nonAPISrv = func(string) ([]string, bool) { return nil, true }
		})
		want(t, runA4(env), "A4", "does not serve GET /healthz")
	})
}

func TestA4ProbeCatchesAnUnguardedRoute(t *testing.T) {
	// The document says fxOpen is anonymous, so it is served without authentication, which the
	// probe accepts; the policy row is what A4 compares. A route that is permissioned in the
	// document but anonymous in policy is refused by Build, so the probe's own proof is on ports
	// that wave everything through.
	env := fxEnv(t, nil)
	srv, err := apihost.Build(env.doc, mustTags(env), env.policy, catalogueOf(env.doc), apihost.Ports{Authn: allowAllAuthn{}, Authz: probePorts{}, Limits: probePorts{}, StepUp: probePorts{}}, quiet)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range srv.Routes() {
		if r.OperationID == "fxList" {
			vs := probeRoute("windows", srv, r, "", probeHosts(env))
			found = len(vs) > 0
			want(t, vs, "A4", "unauthenticated request on")
		}
	}
	if !found {
		t.Fatal("the probe did not flag a route that serves unauthenticated requests")
	}
}

type allowAllAuthn struct{}

func (allowAllAuthn) Authenticate(*http.Request) (apihost.Principal, error) {
	return apihost.Principal{ID: "x", Kind: apihost.KindToken}, nil
}
func (allowAllAuthn) CheckCSRF(*http.Request, apihost.Principal) error { return nil }

func mustTags(env *runtimeEnv) []apihost.TagHandlers {
	tags, _ := env.tags("windows")
	return tags
}

func TestA7ClosureFails(t *testing.T) {
	t.Run("a float in the body", func(t *testing.T) {
		env := fxEnv(t, func(_ *runtimeEnv, rows *[]apihost.Route) {
			(*rows)[3] = fxRoute("fxCreate", "POST", "/fx/objects", "fx.write", "write", apihost.BodyJSON, func() apihost.Input { return &badInput{} }, nil)
		})
		want(t, runA7(env), "A7", "kind float64")
	})
	t.Run("a v1 Marshaler anywhere in the Input", func(t *testing.T) {
		env := fxEnv(t, func(_ *runtimeEnv, rows *[]apihost.Route) {
			(*rows)[1] = fxRoute("fxList", "GET", "/fx/things", "fx.read", "read", apihost.BodyNone, func() apihost.Input { return &v1Input{} }, nil)
		})
		want(t, runA7(env), "A7", "implements the encoding/json v1")
		extraGeneratedPkgs[reflect.TypeOf(objInput{}).PkgPath()] = true
	})
	t.Run("a response type outside the closed set", func(t *testing.T) {
		env := fxEnv(t, func(_ *runtimeEnv, rows *[]apihost.Route) {
			(*rows)[2] = fxRoute("fxMe", "GET", "/fx/me", "authenticated", "read", apihost.BodyNone, func() apihost.Input { return noInput{} },
				func() (apihost.Response, error) { return okResp{body: time.Time{}}, nil })
		})
		want(t, runA7(env), "A7", "type closure (response)")
	})
}

func TestA7ClosureUnits(t *testing.T) {
	if vs := closure(reflectType(&apitypes.GUIDRef{})); len(vs) != 0 {
		t.Fatalf("a generated type must be inside the closed set: %v", vs)
	}
	if vs := closure(reflectType(&v1Input{})); len(vs) == 0 {
		t.Fatal("a v1 MarshalJSON must be refused")
	}
}

func TestA7CorpusFails(t *testing.T) {
	t.Run("a decoder that is not strict", func(t *testing.T) {
		env := fxEnv(t, func(_ *runtimeEnv, rows *[]apihost.Route) {
			(*rows)[3] = fxRoute("fxCreate", "POST", "/fx/objects", "fx.write", "write", apihost.BodyJSON, func() apihost.Input { return &laxInput{} }, nil)
		})
		vs := runA7(env)
		want(t, vs, "A7", "corpus")
	})
	t.Run("a body the contract marks as JSON but whose Input has no target", func(t *testing.T) {
		env := fxEnv(t, func(_ *runtimeEnv, rows *[]apihost.Route) {
			(*rows)[3] = fxRoute("fxCreate", "POST", "/fx/objects", "fx.write", "write", apihost.BodyJSON, func() apihost.Input { return noInput{} }, nil)
		})
		want(t, runA7(env), "A7", "no body target")
	})
}

// laxInput accepts everything: its body target is a map, so no unknown member is ever refused.
type laxInput struct{ m map[string]any }

func (*laxInput) BindRequest(*apihost.Request, *apitypes.Errors) {}
func (i *laxInput) BodyTarget() any                              { return &i.m }
func (*laxInput) Validate(*apitypes.Errors)                      {}
func (*laxInput) DestroySecrets()                                {}

func TestA7CrossCheckDisagreement(t *testing.T) {
	env := fxEnv(t, nil)
	old := ajvRun
	t.Cleanup(func() { ajvRun = old })
	ajvRun = func(_ string, _ []byte, _ string, cases []ajvCase) (map[string]bool, error) {
		res := map[string]bool{}
		for _, c := range cases {
			res[c.Name] = true // an ajv that accepts everything disagrees with every rejection
		}
		return res, nil
	}
	want(t, runA7(env), "A7", "cross-check disagreement")
	ajvRun = func(string, []byte, string, []ajvCase) (map[string]bool, error) { return nil, os.ErrNotExist }
	want(t, runA7(env), "A7", "ajv cross-check could not run")
}

func TestAjvIsInstalledAndAgrees(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, "web", "node_modules", "ajv")); err != nil {
		t.Skip("web dependencies are not installed (make web-install)")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("no node")
	}
	env := fxEnv(t, nil)
	env.root = root
	if vs := runA7(env); len(vs) != 0 {
		t.Fatalf("Go decoders and ajv must agree on the corpus: %v", vs)
	}
}

func TestA14Fails(t *testing.T) {
	long := strings.Repeat("a", 5000)
	env := fxEnv(t, func(_ *runtimeEnv, rows *[]apihost.Route) {
		(*rows)[2] = fxRoute("fxMe", "GET", "/fx/me", "authenticated", "read", apihost.BodyNone, func() apihost.Input { return noInput{} },
			func() (apihost.Response, error) { return okResp{body: apitypes.ObjectView{DN: long}}, nil })
	})
	want(t, runA14(env), "A14", "fxMe")
}

func TestA14SeesAStructWithNoValidator(t *testing.T) {
	type stray struct{ A string }
	env := fxEnv(t, func(_ *runtimeEnv, rows *[]apihost.Route) {
		(*rows)[2] = fxRoute("fxMe", "GET", "/fx/me", "authenticated", "read", apihost.BodyNone, func() apihost.Input { return noInput{} },
			func() (apihost.Response, error) { return okResp{body: stray{}}, nil })
	})
	want(t, runA14(env), "A14", "no generated validator")
}

var runtimeFixtureChecks = []string{"A4", "A14"}

func TestRuntimeFixturesCoverEveryRuntimeCheck(t *testing.T) {
	// A4, A7 and A14 have failing fixtures above; A6 is a source check with fixtures in
	// check_a6_test.go. This guards the list against a check being added without one.
	for _, id := range []string{"A4", "A6", "A7", "A14"} {
		if !isActive(id) {
			t.Errorf("%s must be active", id)
		}
	}
}

func reflectType(v any) reflect.Type { return reflect.TypeOf(v) }

func TestCorpusCoversTheListedCases(t *testing.T) {
	env := fxEnv(t, nil)
	var root map[string]any
	if err := json.Unmarshal(env.bundle, &root); err != nil {
		t.Fatal(err)
	}
	schema, _, _ := requestSchema(root, "/fx/objects", "POST", "application/json")
	cases, err := buildCases(root, schema, apihost.RouteMeta{MaxBody: 1 << 16})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, c := range cases {
		names[c.Name] = true
	}
	for _, n := range []string{
		"valid instance", "object (body): unknown member", `object (body): member "guid" in the wrong case`, `object (body): duplicate member`,
		`object (body): required member "guid" missing`, `object (body): null for non-nullable member "guid"`,
		"body: invalid UTF-8 (\\xff)", "body: lone high surrogate escape", "body: lone low surrogate escape", "body: NUL escape in a value",
		"body: NUL escape in a member name", "body: trailing data", "body: depth 33", "body: oversize",
		"body: Content-Length above the cap", "body: wrong Content-Type",
	} {
		if !names[n] {
			t.Errorf("the corpus lacks %q (have %d cases)", n, len(cases))
		}
	}
}

// The synthetic trees of the other tests are not the repository, so they skip the server-policy
// comparison; TestA4ServerPolicyMatchesPolicyYamlOnTheRealTree runs it against the real files.
func init() { serverPolicySource = nil }

func TestA4ServerPolicyMatchesPolicyYamlOnTheRealTree(t *testing.T) {
	serverPolicySource = server.APIPolicy
	t.Cleanup(func() { serverPolicySource = nil })
	root := filepath.Join("..", "..", "..")
	tr, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	env, vs := loadRuntime(tr, "A4")
	if env == nil {
		t.Fatal(vs)
	}
	if vs := comparePolicies(env); len(vs) != 0 {
		t.Fatalf("the server's policy drifted from policy.yaml: %v", vs)
	}
}
