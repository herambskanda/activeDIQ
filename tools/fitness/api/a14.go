package main

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"net/http/httptest"
	"reflect"
	"sort"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitest"
)

// checkA14 is ADR-0004 A14 (responses conform): every route is called through the shared harness
// (internal/platform/apihost/apitest) with a principal who may do anything, a valid body where the
// operation takes one, and each response body a handler returns is validated against the schema
// the contract declares, with the generated validators, before it is encoded.
func checkA14(t *tree) []Violation {
	env, vs := loadRuntime(t, "A14")
	if env == nil {
		return vs
	}
	return runA14(env)
}

func runA14(env *runtimeEnv) []Violation {
	var vs []Violation
	for _, prof := range env.profiles {
		rec, errs := probeAll(env, prof)
		vs = append(vs, errs...)
		if rec == nil {
			continue
		}
		for _, m := range rec.All() {
			vs = append(vs, fail("A14", "profile "+prof, "response does not conform to its declared schema: %s (ADR-0004 A14)", m))
		}
	}
	return vs
}

// probeAll builds the router for a profile with every handler behind the conformance harness and
// calls every route once, authorised. It returns what the harness recorded. A problem building
// or reading the bundle is returned as violations of A14.
func probeAll(env *runtimeEnv, prof string) (*apitest.Recorder, []Violation) {
	tags, err := env.tags(prof)
	if err != nil {
		return nil, []Violation{fail("A14", "profile "+prof, "the module list could not be read: %v (ADR-0004 A14)", err)}
	}
	var root map[string]any
	if err := json.Unmarshal(env.bundle, &root); err != nil {
		return nil, []Violation{fail("A14", bundleRel, "the bundle does not parse: %v (ADR-0004 A14)", err)}
	}
	rec := &apitest.Recorder{}
	srv, err := apihost.Build(env.doc, apitest.Conform(rec, tags...), env.policy, catalogueOf(env.doc), corpusPorts{}.ports(), apihost.WithBodyBudget(1<<30), quiet)
	if err != nil {
		return nil, []Violation{fail("A14", "profile "+prof, "apihost.Build refuses the contract and policy: %v (ADR-0004 rule 5)", err)}
	}
	var vs []Violation
	metas := map[string]apihost.RouteMeta{}
	for _, th := range tags {
		for _, rt := range th.Routes() {
			metas[rt.Meta().OperationID] = rt.Meta()
		}
	}
	for _, r := range srv.Routes() {
		meta := metas[r.OperationID]
		var body []byte
		if meta.Body == apihost.BodyJSON || meta.Body == apihost.BodyMergePatch {
			schema, _, ok := requestSchema(root, meta.Path, meta.Method, meta.MediaType)
			if ok {
				inst, err := genInstance(root, schema, nil)
				if err != nil {
					vs = append(vs, fail("A14", "profile "+prof+", "+r.OperationID, "cannot generate a valid request body: %v (ADR-0004 A14)", err))
					continue
				}
				body = encode(inst.value)
			}
		}
		host := "api.fitness.invalid"
		if r.Host != "" {
			host = r.Host
		}
		req := httptest.NewRequest(r.Method, concretePath(r.Path), bytes.NewReader(body))
		req.Host, req.RemoteAddr = host, "192.0.2.1:1234"
		if meta.MediaType != "" {
			req.Header.Set("Content-Type", meta.MediaType)
		}
		req.Header.Set(principalHeader, "nobody")
		srv.ServeHTTP(httptest.NewRecorder(), req)
	}
	return rec, vs
}

// observedClosure runs the A7 type closure over the response types the harness saw.
func observedClosure(env *runtimeEnv, prof string, rec *apitest.Recorder) []Violation {
	var vs []Violation
	obs := rec.Observed()
	ids := make([]string, 0, len(obs))
	for id := range obs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	seen := map[reflect.Type]bool{}
	for _, id := range ids {
		for _, t := range obs[id] {
			if seen[t] {
				continue
			}
			seen[t] = true
			for _, m := range closure(t) {
				vs = append(vs, fail("A7", fmt.Sprintf("profile %s, %s", prof, id), "type closure (response): %s (ADR-0004 A7)", m))
			}
		}
	}
	return vs
}
