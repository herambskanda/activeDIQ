package main

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"sort"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// checkA4 is ADR-0004 A4 (TM-F-ANON): for each profile it
// builds the router with apihost.Build and checks the served route set, the anonymous set per
// hostname binding and on an unbound hostname, then probes every route over HTTP.
func checkA4(t *tree) []Violation {
	env, vs := loadRuntime(t, "A4")
	if env == nil {
		return vs
	}
	return runA4(env)
}

func runA4(env *runtimeEnv) []Violation {
	var vs []Violation
	for _, prof := range env.profiles {
		vs = append(vs, a4Profile(env, prof)...)
	}
	return vs
}

func a4Profile(env *runtimeEnv, prof string) []Violation {
	var vs []Violation
	add := func(f string, a ...any) { vs = append(vs, fail("A4", "profile "+prof, f, a...)) }
	tags, err := env.tags(prof)
	if err != nil {
		return []Violation{fail("A4", "profile "+prof, "the module list could not be read: %v (ADR-0004 A4)", err)}
	}
	srv, err := apihost.Build(env.doc, tags, env.policy, catalogueOf(env.doc), probePorts{}.ports(), quiet)
	if err != nil {
		return []Violation{fail("A4", "profile "+prof, "apihost.Build refuses the contract and policy: %v (ADR-0004 rule 5)", err)}
	}

	mounted := map[string]bool{}
	media := map[string]string{} // operationId → request media type
	for _, th := range tags {
		mounted[th.Tag()] = true
		for _, rt := range th.Routes() {
			media[rt.Meta().OperationID] = rt.Meta().MediaType
		}
	}
	// 1. The routes served are exactly the operations of the enabled tags.
	want := map[string]apihost.Operation{}
	for _, o := range env.doc.Operations() {
		if mounted[o.Tag] {
			want[o.Method+" "+apiPrefix+o.Path] = o
		}
	}
	got := map[string]apihost.RouteInfo{}
	for _, r := range srv.Routes() {
		got[r.Method+" "+r.Path] = r
	}
	for _, k := range sortedKeys(want) {
		if _, ok := got[k]; !ok {
			add("misses %s (%s), an operation of an enabled tag (ADR-0004 A4)", k, want[k].ID)
		}
	}
	for _, k := range sortedKeys(got) {
		if _, ok := want[k]; !ok {
			add("serves %s, which is not an operation of an enabled tag (ADR-0004 A4)", k)
		}
	}

	// 2. The anonymous set equals policy.anonymous, per bound hostname.
	rows := map[string]apihost.AnonymousRow{}
	for _, r := range env.policy.Anonymous {
		rows[r.Operation] = r
	}
	served := map[string]string{} // operation → host it is bound to
	for _, r := range srv.Routes() {
		if r.Anonymous {
			served[r.OperationID] = r.Host
		}
	}
	for _, id := range sortedKeys(served) {
		row, ok := rows[id]
		if !ok {
			add("serves %s without authentication but policy.anonymous has no row for it (ADR-0004 A4, TM-F-ANON)", id)
			continue
		}
		if wantHost := env.policy.Hosts[row.Host]; wantHost != served[id] {
			add("%s is served on host %q but policy.anonymous binds it to %q (ADR-0004 A4)", id, served[id], wantHost)
		}
	}
	opByID := map[string]apihost.Operation{}
	for _, o := range env.doc.Operations() {
		opByID[o.ID] = o
	}
	for _, id := range sortedKeys(rows) {
		o, inDoc := opByID[id]
		if !inDoc || !mounted[o.Tag] {
			continue
		}
		if _, ok := served[id]; !ok {
			add("policy.anonymous lists %s but the router does not serve it without authentication (ADR-0004 A4, TM-F-ANON)", id)
		}
	}

	// 3. Routes outside the document equal nonApiRoutes plus the anonymous routes outside it.
	if srvd, ok := env.nonAPISrv(prof); ok {
		wantN := map[string]bool{}
		for _, r := range env.nonAPI {
			wantN[r.Method+" "+r.Path] = true
		}
		gotN := map[string]bool{}
		for _, r := range srvd {
			gotN[r] = true
		}
		for _, k := range sortedKeys(wantN) {
			if !gotN[k] {
				add("does not serve %s, a nonApiRoutes entry (ADR-0004 A4)", k)
			}
		}
		for _, k := range sortedKeys(gotN) {
			if !wantN[k] {
				add("serves %s outside the document and it is not in nonApiRoutes (ADR-0004 A4)", k)
			}
		}
	}

	// 4. The HTTP probe: the middleware enforces what the table says.
	for _, r := range srv.Routes() {
		vs = append(vs, probeRoute(prof, srv, r, media[r.OperationID])...)
	}
	return vs
}

type probeResult struct {
	status int
	typ    string
}

func send(srv http.Handler, method, host, path, ct, principal string, csrf bool) probeResult {
	req := httptest.NewRequest(method, path, nil)
	req.Host = host
	req.RemoteAddr = "192.0.2.1:1234"
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if principal != "" {
		req.Header.Set(principalHeader, principal)
	}
	if csrf {
		req.Header.Set("X-CSRF-Token", "t")
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var p struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &p)
	return probeResult{rec.Code, p.Type}
}

func probeRoute(prof string, srv http.Handler, r apihost.RouteInfo, ct string) []Violation {
	var vs []Violation
	where := "profile " + prof
	bad := func(f string, a ...any) {
		vs = append(vs, fail("A4", where, "%s %s (%s): "+f+" (ADR-0004 A4)", append([]any{r.Method, r.Path, r.OperationID}, a...)...))
	}
	path := concretePath(r.Path)
	host := "api.fitness.invalid"
	if r.Host != "" {
		host = r.Host
	}
	if r.Anonymous {
		if res := send(srv, r.Method, host, path, ct, "", false); res.status == 401 || res.status == 403 {
			bad("an anonymous route answered %d to an unauthenticated request", res.status)
		}
		if r.Host != "" {
			if res := send(srv, r.Method, "other.fitness.invalid", path, ct, "", false); res.status != 404 {
				bad("bound to host %q but answered %d on an unbound hostname, not 404", r.Host, res.status)
			}
		}
		return vs
	}
	if res := send(srv, r.Method, host, path, ct, "", false); res.status != 401 {
		bad("answered %d to an unauthenticated request, want 401", res.status)
	}
	authenticatedOnly := r.Permission == "authenticated"
	res := send(srv, r.Method, host, path, ct, "nobody", false)
	switch {
	case authenticatedOnly && res.status == 403:
		bad("an authenticated route answered 403 to a principal with no permissions")
	case !authenticatedOnly && res.status != 403:
		bad("answered %d to a principal with no permissions, want 403", res.status)
	}
	if isUnsafeMethod(r.Method) {
		if res := send(srv, r.Method, host, path, ct, "session", false); res.typ != apitypes.ProblemTypeCSRFFailed {
			bad("a cookie-session request without the CSRF header answered %d %q, want %s", res.status, res.typ, apitypes.ProblemTypeCSRFFailed)
		}
	}
	return vs
}

func isUnsafeMethod(m string) bool {
	switch m {
	case "GET", "HEAD", "OPTIONS":
		return false
	}
	return true
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
