package main

import (
	"fmt"
	"sort"
	"strings"
)

// checkInfo is one row of the ADR-0004 fitness table.
type checkInfo struct {
	ID    string
	Title string
	// run is set for a check this job implements. Everything else is reported inactive.
	run func(*tree) []Violation
	// needs names the input that does not exist yet (or the work not yet done), printed on every run.
	needs string
	// note qualifies an active check: what it does not cover yet.
	note string
	// rest names the part of an active check that is still inactive (its runtime half). A check with
	// a rest prints "active" for what runs and "inactive part" for the rest, and ADR-0004 is not
	// accepted while any rest is non-empty. It is a function so a rest can end with its input.
	rest func(root string, t *tree) string
	// restReady reports that the input of the rest now exists, so the rest is overdue.
	restReady func(root string, t *tree) bool
	// ready reports that the missing input now exists, so the check is overdue (printed, not failed:
	// the ADR does not turn the job red for a check that is merely late, it keeps the ADR unaccepted).
	ready func(root string, t *tree) bool
}

// checks is A1 to A14 in ADR-0004's order. Do not add a check that prints "active" without a run
// function and a failing fixture in check_test.go (TestEveryActiveCheckHasAFailingFixture).
var checks = []checkInfo{
	{ID: "A1", Title: "layout and sources", run: checkA1,
		note: "bundle staleness is make gen-api-check, not repeated here"},
	{ID: "A2", Title: "dialect and style",
		needs: "owned by tools/gen/api (rejects the dialect, make gen-api-check) and vacuum (make lint-api), both in make ci; fitness-api does not re-run either, so the ADR owner must accept that delegation or ask for a re-run here"},
	{ID: "A3", Title: "permission", run: checkA3,
		note: "document half: x-permission, anonymous and authenticated rows",
		rest: func(string, *tree) string {
			return "runtime half: no EP-6 permission catalogue (Registrar and kernel contributions) to check each x-permission against"
		}},
	{ID: "A4", Title: "route set (TM-F-ANON)", run: checkA4,
		note: "per profile (windows, linux-oci, saas): apihost.Build, served set against the enabled tags, the anonymous set per hostname binding and on an unbound hostname, and the HTTP probe (401, 403, CSRF)",
		rest: func(root string, _ *tree) string { return runtimeGap(root, true) }},
	{ID: "A5", Title: "generated client", run: checkA5,
		note: "generated types cover every operation, open enums widened with a type-check fixture, web/src/api file set, rule 12 ESLint rule wired; byte-for-byte staleness is make gen-api-check and the rule 12 fire-test is make ci-proof"},
	{ID: "A6", Title: "generated server", run: checkA6,
		note: "source half: route constructors only in generated files, Registrar.API takes api.Bind, no net/http in handler packages, apihost imports no API-serving kernel package, api packages are generated only; *.gen.go staleness is make gen-api-check"},
	{ID: "A7", Title: "strict JSON", run: checkA7,
		note: "static half, then per profile over apihost.Build: type closure of Input, body target and observed responses, the generated corpus through the router, and the ajv cross-check on the same bundle",
		rest: func(root string, _ *tree) string {
			r := "secret-buffer zeroing is not observed (apihost has no test-build hook yet); " + runtimeGap(root, false)
			if n := len(jsonV1Debt(root)); n > 0 {
				r += fmt.Sprintf("; %d file(s) still import encoding/json v1 under the baseline tools/fitness/api/json-v1-baseline.txt", n)
			}
			return r
		},
	},
	{ID: "A8", Title: "secrets out (TM-F-SECRETOUT)", run: checkA8,
		note: "linter half",
		rest: func(string, *tree) string {
			return "runtime half: the canary through every sink (T-0033, T-0034)"
		}},
	{ID: "A9", Title: "tenancy",
		needs: "no check in this job by design (ADR-0004): T5 openapi-tenant-param runs in make fitness-tenancy and must itself be active for the ADR to be accepted"},
	{ID: "A10", Title: "versioning", run: checkA10,
		note: "stability, sunset, and oasdiff of the stable operations against main",
		rest: func(root string, _ *tree) string {
			if latestReleaseTag(root) == "" {
				return "no release tag (v<major>.<minor>.<patch>) exists yet to diff against; the tag diff starts with the first release"
			}
			return ""
		}},
	{ID: "A11", Title: "problems", run: checkA11},
	{ID: "A12", Title: "limits", run: checkA12},
	{ID: "A13", Title: "policy hygiene", run: checkA13,
		note: "host bindings are looked up in the apihost table; a route outside the document is matched against the routes the server mounts, once any is mounted; TM- references are shape-checked only (AN-n rows are resolved)",
		rest: func(root string, _ *tree) string {
			if _, ok := nonAPIServedSource(""); !ok {
				return "no server mounts a route outside the document yet (/healthz, /readyz, the console), so anonymous and nonApiRoutes entries naming one cannot be matched to a served route"
			}
			return ""
		}},
	{ID: "A14", Title: "responses conform", run: checkA14,
		note: "every route is called through internal/platform/apihost/apitest, which validates each response body with the generated validators; module contract tests use the same harness"},
}

func isActive(id string) bool {
	for _, c := range checks {
		if c.ID == id {
			return c.run != nil
		}
	}
	return false
}

// jsonV1Debt lists the baselined files that still import encoding/json (v1).
func jsonV1Debt(root string) []string {
	b, _ := jsonV1Baseline(root)
	var out []string
	for f := range b {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func activeIDs() []string {
	var out []string
	for _, c := range checks {
		if c.run != nil {
			out = append(out, c.ID)
		}
	}
	return out
}

// runtimeGap names what the runtime checks cannot see yet: routes no module mounts. The real tag
// source is the module list, and Registrar.API does not exist, so a generated api package is not
// reachable from it. nonAPI adds the routes outside the document.
func runtimeGap(root string, nonAPI bool) string {
	var pkgs []string
	for d := range apiPackageDirs(root) {
		pkgs = append(pkgs, d)
	}
	sort.Strings(pkgs)
	var r []string
	if len(pkgs) > 0 {
		r = append(r, fmt.Sprintf("generated api package(s) no module mounts yet: %s (Registrar.API is not built), so the router the checks build serves no route and they run on fixtures only", strings.Join(pkgs, ", ")))
	}
	if nonAPI {
		if _, ok := nonAPIServedSource(""); !ok {
			r = append(r, "no server mounts a route outside the document, so nonApiRoutes is not compared with a served set")
		}
	}
	return strings.Join(r, "; ")
}

// restText is the unfinished part of an active check, "" when there is none.
func (c checkInfo) restText(root string, t *tree) string {
	if c.run == nil || c.rest == nil || t == nil {
		return ""
	}
	return c.rest(root, t)
}

// statusLine renders one check for the table.
func (c checkInfo) statusLine(root string, t *tree, ranOK bool) string {
	if c.run != nil {
		state := "active"
		if !ranOK {
			state = "active (not run: excluded by -checks)"
		}
		if c.note != "" && ranOK {
			state += " (" + c.note + ")"
		}
		if r := c.restText(root, t); r != "" {
			state += "; inactive part: " + r
			if c.restReady != nil && c.restReady(root, t) {
				state += " [INPUT NOW PRESENT: this part is overdue; ADR-0004 cannot be accepted]"
			}
		}
		return fmt.Sprintf("fitness-api %-4s %-34s %s", c.ID, c.Title, state)
	}
	line := fmt.Sprintf("fitness-api %-4s %-34s inactive (%s)", c.ID, c.Title, c.needs)
	if c.ready != nil && t != nil && c.ready(root, t) {
		line += " [INPUT NOW PRESENT: this check is overdue; ADR-0004 cannot be accepted]"
	}
	return line
}
