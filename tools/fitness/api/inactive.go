package main

import (
	"fmt"
	"os"
	"path/filepath"
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
		needs: "not asserted here yet: the dialect is rejected by tools/gen/api (make gen-api-check) and vacuum runs in make lint-api; fitness-api does not re-run either"},
	{ID: "A3", Title: "permission",
		needs: "no operation in api/openapi to carry x-permission, and no EP-6 permission catalogue for the runtime half",
		ready: func(_ string, t *tree) bool { return len(t.ops) > 0 }},
	{ID: "A4", Title: "route set (TM-F-ANON)",
		needs: "no apihost.Build router and profile manifests with hostname bindings to probe",
		ready: func(root string, _ *tree) bool { return apihostBuildExists(root) }},
	{ID: "A5", Title: "generated client",
		needs: "not asserted here yet: staleness is make gen-api-check and rule 12 is the web lint; the open-enum type-check fixture is missing"},
	{ID: "A6", Title: "generated server",
		needs: "no module api package (internal/modules/*/api) holding generated handlers",
		ready: func(root string, _ *tree) bool { return globExists(root, "internal/modules/*/api") }},
	{ID: "A7", Title: "strict JSON",
		needs: "no route table to reflect over (apihost.Build) and no operation to derive a corpus from",
		ready: func(root string, _ *tree) bool { return apihostBuildExists(root) }},
	{ID: "A8", Title: "secrets out (TM-F-SECRETOUT)",
		needs: "no operation response in api/openapi to lint for secret markers",
		ready: func(_ string, t *tree) bool { return len(t.ops) > 0 }},
	{ID: "A9", Title: "tenancy",
		needs: "no check in this job by design (ADR-0004): T5 openapi-tenant-param runs in make fitness-tenancy and must itself be active for the ADR to be accepted"},
	{ID: "A10", Title: "versioning",
		needs: "no operation with x-activediq-stability to diff, and no release tag to diff against (oasdiff)",
		ready: func(_ string, t *tree) bool { return len(t.ops) > 0 }},
	{ID: "A11", Title: "problems",
		needs: "no operation error response in api/openapi to check against the problems catalogue",
		ready: func(_ string, t *tree) bool { return len(t.ops) > 0 }},
	{ID: "A12", Title: "limits",
		needs: "no operation in api/openapi carrying a rate class or maxBodyBytes",
		ready: func(_ string, t *tree) bool { return len(t.ops) > 0 }},
	{ID: "A13", Title: "policy hygiene", run: checkA13,
		note: "routes outside the document and hostname bindings cannot be verified until apihost serves routes (A4); an entry naming a host binding fails until then; TM- references are shape-checked only (AN-n rows are resolved)"},
	{ID: "A14", Title: "responses conform",
		needs: "no runtime contract-test harness (apihost.Build plus the shared response validator)",
		ready: func(root string, _ *tree) bool { return apihostBuildExists(root) }},
}

func isActive(id string) bool {
	for _, c := range checks {
		if c.ID == id {
			return c.run != nil
		}
	}
	return false
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

// apihostBuildExists reports a non-test Go file in apihost declaring func Build.
func apihostBuildExists(root string) bool {
	dir := filepath.Join(root, "internal", "platform", "apihost")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err == nil && strings.Contains("\n"+string(b), "\nfunc Build(") {
			return true
		}
	}
	return false
}

func globExists(root, pattern string) bool {
	m, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
	return len(m) > 0
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
		return fmt.Sprintf("fitness-api %-4s %-34s %s", c.ID, c.Title, state)
	}
	line := fmt.Sprintf("fitness-api %-4s %-34s inactive (%s)", c.ID, c.Title, c.needs)
	if c.ready != nil && t != nil && c.ready(root, t) {
		line += " [INPUT NOW PRESENT: this check is overdue; ADR-0004 cannot be accepted]"
	}
	return line
}
