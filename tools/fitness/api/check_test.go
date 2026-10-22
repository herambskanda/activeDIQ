package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// base is a small valid contract tree: one module (users), one kernel package (jobs), a shared
// component, a policy with one entry per section, and a bundle that agrees with the sources.
func base() map[string]string {
	return map[string]string{
		"internal/modules/users/doc.go":  "package users\n",
		"internal/platform/jobs/doc.go":  "package jobs\n",
		"api/openapi/openapi.yaml":       rootYAML("users", "platform.jobs"),
		"api/openapi/.vacuum.yaml":       "extends: [[spectral:oas, recommended]]\n",
		"api/openapi/shared/paging.yaml": "components:\n  schemas:\n    Cursor:\n      type: string\n",
		"api/openapi/modules/users.yaml": `paths:
  /users:
    get:
      operationId: listUsers
      tags: [users]
      x-permission: users.read
      x-activediq-stability: stable
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: shared/paging.yaml#/components/schemas/Cursor
        "400":
          $ref: shared/problems.yaml#/components/responses/Validation
  /users/{id}/reset:
    post:
      operationId: resetUser
      tags: [users]
      x-permission: secret.reveal
      x-activediq-stability: stable
      x-activediq-limits:
        class: reveal
components:
  schemas:
    User:
      type: object
      properties:
        next:
          $ref: '#/components/schemas/Name'
    Name:
      type: string
    Mode:
      type: string
      x-activediq-enum: open
      enum: [a, b]
`,
		"api/openapi/platform/jobs.yaml": `paths:
  /jobs:
    get:
      operationId: listJobs
      tags: [platform.jobs]
      x-permission: authenticated
      x-activediq-stability: stable
components:
  schemas:
    Job:
      type: string
`,
		"api/openapi/shared/problems.yaml":                   baseProblems,
		"web/src/api/schema.gen.d.ts":                        baseGenTS,
		"web/src/api/client.ts":                              "export {};\n",
		"web/src/api/client.test.ts":                         "import type { components } from \"./schema.gen\";\nexport const future: components[\"schemas\"][\"Mode\"] = \"from-the-future\";\n",
		"web/eslint.config.js":                               baseESLint,
		"web/proof/api-client-violation.ts":                  "export const a = fetch(\"/x\");\n",
		"api/openapi/policy.yaml":                            basePolicy,
		"knowledge/development/architecture/threat-model.md": "| AN-1 | Health | x | None |\n| AN-2 | Static | x | None |\n",
		"internal/platform/apihost/spec/openapi.gen.json":    `{"paths": {"/users": {"get": {}}, "/users/{id}/reset": {"post": {}}, "/jobs": {"get": {}}}}`,
	}
}

const baseProblems = `components:
  schemas:
    Problem:
      type: object
      required: [type, title, status]
      properties:
        type: {type: string}
        title: {type: string}
        status: {type: integer, minimum: 400, maximum: 599}
  responses:
    Validation:
      description: The request is invalid
      content:
        application/problem+json:
          schema:
            $ref: shared/problems.yaml#/components/schemas/Problem
          example:
            type: /problems/validation
            title: The request is invalid
            status: 400
`

const baseGenTS = `export interface components {
    schemas: {
        Mode: "a" | "b" | (string & {});
    };
}
export interface operations {
    listUsers: {
    };
    resetUser: {
    };
    listJobs: {
    };
}
`

const baseESLint = `const g = ["fetch", "XMLHttpRequest", "EventSource"]; // axios
const lit = "Literal[value=/^\\\\/api(\\\\/|$)/]"; // files: src/api exempt
`

const basePolicy = `# the six rule 9 sections
anonymous:
  - method: GET
    path: /healthz
    ref: AN-1
    gate: none
    reason: Load balancers probe liveness before any login exists.
authenticated:
  - operation: listJobs
    ref: TM-D16
    reason: Any signed-in principal may see the job list.
nonApiRoutes:
  - method: GET
    path: /readyz
    ref: AN-1
    reason: Readiness probe, status only.
secretResponses:
  - operation: resetUser
    schema: User
    ref: TM-F-SECRETOUT
    reason: Shows the new password once.
stepUp:
  - permission: secret.reveal
    ref: TM-D16
    reason: Resetting a password needs a fresh MFA.
largeBodies:
  - operation: listUsers
    ref: TM-Q2
    reason: Import of a large directory export.
`

func rootYAML(tags ...string) string {
	var b strings.Builder
	b.WriteString("openapi: 3.1.0\ninfo: {title: t, version: 0.0.0}\nservers: [{url: /api/v1}]\ntags:\n")
	for _, t := range tags {
		b.WriteString("  - name: " + t + "\n")
	}
	return b.String()
}

func write(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func run(t *testing.T, files map[string]string) []Violation {
	t.Helper()
	rep, err := Run(write(t, files), nil)
	if err != nil {
		t.Fatal(err)
	}
	return rep.Violations
}

// fixture is one deliberate violation. The coverage test requires every active check to have at
// least one, so a check cannot go active without a failing run.
type fixture struct {
	name   string
	check  string // the violation's Check: A1, A13 or self-test
	mutate func(f map[string]string)
	pos    string // the violation must be reported at a position containing this (the file)
	want   string // and its message must contain this (the rule)
}

func repl(f map[string]string, file, old, new string) {
	if !strings.Contains(f[file], old) {
		panic("fixture is stale: " + file + " lacks " + old)
	}
	f[file] = strings.Replace(f[file], old, new, 1)
}

var fixtures = []fixture{
	// --- A1 -----------------------------------------------------------------------------------
	{"misplaced file", "A1", func(f map[string]string) { f["api/openapi/extra/stray.yaml"] = "a: b\n" },
		"api/openapi/extra/stray.yaml", "outside the rule 1 places"},
	{"non-yaml file", "A1", func(f map[string]string) { f["api/openapi/modules/users.json"] = "{}" },
		"api/openapi/modules/users.json", "only .yaml files"},
	{"module file with an unknown module id", "A1", func(f map[string]string) {
		f["api/openapi/modules/ghost.yaml"] = "components:\n  schemas:\n    Ghost:\n      type: string\n"
	}, "api/openapi/modules/ghost.yaml", "not in the module list"},
	{"platform file with no kernel package", "A1", func(f map[string]string) {
		f["api/openapi/platform/phantom.yaml"] = "components:\n  schemas:\n    Phantom:\n      type: string\n"
	}, "api/openapi/platform/phantom.yaml", "no internal/platform/phantom"},
	{"operation with two tags", "A1", func(f map[string]string) {
		repl(f, "api/openapi/modules/users.yaml", "operationId: listUsers\n      tags: [users]", "operationId: listUsers\n      tags: [users, platform.jobs]")
	}, "api/openapi/modules/users.yaml", "has 2 tags; an operation has exactly one"},
	{"operation with no tag", "A1", func(f map[string]string) {
		repl(f, "api/openapi/modules/users.yaml", "operationId: listUsers\n      tags: [users]", "operationId: listUsers")
	}, "api/openapi/modules/users.yaml", "has 0 tags"},
	{"operation tagged for another file", "A1", func(f map[string]string) {
		repl(f, "api/openapi/modules/users.yaml", "operationId: listUsers\n      tags: [users]", "operationId: listUsers\n      tags: [platform.jobs]")
	}, "api/openapi/modules/users.yaml", `whose tag is "users"`},
	{"duplicate operationId", "A1", func(f map[string]string) {
		repl(f, "api/openapi/platform/jobs.yaml", "listJobs", "listUsers")
	}, "api/openapi/platform/jobs.yaml", `duplicate operationId "listUsers"`},
	{"duplicate component name", "A1", func(f map[string]string) {
		repl(f, "api/openapi/platform/jobs.yaml", "    Job:", "    Name:")
	}, "api/openapi/platform/jobs.yaml", "duplicate component schemas/Name"},
	{"component not PascalCase", "A1", func(f map[string]string) {
		repl(f, "api/openapi/platform/jobs.yaml", "    Job:", "    job:")
	}, "api/openapi/platform/jobs.yaml", "not PascalCase"},
	{"cross-module $ref", "A1", func(f map[string]string) {
		repl(f, "api/openapi/modules/users.yaml", "$ref: '#/components/schemas/Name'", "$ref: platform/jobs.yaml#/components/schemas/Job")
	}, "api/openapi/modules/users.yaml", "cross-module reference"},
	{"shared references a module", "A1", func(f map[string]string) {
		f["api/openapi/shared/paging.yaml"] = "components:\n  schemas:\n    Cursor:\n      $ref: modules/users.yaml#/components/schemas/User\n"
	}, "api/openapi/shared/paging.yaml", "shared/ may reference only shared/"},
	{"upward $ref", "A1", func(f map[string]string) {
		repl(f, "api/openapi/modules/users.yaml", "$ref: '#/components/schemas/Name'", "$ref: ../../secret/x.yaml#/components/schemas/Name")
	}, "api/openapi/modules/users.yaml", "upward reference"},
	{"$ref into a component another file declares, written locally", "A1", func(f map[string]string) {
		repl(f, "api/openapi/modules/users.yaml", "$ref: '#/components/schemas/Name'", "$ref: '#/components/schemas/Job'")
	}, "api/openapi/modules/users.yaml", "is declared in platform/jobs.yaml, not in modules/users.yaml"},
	{"$ref to nothing", "A1", func(f map[string]string) {
		repl(f, "api/openapi/modules/users.yaml", "$ref: '#/components/schemas/Name'", "$ref: '#/components/schemas/Nope'")
	}, "api/openapi/modules/users.yaml", "no file declares"},
	{"tag file missing from the root tag list", "A1", func(f map[string]string) {
		f["api/openapi/openapi.yaml"] = rootYAML("users")
	}, "api/openapi/platform/jobs.yaml", "missing from the root tag list"},
	{"root tag with no file", "A1", func(f map[string]string) {
		f["api/openapi/openapi.yaml"] = rootYAML("users", "platform.jobs", "billing")
	}, "api/openapi/openapi.yaml", `tag "billing" has no file`},
	{"path item key that is not a method", "A1", func(f map[string]string) {
		repl(f, "api/openapi/platform/jobs.yaml", "    get:", "    summary: x\n    get:")
	}, "api/openapi/platform/jobs.yaml", `"summary" is not an HTTP method`},
	{"unparsable file", "A1", func(f map[string]string) { f["api/openapi/shared/bad.yaml"] = "a: [unclosed\n" },
		"api/openapi/shared/bad.yaml", "cannot parse"},
	{"missing root document", "A1", func(f map[string]string) { delete(f, "api/openapi/openapi.yaml") },
		"api/openapi/openapi.yaml", "root document is missing"},

	// --- A13 ----------------------------------------------------------------------------------
	{"policy entry naming a missing operation", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "operation: listJobs", "operation: deleteEverything")
	}, "api/openapi/policy.yaml", `operation "deleteEverything" is not in the contract`},
	{"policy entry with no reason", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "    reason: Any signed-in principal may see the job list.\n", "")
	}, "api/openapi/policy.yaml", "no reason"},
	{"policy entry with a blank reason", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "reason: Any signed-in principal may see the job list.", "reason: '   '")
	}, "api/openapi/policy.yaml", "no reason"},
	{"policy entry with no AN/TM reference", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "    ref: TM-D16\n    reason: Any signed-in", "    reason: Any signed-in")
	}, "api/openapi/policy.yaml", "no AN/TM reference"},
	{"policy entry whose reference is not AN or TM", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "ref: TM-D16\n    reason: Any signed-in", "ref: because\n    reason: Any signed-in")
	}, "api/openapi/policy.yaml", "no AN/TM reference"},
	{"stepUp permission no operation declares", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "permission: secret.reveal", "permission: users.vaporise")
	}, "api/openapi/policy.yaml", `no operation declares x-permission "users.vaporise"`},
	{"policy entry naming a missing route", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "  - method: GET\n    path: /healthz", "  - method: GET\n    path: /api/v1/ghosts")
	}, "api/openapi/policy.yaml", "no operation GET /ghosts"},
	{"policy entry whose method does not match the operation", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "  - method: GET\n    path: /healthz", "  - operation: listJobs\n    method: DELETE")
	}, "api/openapi/policy.yaml", "stale: operation \"listJobs\" is GET /jobs, not DELETE"},
	{"policy entry naming a missing hostname binding", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "    gate: none\n", "    gate: none\n    host: enduser\n")
	}, "api/openapi/policy.yaml", `hostname binding "enduser"`},
	{"secret response schema that does not exist", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "schema: User", "schema: Missing")
	}, "api/openapi/policy.yaml", `response schema "Missing" is not declared`},
	{"secret response naming no schema", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "    schema: User\n", "")
	}, "api/openapi/policy.yaml", "names no response schema"},
	{"non-API route under /api/", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "path: /readyz", "path: /api/v1/jobs")
	}, "api/openapi/policy.yaml", "cannot live under /api/"},
	{"policy entry with a field the schema does not have", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "    gate: none\n", "    gate: none\n    reasn: typo\n")
	}, "api/openapi/policy.yaml", `unknown field "reasn"`},
	{"policy section dropped", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "stepUp:\n", "stepup:\n")
	}, "api/openapi/policy.yaml", `section "stepUp" must be a list`},
	{"policy.yaml missing", "A13", func(f map[string]string) { delete(f, "api/openapi/policy.yaml") },
		"api/openapi/policy.yaml", "policy.yaml is missing"},

	{"duplicate anonymous section in flow style", "A13", func(f map[string]string) {
		f["api/openapi/policy.yaml"] += "anonymous: [{operation: deleteAllUsers}]\n"
	}, "api/openapi/policy.yaml", `duplicate mapping key "anonymous"`},
	{"duplicate field inside a policy entry", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "  - operation: listJobs\n", "  - operation: listJobs\n    operation: other\n")
	}, "api/openapi/policy.yaml", `duplicate mapping key "operation"`},
	{"duplicate paths key in a module file", "A1", func(f map[string]string) {
		f["api/openapi/modules/users.yaml"] += "paths:\n  /hidden:\n    get:\n      operationId: hidden\n      tags: [users]\n"
	}, "api/openapi/modules/users.yaml", `duplicate mapping key "paths"`},
	{"anonymous entry citing an AN row that does not exist", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "    ref: AN-1\n    gate: none", "    ref: AN-99\n    gate: none")
	}, "api/openapi/policy.yaml", "AN-99 is not a row"},
	{"anonymous entry citing only a TM token", "A13", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "    ref: AN-1\n    gate: none", "    ref: TM-D16\n    gate: none")
	}, "api/openapi/policy.yaml", "must cite the AN-n row"},
	{"threat model with no AN rows", "self-test", func(f map[string]string) {
		f["knowledge/development/architecture/threat-model.md"] = "# nothing\n"
	}, "threat-model.md", "no AN-n rows"},

	// --- self-test (M12): a check that finds nothing where the tree has something fails --------
	{"bundle has operations but no tag file was read", "self-test", func(f map[string]string) {
		delete(f, "api/openapi/modules/users.yaml")
		delete(f, "api/openapi/platform/jobs.yaml")
		f["api/openapi/openapi.yaml"] = rootYAML()
		f["api/openapi/policy.yaml"] = "anonymous: []\nauthenticated: []\nnonApiRoutes: []\nsecretResponses: []\nstepUp: []\nlargeBodies: []\n"
	}, "api/openapi", "holds 3 operation(s) but A1 found 0"},
	{"operations the parser cannot see", "self-test", func(f map[string]string) {
		f["api/openapi/modules/users.yaml"] += "    Hidden:\n      description: |\n        operationId: smuggled\n"
	}, "api/openapi", "plain text count finds 4 operationId"},
	{"no root document and no files", "self-test", func(f map[string]string) {
		for p := range f {
			if strings.HasPrefix(p, "api/openapi/") && p != "api/openapi/.vacuum.yaml" {
				delete(f, p)
			}
		}
	}, "api/openapi", "found no root document and 0 file(s)"},
	{"policy entries where the check does not look", "self-test", func(f map[string]string) {
		repl(f, "api/openapi/policy.yaml", "stepUp:\n  - permission", "stepUp: []\nstepUpp:\n  - permission")
	}, "api/openapi/policy.yaml", "A13 read 5 entr"},
}

func TestFixturesFail(t *testing.T) {
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			f := base()
			fx.mutate(f)
			vs := run(t, f)
			for _, v := range vs {
				if v.Check == fx.check && strings.Contains(v.Pos, fx.pos) && strings.Contains(v.Msg, fx.want) {
					if !strings.Contains(v.String(), "ADR-0004") {
						t.Errorf("a message must name the rule: %s", v)
					}
					return
				}
			}
			t.Fatalf("want a %s violation at %q containing %q; got %v", fx.check, fx.pos, fx.want, vs)
		})
	}
}

// Every active check must have a fixture that makes it fail: a check without a failing run is not
// a check (factory rule). Adding an active check without a fixture breaks this test.
func TestEveryActiveCheckHasAFailingFixture(t *testing.T) {
	have := map[string]bool{}
	for _, fx := range fixtures {
		have[fx.check] = true
	}
	for _, id := range activeIDs() {
		if !have[id] {
			t.Errorf("active check %s has no failing fixture in check_test.go", id)
		}
	}
	if !have["self-test"] {
		t.Error("the M12 self-test has no failing fixture")
	}
}

// The clean tree passes, so the failing fixtures above fail for their own reason and not because
// the base is broken.
func TestBaseTreeIsClean(t *testing.T) {
	if vs := run(t, base()); len(vs) != 0 {
		t.Fatalf("the base tree must be clean, got %v", vs)
	}
}

func TestStatusTable(t *testing.T) {
	rep, err := Run(write(t, base()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Lines) != 14 {
		t.Fatalf("want one line per check A1 to A14, got %d", len(rep.Lines))
	}
	for i, l := range rep.Lines {
		id := checks[i].ID
		if !strings.HasPrefix(l, "fitness-api "+id+" ") {
			t.Errorf("line %d does not start with %s: %q", i, id, l)
		}
		active := checks[i].run != nil
		switch {
		case active && !strings.Contains(l, " active"):
			t.Errorf("%s should print active: %q", id, l)
		case !active && !strings.Contains(l, " inactive ("):
			t.Errorf("%s should print inactive (<missing input>): %q", id, l)
		}
	}
	if got := strings.Join(activeIDs(), ","); got != "A1,A3,A5,A7,A8,A10,A11,A12,A13" {
		t.Errorf("the active checks are A1, A3, A5, A7, A8, A10, A11, A12, A13, got %v", activeIDs())
	}
	if !strings.Contains(rep.Summary(), "5 INACTIVE") {
		t.Errorf("the summary must name the inactive count: %s", rep.Summary())
	}
}

func TestInactiveBecomesOverdueWhenItsInputAppears(t *testing.T) {
	f := base()
	f["internal/platform/apihost/build.go"] = "package apihost\n\nfunc Build() {}\n"
	rep, err := Run(write(t, f), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range rep.Lines {
		if strings.Contains(l, " A4 ") && !strings.Contains(l, "INPUT NOW PRESENT") {
			t.Errorf("A4's input exists but the line does not say the check is overdue: %q", l)
		}
		if strings.Contains(l, " A13 ") && strings.Contains(l, "INPUT NOW PRESENT") {
			t.Errorf("an active check must not be flagged overdue: %q", l)
		}
	}
}

func TestChecksFlagRunsOnlyTheNamedCheck(t *testing.T) {
	f := base()
	repl(f, "api/openapi/policy.yaml", "operation: listJobs", "operation: gone")
	rep, err := Run(write(t, f), map[string]bool{"A1": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range rep.Violations {
		if v.Check == "A13" {
			t.Fatalf("-checks A1 ran A13: %v", v)
		}
	}
}

func TestNoAPIDirectoryIsAnError(t *testing.T) {
	if _, err := Run(write(t, map[string]string{"go.mod": "module x\n"}), nil); err == nil {
		t.Fatal("a tree with no api/openapi must fail, not pass")
	}
}

// The repository itself: the checks must be clean and must see what is there. A1 and A13 are
// active; the committed policy and sources satisfy them.
func TestRepositoryTree(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skip("not run from the repository")
	}
	rep, err := Run(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range rep.Violations {
		t.Errorf("%s", v)
	}
	tr, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.files) == 0 || tr.byRel["openapi.yaml"] == nil || tr.byRel["policy.yaml"] == nil {
		t.Fatalf("the loader saw %d files and not the root and the policy", len(tr.files))
	}
}
