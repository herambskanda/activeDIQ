package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Failing fixtures for the document-side and static checks A3, A5, A7, A8, A10, A11 and A12
// (T-0017). They join the table in check_test.go, so TestFixturesFail and
// TestEveryActiveCheckHasAFailingFixture cover them.
func init() { fixtures = append(fixtures, staticFixtures...) }

const (
	users = "api/openapi/modules/users.yaml"
	jobs  = "api/openapi/platform/jobs.yaml"
	pol   = "api/openapi/policy.yaml"
	gen   = "web/src/api/schema.gen.d.ts"
)

// userResponse makes listUsers return the User schema, and gives User the given extra body.
func userResponse(f map[string]string, userBody string) {
	repl(f, users, "$ref: shared/paging.yaml#/components/schemas/Cursor", "$ref: '#/components/schemas/User'")
	repl(f, users, "    User:\n      type: object\n      properties:\n", "    User:\n      type: object\n      properties:\n"+userBody)
}

func withParam(f map[string]string, param string) {
	repl(f, users, "      x-permission: users.read\n", "      x-permission: users.read\n      parameters:\n"+param)
}

func inlineError(f map[string]string, body string) {
	repl(f, users, `        "400":
          $ref: shared/problems.yaml#/components/responses/Validation
`, "        \"400\":\n          description: bad\n"+body)
}

var staticFixtures = []fixture{
	// --- A3 -----------------------------------------------------------------------------------
	{"operation with no x-permission", "A3", func(f map[string]string) {
		repl(f, users, "      x-permission: secret.reveal\n", "")
	}, users, "has no x-permission"},
	{"operation with two x-permission", "A3", func(f map[string]string) {
		repl(f, users, "      x-permission: secret.reveal\n", "      x-permission: secret.reveal\n      x-permission: users.read\n")
	}, users, "more than one x-permission"},
	{"x-permission that is not a permission ID", "A3", func(f map[string]string) {
		repl(f, users, "x-permission: users.read", "x-permission: 'read users'")
	}, users, "is not a permission ID"},
	{"anonymous operation with no allow-list row named", "A3", func(f map[string]string) {
		repl(f, jobs, "x-permission: authenticated", "x-permission: anonymous")
	}, jobs, "no x-activediq-anonymous"},
	{"anonymous operation naming a row that is not an operation row", "A3", func(f map[string]string) {
		repl(f, jobs, "x-permission: authenticated", "x-permission: anonymous\n      x-activediq-anonymous: AN-2")
	}, jobs, "is not an operation row"},
	{"anonymous operation with no policy row", "A3", func(f map[string]string) {
		repl(f, jobs, "x-permission: authenticated", "x-permission: anonymous\n      x-activediq-anonymous: AN-1")
	}, jobs, "policy.yaml anonymous has no entry"},
	{"authenticated operation with no policy row", "A3", func(f map[string]string) {
		repl(f, pol, "authenticated:\n  - operation: listJobs\n    ref: TM-D16\n    reason: Any signed-in principal may see the job list.\n", "authenticated: []\n")
	}, jobs, "policy.yaml authenticated has no entry"},
	{"policy row that exempts a permissioned operation", "A3", func(f map[string]string) {
		repl(f, pol, "authenticated:\n  - operation: listJobs", "authenticated:\n  - operation: listUsers")
	}, pol, "would exempt a permissioned operation"},
	{"x-activediq-anonymous on a permissioned operation", "A3", func(f map[string]string) {
		repl(f, users, "x-permission: users.read", "x-permission: users.read\n      x-activediq-anonymous: AN-1")
	}, users, "carries x-activediq-anonymous"},

	// --- A5 -----------------------------------------------------------------------------------
	{"hand-written file in web/src/api", "A5", func(f map[string]string) { f["web/src/api/users.ts"] = "export {};\n" },
		"web/src/api/users.ts", "only the generated files"},
	{"generated types missing an operation", "A5", func(f map[string]string) {
		repl(f, gen, "    listJobs: {\n", "")
	}, gen, "operation GET /jobs (listJobs) is in the contract but not in the generated types"},
	{"open enum not widened in the generated types", "A5", func(f map[string]string) {
		repl(f, gen, ` | (string & {})`, "")
	}, "api/openapi/modules/users.yaml", "not widened"},
	{"no open-enum type-check fixture", "A5", func(f map[string]string) {
		f["web/src/api/client.test.ts"] = "export {};\n"
	}, "web/src/api", "no open-enum type-check fixture"},
	{"generated client directory missing", "A5", func(f map[string]string) {
		for p := range f {
			if strings.HasPrefix(p, "web/src/api/") {
				delete(f, p)
			}
		}
	}, "web/src/api", "directory is missing"},
	{"ESLint config that stopped banning XMLHttpRequest", "A5", func(f map[string]string) {
		repl(f, "web/eslint.config.js", `"XMLHttpRequest", `, "")
	}, "web/eslint.config.js", "no longer bans XMLHttpRequest"},
	{"ESLint config that stopped banning /api/ literals", "A5", func(f map[string]string) {
		repl(f, "web/eslint.config.js", "/api", "/x")
	}, "web/eslint.config.js", "no longer bans a string literal starting with /api/"},
	{"rule 12 violation file missing", "A5", func(f map[string]string) { delete(f, "web/proof/api-client-violation.ts") },
		"web/proof/api-client-violation.ts", "missing"},

	// --- A7 static ----------------------------------------------------------------------------
	{"encoding/json v1 import in internal", "A7", func(f map[string]string) {
		f["internal/platform/jobs/x.go"] = "package jobs\n\nimport \"encoding/json\"\n\nvar _ = json.Marshal\n"
	}, "internal/platform/jobs/x.go:3", "imports encoding/json (v1)"},
	{"encoding/json v1 import in cmd", "A7", func(f map[string]string) {
		f["cmd/activediq/main.go"] = "package main\n\nimport j \"encoding/json\"\n\nvar _ = j.Marshal\n\nfunc main() {}\n"
	}, "cmd/activediq/main.go:3", "imports encoding/json (v1)"},
	{"banned v2 option", "A7", func(f map[string]string) {
		f["internal/platform/jobs/x.go"] = "package jobs\n\nimport \"encoding/json/jsontext\"\n\nvar _ = jsontext.AllowInvalidUTF8(true)\n"
	}, "internal/platform/jobs/x.go:5", "uses jsontext.AllowInvalidUTF8"},
	{"case-insensitive name matching option", "A7", func(f map[string]string) {
		f["internal/platform/jobs/x.go"] = "package jobs\n\nimport j \"encoding/json/v2\"\n\nvar _ = j.MatchCaseInsensitiveNames(true)\n"
	}, "internal/platform/jobs/x.go:5", "uses j.MatchCaseInsensitiveNames"},
	{"nojsonv2 in a Makefile", "A7", func(f map[string]string) {
		f["Makefile"] = "build:\n\tGOEXPERIMENT=" + "nojson" + "v2 go build ./...\n"
	}, "Makefile:2", "GOEXPERIMENT contains nojsonv2"},
	{"nojsonv2 in a Dockerfile", "A7", func(f map[string]string) {
		f["deploy/Dockerfile"] = "FROM scratch\nENV GOEXPERIMENT=cgocheck2,no" + "jsonv2\n"
	}, "deploy/Dockerfile:2", "GOEXPERIMENT contains nojsonv2"},
	{"baseline line for a file that no longer imports v1", "A7", func(f map[string]string) {
		f["tools/fitness/api/json-v1-baseline.txt"] = "# baseline\ninternal/platform/jobs/gone.go\n"
	}, "tools/fitness/api/json-v1-baseline.txt:2", "no longer imports encoding/json"},

	// --- A8 -----------------------------------------------------------------------------------
	{"secret-named property reachable from a response", "A8", func(f map[string]string) {
		userResponse(f, "        adminPassword:\n          type: string\n")
	}, users, `property "adminPassword"`},
	{"secret-named property behind an array and a $ref", "A8", func(f map[string]string) {
		repl(f, users, "$ref: shared/paging.yaml#/components/schemas/Cursor", "type: array\n                items:\n                  $ref: '#/components/schemas/User'")
		repl(f, users, "    User:\n      type: object\n      properties:\n", "    User:\n      type: object\n      properties:\n        refreshToken:\n          type: string\n")
	}, users, `property "refreshToken"`},
	{"writeOnly schema reachable from a response", "A8", func(f map[string]string) {
		userResponse(f, "        note:\n          type: string\n          writeOnly: true\n")
	}, users, "writeOnly"},
	{"x-activediq-secret schema reachable from a response", "A8", func(f map[string]string) {
		userResponse(f, "        note:\n          type: string\n          x-activediq-secret: true\n")
	}, users, "x-activediq-secret"},
	{"format password reachable from a response", "A8", func(f map[string]string) {
		userResponse(f, "        note:\n          type: string\n          format: password\n")
	}, users, "format: password"},
	{"credential-named query parameter", "A8", func(f map[string]string) {
		withParam(f, "        - name: api_key\n          in: query\n          schema: {type: string}\n")
	}, users, `query parameter "api_key"`},
	{"apiKey security scheme in the query string", "A8", func(f map[string]string) {
		f["api/openapi/shared/paging.yaml"] += "  securitySchemes:\n    Legacy:\n      type: apiKey\n      in: query\n      name: k\n"
	}, "api/openapi/shared/paging.yaml", "apiKey in the query string"},
	{"secretResponses operation that is not class reveal", "A8", func(f map[string]string) {
		repl(f, users, "      x-activediq-limits:\n        class: reveal\n", "")
	}, pol, "not reveal"},
	{"secretResponses operation without a secret or token-creation permission", "A8", func(f map[string]string) {
		repl(f, users, "x-permission: secret.reveal", "x-permission: users.reset")
	}, pol, "secret.* permission or a token-creation permission"},

	// --- A10 (document side; the diff against main is TestA10* below) -------------------------
	{"operation with no stability", "A10", func(f map[string]string) {
		repl(f, jobs, "      x-activediq-stability: stable\n", "")
	}, jobs, "every operation is preview or stable"},
	{"operation with an unknown stability", "A10", func(f map[string]string) {
		repl(f, jobs, "x-activediq-stability: stable", "x-activediq-stability: beta")
	}, jobs, `"beta"`},
	{"deprecated operation with no sunset", "A10", func(f map[string]string) {
		repl(f, jobs, "x-activediq-stability: stable", "x-activediq-stability: stable\n      deprecated: true")
	}, jobs, "no x-activediq-sunset"},
	{"sunset without deprecated", "A10", func(f map[string]string) {
		repl(f, jobs, "x-activediq-stability: stable", "x-activediq-stability: stable\n      x-activediq-sunset: \"1.4.0\"")
	}, jobs, "is not deprecated: true"},

	// --- A11 ----------------------------------------------------------------------------------
	{"error response that is not problem+json", "A11", func(f map[string]string) {
		inlineError(f, "          content:\n            application/json:\n              schema: {type: object}\n")
	}, users, "is only application/problem+json"},
	{"error response with its own schema", "A11", func(f map[string]string) {
		inlineError(f, "          content:\n            application/problem+json:\n              schema: {type: object}\n")
	}, users, "does not use the shared Problem schema"},
	{"error response with no body", "A11", func(f map[string]string) { inlineError(f, "") }, users, "has no body"},
	{"error response with a type outside the catalogue", "A11", func(f map[string]string) {
		inlineError(f, "          content:\n            application/problem+json:\n              schema:\n                $ref: shared/problems.yaml#/components/schemas/Problem\n              example: {type: /problems/ad-hoc, title: x, status: 400}\n")
	}, users, `"/problems/ad-hoc"`},
	{"component error response outside the catalogue", "A11", func(f map[string]string) {
		f["api/openapi/shared/problems.yaml"] += "    Teapot:\n      description: t\n      content:\n        application/json:\n          example: {type: /problems/teapot, title: t, status: 418}\n"
	}, "api/openapi/shared/problems.yaml", "is only application/problem+json"},
	{"http.Error outside apihost", "A11", func(f map[string]string) {
		f["internal/modules/users/h.go"] = "package users\n\nimport \"net/http\"\n\nfunc H(w http.ResponseWriter) { http.Error(w, \"x\", 400) }\n"
	}, "internal/modules/users/h.go:5", "http.Error in internal/**"},
	{"WriteHeader outside apihost", "A11", func(f map[string]string) {
		f["internal/platform/jobs/h.go"] = "package jobs\n\nimport \"net/http\"\n\nfunc H(w http.ResponseWriter) { w.WriteHeader(500) }\n"
	}, "internal/platform/jobs/h.go:5", "WriteHeader in internal/**"},

	// --- A12 ----------------------------------------------------------------------------------
	{"unknown rate class", "A12", func(f map[string]string) {
		repl(f, users, "class: reveal", "class: turbo")
	}, users, `unknown rate class "turbo"`},
	{"anonymous operation in a read class", "A12", func(f map[string]string) {
		repl(f, jobs, "x-permission: authenticated\n", "x-permission: anonymous\n      x-activediq-anonymous: AN-1\n      x-activediq-limits: {class: read}\n")
	}, jobs, "an anonymous operation declares anonymous or auth"},
	{"anonymous operation with no class", "A12", func(f map[string]string) {
		repl(f, jobs, "x-permission: authenticated", "x-permission: anonymous\n      x-activediq-anonymous: AN-1")
	}, jobs, "an anonymous operation declares anonymous or auth"},
	{"upload with no maxBodyBytes", "A12", func(f map[string]string) {
		repl(f, jobs, "x-activediq-stability: stable\n", "x-activediq-stability: stable\n      requestBody:\n        content:\n          text/csv:\n            schema: {type: string}\n")
	}, jobs, "upload with no maxBodyBytes"},
	{"binary string body with no maxBodyBytes", "A12", func(f map[string]string) {
		repl(f, jobs, "x-activediq-stability: stable\n", "x-activediq-stability: stable\n      requestBody:\n        content:\n          application/json:\n            schema: {type: string, format: binary}\n")
	}, jobs, "(binary) upload with no maxBodyBytes"},
	{"maxBodyBytes above 16 MiB without a largeBodies entry", "A12", func(f map[string]string) {
		repl(f, jobs, "x-activediq-stability: stable\n", "x-activediq-stability: stable\n      x-activediq-limits: {class: bulk, maxBodyBytes: 20971520}\n")
	}, jobs, "above 16 MiB, with no policy largeBodies entry"},
	{"maxBodyBytes that is not a number", "A12", func(f map[string]string) {
		repl(f, jobs, "x-activediq-stability: stable\n", "x-activediq-stability: stable\n      x-activediq-limits: {maxBodyBytes: lots}\n")
	}, jobs, "not a positive integer"},
	{"unknown x-activediq-limits member", "A12", func(f map[string]string) {
		repl(f, jobs, "x-activediq-stability: stable\n", "x-activediq-stability: stable\n      x-activediq-limits: {burst: 9}\n")
	}, jobs, `unknown member "burst"`},
	{"secret operation in the wrong class", "A12", func(f map[string]string) {
		secretOp(f, "{class: write, maxBodyBytes: 4096}", "")
	}, jobs, "accepts a SecretInput but declares rate class"},
	{"secret operation above 64 KiB", "A12", func(f map[string]string) {
		secretOp(f, "{class: secret, maxBodyBytes: 1048576}", "")
	}, jobs, "above the 64 KiB secret cap"},
	{"secret operation with the default body cap", "A12", func(f map[string]string) {
		secretOp(f, "{class: secret}", "")
	}, jobs, "declares no maxBodyBytes"},
	{"secret operation with a binary body", "A12", func(f map[string]string) {
		secretOp(f, "{class: secret, maxBodyBytes: 4096}", "application/octet-stream")
	}, jobs, "a secret body is JSON, never binary"},
	{"AN-8 per-account 429 response", "A12", func(f map[string]string) {
		an8Op(f, "Too many requests from this source-IP.", "        \"429\":\n          description: Too many attempts for this account\n")
	}, jobs, "AN-8 answers 429 only from the source-IP limiter"},
	{"AN-8 429 not described as the source-IP limiter", "A12", func(f map[string]string) {
		an8Op(f, "Rate limited.", "        \"429\":\n          $ref: shared/problems.yaml#/components/responses/RateLimited\n")
	}, jobs, "does not say it is the source-IP limiter"},
}

// an8Op turns listJobs into an AN-8 operation with the given description and a responses block.
func an8Op(f map[string]string, desc, responses string) {
	repl(f, jobs, "x-permission: authenticated\n", "description: "+desc+"\n      x-permission: anonymous\n      x-activediq-anonymous: AN-8\n      x-activediq-limits: {class: auth}\n")
	repl(f, jobs, "x-activediq-stability: stable\n", "x-activediq-stability: stable\n      responses:\n"+responses)
}

// The compliant AN-8 shape (shared RateLimited, described as the source-IP limiter) raises no AN-8 violation.
func TestA12AcceptsAN8SourceIPRateLimit(t *testing.T) {
	f := base()
	an8Op(f, "A 429 here is the source-IP limiter.", "        \"429\":\n          $ref: shared/problems.yaml#/components/responses/RateLimited\n")
	for _, v := range run(t, f) {
		if v.Check == "A12" && strings.Contains(v.Msg, "AN-8") {
			t.Errorf("compliant AN-8 429 refused: %s", v)
		}
	}
}

// secretOp makes listJobs accept a SecretInput body with the given limits (and media type).
func secretOp(f map[string]string, limits, media string) {
	if media == "" {
		media = "application/json"
	}
	repl(f, jobs, "x-activediq-stability: stable\n", "x-activediq-stability: stable\n      x-activediq-limits: "+limits+"\n      requestBody:\n        content:\n          "+media+":\n            schema:\n              $ref: '#/components/schemas/Pw'\n")
	f[jobs] += "    Pw:\n      type: string\n      writeOnly: true\n      x-activediq-secret: true\n"
}

// Rule 9's name list, with its pass and fail names (they are part of the A8 check).
func TestSecretNameMatching(t *testing.T) {
	for _, n := range []string{"password", "Password", "pwd", "secret", "token", "apiKey", "privateKey", "recoveryKey", "clientSecret",
		"adminPassword", "refreshToken", "unicodePwd", "bitlockerRecoveryKey", "newPassword", "client_secret", "api-key", "accessToken"} {
		if _, ok := nameMatches(n, secretWords); !ok {
			t.Errorf("%q must match the secret-name list", n)
		}
	}
	for _, n := range []string{"passwordLastSet", "passwordNeverExpires", "pwdLastSet", "badPwdCount", "maxPwdAge", "tokenGroups", "apiKeyId", "keyboard", "subtoken", "mysecretary", "name", ""} {
		if w, ok := nameMatches(n, secretWords); ok {
			t.Errorf("%q must not match the secret-name list (matched %q)", n, w)
		}
	}
}

func TestA8ExemptsTheSecretResponsesOperations(t *testing.T) {
	f := base()
	userResponse(f, "        adminPassword:\n          type: string\n")
	repl(f, pol, "  - operation: resetUser", "  - operation: listUsers\n    schema: User\n    ref: TM-F-SECRETOUT\n    reason: x.\n  - operation: resetUser")
	repl(f, users, "      x-permission: users.read\n", "      x-permission: secret.reveal\n      x-activediq-limits: {class: reveal}\n")
	for _, v := range run(t, f) {
		if v.Check == "A8" {
			t.Errorf("an operation in secretResponses may return a secret: %s", v)
		}
	}
}

func TestA11IgnoresTestsAndApihost(t *testing.T) {
	f := base()
	src := "package x\n\nimport \"net/http\"\n\nfunc H(w http.ResponseWriter) { http.Error(w, \"x\", 400); w.WriteHeader(500) }\n"
	f["internal/platform/apihost/h.go"] = src
	f["internal/modules/users/h_test.go"] = src
	f["internal/connector/graph/graphtest/fake.go"] = src // fake of an external service, not our API
	f["internal/connector/graph/other/fake.go"] = "package other\n\nimport \"net/http\"\n\nfunc H(w http.ResponseWriter) { w.WriteHeader(500) }\n"
	sibling := false
	for _, v := range run(t, f) {
		if v.Check != "A11" {
			continue
		}
		if strings.Contains(v.Pos, "graph/other/") {
			sibling = true // control: a sibling package is still checked
			continue
		}
		t.Errorf("apihost, tests and external-service fakes may write statuses: %s", v)
	}
	if !sibling {
		t.Error("a package next to graphtest must still be checked")
	}
}

func TestA7LeavesTestsAndToolsAlone(t *testing.T) {
	f := base()
	f["internal/platform/jobs/x_test.go"] = "package jobs\n\nimport \"encoding/json\"\n\nvar _ = json.Marshal\n"
	f["tools/x/x.go"] = "package x\n\nimport \"encoding/json\"\n\nvar _ = json.Marshal\n"
	f["internal/platform/jobs/ok.go"] = "package jobs\n\nimport \"encoding/json/v2\"\n\nvar _ = json.Marshal\n"
	for _, v := range run(t, f) {
		if v.Check == "A7" {
			t.Errorf("tests and tools may use v1, v2 is fine: %s", v)
		}
	}
}

// --- A10: the diff against main -----------------------------------------------------------------

// bundle renders a one-path bundle for the diff tests.
func bundle(version, stability, extra string) string {
	return `{"openapi":"3.1.0","info":{"title":"t","version":"` + version + `"},"paths":{"/jobs":{"get":{"operationId":"listJobs","x-activediq-stability":"` + stability + `"` + extra + `,"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","properties":{"id":{"type":"string"}}}}}}}}}}}`
}

// withBase runs the tree with the current bundle cur and main's bundle base.
func withBase(t *testing.T, mainBundle, cur string) []Violation {
	t.Helper()
	oldBases, oldTools := baseBundles, apitoolsDir
	t.Cleanup(func() { baseBundles, apitoolsDir = oldBases, oldTools })
	baseBundles = func(string) ([]baseDoc, error) { return []baseDoc{{"main", []byte(mainBundle)}}, nil }
	apitoolsDir = func(string) string { return filepath.Join("..", "..", "apitools") }
	f := base()
	f[bundlePath] = cur
	var out []Violation
	for _, v := range run(t, f) {
		if v.Check == "A10" {
			out = append(out, v)
		}
	}
	return out
}

func TestA10Diff(t *testing.T) {
	if testing.Short() {
		t.Skip("runs oasdiff (compiles the tool on first use)")
	}
	if _, err := os.Stat(filepath.Join("..", "..", "apitools", "go.mod")); err != nil {
		t.Skip("tools/apitools is absent")
	}
	same := bundle("1.0.0", "stable", "")
	cases := []struct {
		name, base, cur, want string
	}{
		{"unchanged", same, same, ""},
		{"a required query parameter added to a stable operation",
			same, bundle("1.0.0", "stable", `,"parameters":[{"name":"q","in":"query","required":true,"schema":{"type":"string"}}]`), "breaking change against main on a stable operation"},
		{"a stable operation demoted to preview", same, bundle("1.0.0", "preview", ""), "demoting a stable operation"},
		{"a stable operation removed", same, `{"openapi":"3.1.0","info":{"title":"t","version":"1.0.0"},"paths":{}}`, "stable operation listJobs"},
		{"a deprecated operation removed before its sunset release",
			bundle("1.0.0", "stable", `,"deprecated":true,"x-activediq-sunset":"1.4.0"`), `{"openapi":"3.1.0","info":{"title":"t","version":"1.2.0"},"paths":{}}`, "sunset release 1.4.0 has arrived"},
		{"a deprecated operation removed after its sunset release",
			bundle("1.0.0", "stable", `,"deprecated":true,"x-activediq-sunset":"1.4.0"`), `{"openapi":"3.1.0","info":{"title":"t","version":"1.4.0"},"paths":{}}`, ""},
		{"a preview operation changed incompatibly",
			bundle("1.0.0", "preview", ""), strings.Replace(bundle("1.0.0", "preview", ""), `"properties":{"id":{"type":"string"}}`, `"properties":{}`, 1), ""},
		{"a new operation", `{"openapi":"3.1.0","info":{"title":"t","version":"1.0.0"},"paths":{}}`, same, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vs := withBase(t, c.base, c.cur)
			if c.want == "" {
				if len(vs) != 0 {
					t.Fatalf("want no A10 violation, got %v", vs)
				}
				return
			}
			for _, v := range vs {
				if strings.Contains(v.Msg, c.want) {
					return
				}
			}
			t.Fatalf("want an A10 violation containing %q, got %v", c.want, vs)
		})
	}
}

func TestA10UnresolvableMainIsAViolation(t *testing.T) {
	old := baseBundles
	t.Cleanup(func() { baseBundles = old })
	baseBundles = func(string) ([]baseDoc, error) { return nil, os.ErrNotExist }
	for _, v := range run(t, base()) {
		if v.Check == "A10" && strings.Contains(v.Msg, "file does not exist") {
			return
		}
	}
	t.Fatal("an unreadable main must fail A10, not skip it")
}

func TestSemverLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"1.2.0", "1.4.0", true}, {"1.4.0", "1.4.0", false}, {"1.10.0", "1.4.0", false}, {"2.0", "10.0.0", true}, {"v1.0.1", "1.0.2", true}} {
		if semverLess(c.a, c.b) != c.want {
			t.Errorf("semverLess(%q, %q) != %v", c.a, c.b, c.want)
		}
	}
}

// --- review findings of T-0017 (security-architect) ---------------------------------------------

func a8Header(f map[string]string, name, schema string) {
	repl(f, users, `        "400":
          $ref: shared/problems.yaml#/components/responses/Validation
`, "        \"400\":\n          $ref: shared/problems.yaml#/components/responses/Validation\n        \"200\":\n          description: ok\n          headers:\n            "+name+":\n              schema:\n"+schema)
}

func TestA8ResponseHeaders(t *testing.T) {
	for _, c := range []struct{ name, hdr, schema, want string }{
		{"format password", "X-Note", "                type: string\n                format: password\n", "format: password"},
		{"x-activediq-secret", "X-Note", "                type: string\n                x-activediq-secret: true\n", "x-activediq-secret"},
		{"writeOnly", "X-Note", "                type: string\n                writeOnly: true\n", "writeOnly"},
		{"secret-named header", "X-Api-Token", "                type: string\n", `header "X-Api-Token"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := base()
			a8Header(f, c.hdr, c.schema)
			for _, v := range run(t, f) {
				if v.Check == "A8" && strings.Contains(v.Msg, c.want) {
					return
				}
			}
			t.Fatalf("want an A8 violation containing %q", c.want)
		})
	}
	for _, h := range []string{"Retry-After", "Location"} {
		f := base()
		a8Header(f, h, "                type: string\n")
		for _, v := range run(t, f) {
			if v.Check == "A8" {
				t.Errorf("header %s is not a secret: %s", h, v)
			}
		}
	}
}

func TestA3AnRefIsAWholeToken(t *testing.T) {
	for _, c := range []struct {
		ref, an string
		want    bool
	}{{"AN-1", "AN-1", true}, {"AN-10", "AN-1", false}, {"TM-D16, AN-1", "AN-1", true}, {"AN-1 and AN-10", "AN-10", true}, {"AN-11", "AN-1", false}} {
		if refCitesAN(c.ref, c.an) != c.want {
			t.Errorf("refCitesAN(%q, %q) != %v", c.ref, c.an, c.want)
		}
	}
	f := base()
	repl(f, jobs, "x-permission: authenticated", "x-permission: anonymous\n      x-activediq-anonymous: AN-1")
	repl(f, pol, "authenticated:\n  - operation: listJobs\n    ref: TM-D16\n    reason: Any signed-in principal may see the job list.\n", "authenticated: []\n")
	repl(f, pol, "anonymous:\n", "anonymous:\n  - operation: listJobs\n    ref: AN-10\n    reason: wrong row\n")
	for _, v := range run(t, f) {
		if v.Check == "A3" && strings.Contains(v.Msg, "cites") {
			return
		}
	}
	t.Fatal("an AN-1 operation with a policy row citing AN-10 must fail A3")
}

func TestA7BaselineMayNotGrow(t *testing.T) {
	old := baseBaseline
	t.Cleanup(func() { baseBaseline = old })
	f := base()
	f["internal/platform/evil/e.go"] = "package evil\n\nimport \"encoding/json\"\n\nvar _ = json.Marshal\n"
	f[baselinePath] = "# baseline\ninternal/platform/evil/e.go\n"
	baseBaseline = func(string) (map[string]bool, bool, error) { return map[string]bool{}, true, nil }
	found := false
	for _, v := range run(t, f) {
		found = found || (v.Check == "A7" && strings.Contains(v.Msg, "not in the baseline on main"))
	}
	if !found {
		t.Fatal("a baseline line absent from main's baseline must fail A7")
	}
	baseBaseline = func(string) (map[string]bool, bool, error) {
		return map[string]bool{"internal/platform/evil/e.go": true}, true, nil
	}
	for _, v := range run(t, f) {
		if v.Check == "A7" {
			t.Errorf("a line present on main stays allowed: %s", v)
		}
	}
	baseBaseline = func(string) (map[string]bool, bool, error) { return nil, true, os.ErrNotExist }
	found = false
	for _, v := range run(t, f) {
		found = found || (v.Check == "A7" && strings.Contains(v.Msg, "file does not exist"))
	}
	if !found {
		t.Fatal("an unresolvable main must fail A7, not skip it")
	}
}
