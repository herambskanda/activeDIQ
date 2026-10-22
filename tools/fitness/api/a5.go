package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const webAPIDir = "web/src/api"

// webAPIAllowed is rule 12: web/src/api holds the generated files and client.ts. The client's own
// test and the README that explains the directory are the two additions the directory already has.
func webAPIAllowed(name string) bool {
	switch name {
	case "client.ts", "client.test.ts", "README.md":
		return true
	}
	return strings.Contains(name, ".gen.")
}

// rule12Markers are the pieces of web/eslint.config.js that make rule 12 a lint failure. A config
// that loses one no longer bans that spelling; the proof (tools/ci/proof.sh) runs the real ESLint
// on web/proof/api-client-violation.ts and requires every rule to fire.
var rule12Markers = []struct{ what, needle string }{
	{"fetch", `"fetch"`},
	{"XMLHttpRequest", `"XMLHttpRequest"`},
	{"EventSource", `"EventSource"`},
	{"an HTTP-library import", "axios"},
	{"a string literal starting with /api/", `\\/api`},
	{"the src/api exemption only", "src/api"},
}

var assignOpenEnumRe = regexp.MustCompile(`components\["schemas"\]\["([A-Za-z0-9]+)"\]\s*=\s*"`)

// checkA5 is the static half of ADR-0004 A5 (the console uses the generated client only): the
// generated types cover every operation, every response enum is widened to admit unknown values
// and a type-check fixture proves it, web/src/api holds only generated files and client.ts, and
// rule 12's ESLint rule is wired. Byte-for-byte staleness is make gen-api-check.
func checkA5(t *tree) []Violation {
	var vs []Violation
	add := func(pos, f string, a ...any) { vs = append(vs, Violation{"A5", pos, fmt.Sprintf(f, a...)}) }
	dir := filepath.Join(t.root, filepath.FromSlash(webAPIDir))
	ents, err := os.ReadDir(dir)
	if err != nil {
		return []Violation{{"A5", webAPIDir, "the generated client directory is missing: the console reaches the API only through web/src/api (ADR-0004 rule 12)"}}
	}
	for _, e := range ents {
		if e.IsDir() || !webAPIAllowed(e.Name()) {
			add(webAPIDir+"/"+e.Name(), "only the generated files and client.ts live in web/src/api (ADR-0004 rule 12); a hand-written client file is a private endpoint caller")
		}
	}
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		return string(b)
	}

	// Generated types: one entry per operation, open enums widened.
	gen := read("schema.gen.d.ts")
	if gen == "" {
		add(webAPIDir+"/schema.gen.d.ts", "the generated types are missing: run make gen-api (ADR-0004 rule 12)")
	} else {
		for _, o := range t.ops {
			if !regexp.MustCompile(`(?m)^\s+` + regexp.QuoteMeta(o.id) + `: \{`).MatchString(gen) {
				add(webAPIDir+"/schema.gen.d.ts", "stale: operation %s is in the contract but not in the generated types; run make gen-api (ADR-0004 rule 12)", o.label())
			}
		}
	}
	open := map[string]component{}
	for _, c := range t.comps {
		if c.section != "schemas" {
			continue
		}
		f := c.file
		if s := get(get(get(f.doc, "components"), "schemas"), c.name); s != nil && scalar(get(s, "x-activediq-enum")) == "open" {
			open[c.name] = c
		}
	}
	for name, c := range open {
		if gen != "" && !regexp.MustCompile(`(?m)^\s+`+regexp.QuoteMeta(name)+`: .*\(string & \{\}\)`).MatchString(gen) {
			add(fmt.Sprintf("%s:%d", c.file.pos, c.line), "open enum %s is not widened to `| (string & {})` in the generated types: an older console would fail to type-check a newer server's value (ADR-0004 rule 2, A5)", name)
		}
	}
	// The type-check fixture: an unknown value assigned to a generated open-enum type, compiled by tsc in lint-web.
	if len(open) > 0 {
		fixture := false
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".test.ts") {
				continue
			}
			for _, m := range assignOpenEnumRe.FindAllStringSubmatch(read(e.Name()), -1) {
				if _, ok := open[m[1]]; ok {
					fixture = true
				}
			}
		}
		if !fixture {
			add(webAPIDir, "no open-enum type-check fixture: a *.test.ts here must assign an unknown string to a generated open enum (components[\"schemas\"][\"<Enum>\"] = \"...\") so `tsc --noEmit` fails if the widening is lost (ADR-0004 rule 2, A5)")
		}
	}

	// Rule 12's lint rule, and the violation file the proof lints.
	cfgPath := filepath.Join(t.root, "web", "eslint.config.js")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		add("web/eslint.config.js", "missing: rule 12 has no ESLint rule to run (ADR-0004 rule 12)")
	} else {
		for _, m := range rule12Markers {
			if !strings.Contains(string(cfg), m.needle) {
				add("web/eslint.config.js", "rule 12 no longer bans %s (no %s in the config) (ADR-0004 rule 12, A5)", m.what, m.needle)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(t.root, "web", "proof", "api-client-violation.ts")); err != nil {
		add("web/proof/api-client-violation.ts", "missing: the violation file the proof lints to show rule 12 fires (ADR-0004 rule 12, A5)")
	}
	return vs
}
