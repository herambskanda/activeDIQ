package main

import (
	"fmt"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

const problemMedia = "application/problem+json"

// problemCatalogue is the closed set of /problems/<slug> types: the example types of the
// components.responses of shared/problems.yaml, where the catalogue is defined (rule 8).
func (t *tree) problemCatalogue() map[string]bool {
	out := map[string]bool{}
	pf := t.byRel["shared/problems.yaml"]
	if pf == nil || pf.doc == nil {
		return out
	}
	rs := get(get(pf.doc, "components"), "responses")
	if rs == nil || rs.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(rs.Content); i += 2 {
		for _, m := range mediaSchemas(get(rs.Content[i+1], "content")) {
			if ty := scalar(get(get(m.node, "example"), "type")); ty != "" {
				out[ty] = true
			}
		}
	}
	return out
}

func isErrorStatus(s string) bool {
	if s == "default" {
		return true
	}
	if len(s) == 3 && (s[0] == '4' || s[0] == '5') && (s[1:] == "XX" || s[1:] == "xx") {
		return true
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 400 && n <= 599
}

// checkA11 enforces rule 8 on the document: every 4xx and 5xx response is application/problem+json
// with the shared Problem schema, and every example type is in the closed catalogue. It also bans
// http.Error and WriteHeader in internal/** outside apihost (a Go source scan).
func checkA11(t *tree) []Violation {
	var vs []Violation
	add := func(pos, f string, a ...any) {
		vs = append(vs, Violation{"A11", pos, fmt.Sprintf(f, a...)})
	}
	cat := t.problemCatalogue()
	if len(cat) == 0 {
		add(specDir+"/shared/problems.yaml", "the problem catalogue is empty or missing: no components.responses with an example type (ADR-0004 rule 8, A11)")
	}
	checkResponse := func(where, who string, n *yaml.Node, f *srcFile) {
		ms := mediaSchemas(get(n, "content"))
		if len(ms) == 0 {
			add(where, "%s has no body: an error response is %s with the shared Problem schema (ADR-0004 rule 8, A11)", who, problemMedia)
		}
		for _, m := range ms {
			if m.name != problemMedia {
				add(fmt.Sprintf("%s:%d", f.pos, m.line), "%s offers %s: an error response is only %s (ADR-0004 rule 8, A11)", who, m.name, problemMedia)
				continue
			}
			sc, sf, ok := t.resolve(f, m.schema)
			_ = sc
			_ = sf
			if !ok || refName(m.schema) != "Problem" || !strings.HasSuffix(scalar(get(m.schema, "$ref")), "shared/problems.yaml#/components/schemas/Problem") {
				add(fmt.Sprintf("%s:%d", f.pos, m.line), "%s does not use the shared Problem schema (shared/problems.yaml#/components/schemas/Problem) (ADR-0004 rule 8, A11)", who)
			}
			exs := []*yaml.Node{get(m.node, "example")}
			if es := get(m.node, "examples"); es != nil && es.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(es.Content); i += 2 {
					exs = append(exs, get(es.Content[i+1], "value"))
				}
			}
			for _, ex := range exs {
				if ty := scalar(get(ex, "type")); ty != "" && !cat[ty] {
					add(fmt.Sprintf("%s:%d", f.pos, ex.Line), "%s has example type %q, which is not in the problem catalogue of shared/problems.yaml: the catalogue is closed, add the slug there first (ADR-0004 rule 8, A11)", who, ty)
				}
			}
		}
	}

	for _, o := range t.ops {
		for _, r := range t.responses(o) {
			if !isErrorStatus(r.status) {
				continue
			}
			who := fmt.Sprintf("%s response %s", o.label(), r.status)
			if r.node == nil {
				add(fmt.Sprintf("%s:%d", o.file.pos, r.line), "%s cannot be resolved (ADR-0004 rule 8, A11)", who)
				continue
			}
			checkResponse(fmt.Sprintf("%s:%d", o.file.pos, r.line), who, r.node, r.file)
		}
	}
	// Component responses that look like errors (4xx/5xx example status) hold to the same rule.
	for _, f := range t.files {
		if f.doc == nil || f.kind == "root" {
			continue
		}
		rs := get(get(f.doc, "components"), "responses")
		if rs == nil || rs.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(rs.Content); i += 2 {
			n := deref(rs.Content[i+1])
			for _, m := range mediaSchemas(get(n, "content")) {
				st := scalar(get(get(m.node, "example"), "status"))
				if v, err := strconv.Atoi(st); err == nil && v >= 400 {
					checkResponse(fmt.Sprintf("%s:%d", f.pos, rs.Content[i].Line), "component response "+rs.Content[i].Value, n, f)
					break
				}
			}
		}
	}

	vs = append(vs, goHTTPStatusWrites(t.root)...)
	return vs
}
