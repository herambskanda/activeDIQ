package main

import (
	"fmt"
	"path"
	"strings"

	"go.yaml.in/yaml/v3"
)

// resolve follows a $ref node (an object whose only member is $ref) to the component it names and
// returns that node with the file that holds it. A node that is not a reference is returned as is.
// A reference this reader cannot follow (a cycle, a missing file or component) returns ok=false: A1
// reports dangling references, so the checks here only skip them.
func (t *tree) resolve(from *srcFile, n *yaml.Node) (*yaml.Node, *srcFile, bool) {
	n = deref(n)
	for i := 0; i < 32; i++ {
		if n == nil || n.Kind != yaml.MappingNode {
			return n, from, n != nil
		}
		r := scalar(get(n, "$ref"))
		if r == "" {
			return n, from, true
		}
		m := refRe.FindStringSubmatch(r)
		if m == nil {
			return nil, from, false
		}
		target := from
		if m[1] != "" {
			target = t.byRel[path.Clean(m[1])]
		}
		if target == nil || target.doc == nil {
			return nil, from, false
		}
		next := get(get(get(target.doc, "components"), m[2]), m[3])
		if next == nil {
			return nil, from, false
		}
		n, from = next, target
	}
	return nil, from, false
}

// refName is the component name a $ref node points at ("" when n is not a reference).
func refName(n *yaml.Node) string {
	if m := refRe.FindStringSubmatch(scalar(get(n, "$ref"))); m != nil {
		return m[3]
	}
	return ""
}

// walkSchema visits every schema reachable from n through $ref, properties, items,
// additionalProperties, oneOf, anyOf, allOf, not and prefixItems. onSchema gets each schema object
// once; onProp gets each property name with its key line. Cycles are cut by the seen set.
func (t *tree) walkSchema(from *srcFile, n *yaml.Node, seen map[*yaml.Node]bool, onSchema func(s *yaml.Node, f *srcFile), onProp func(name string, line int, f *srcFile)) {
	s, f, ok := t.resolve(from, n)
	if !ok || s == nil || s.Kind != yaml.MappingNode || seen[s] {
		return
	}
	seen[s] = true
	onSchema(s, f)
	if ps := get(s, "properties"); ps != nil && ps.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(ps.Content); i += 2 {
			if onProp != nil {
				onProp(ps.Content[i].Value, ps.Content[i].Line, f)
			}
			t.walkSchema(f, ps.Content[i+1], seen, onSchema, onProp)
		}
	}
	for _, k := range []string{"items", "additionalProperties", "not", "contains", "propertyNames"} {
		if c := get(s, k); c != nil && c.Kind == yaml.MappingNode {
			t.walkSchema(f, c, seen, onSchema, onProp)
		}
	}
	for _, k := range []string{"oneOf", "anyOf", "allOf", "prefixItems"} {
		if c := get(s, k); c != nil && c.Kind == yaml.SequenceNode {
			for _, e := range c.Content {
				t.walkSchema(f, e, seen, onSchema, onProp)
			}
		}
	}
}

// mediaSchemas returns the (media type, schema node) pairs of a content map.
func mediaSchemas(content *yaml.Node) []mediaType {
	var out []mediaType
	content = deref(content)
	if content == nil || content.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(content.Content); i += 2 {
		mt := deref(content.Content[i+1])
		out = append(out, mediaType{name: content.Content[i].Value, node: mt, schema: get(mt, "schema"), line: content.Content[i].Line})
	}
	return out
}

type mediaType struct {
	name   string
	node   *yaml.Node
	schema *yaml.Node
	line   int
}

// response is one entry of an operation's responses, resolved.
type response struct {
	status string
	node   *yaml.Node
	file   *srcFile
	line   int
	ref    string // component name when the entry is a $ref, else ""
}

// responses lists the responses of an operation. Unresolvable references are kept with a nil node.
func (t *tree) responses(o operation) []response {
	rs := get(o.node, "responses")
	if rs == nil || rs.Kind != yaml.MappingNode {
		return nil
	}
	var out []response
	for i := 0; i+1 < len(rs.Content); i += 2 {
		raw := deref(rs.Content[i+1])
		n, f, ok := t.resolve(o.file, raw)
		if !ok {
			n = nil
		}
		out = append(out, response{status: rs.Content[i].Value, node: n, file: f, line: rs.Content[i].Line, ref: refName(raw)})
	}
	return out
}

func (o operation) where() string { return fmt.Sprintf("%s:%d", o.file.pos, o.line) }

func (o operation) label() string {
	return fmt.Sprintf("%s %s (%s)", strings.ToUpper(o.method), o.path, o.id)
}

// policyEntries reads one policy.yaml section leniently (A13 reports shape errors): each entry as
// its scalar fields, with the line of the entry.
func (t *tree) policyEntries(section string) []policyEntry {
	pf := t.byRel["policy.yaml"]
	if pf == nil || pf.doc == nil {
		return nil
	}
	l := get(pf.doc, section)
	if l == nil || l.Kind != yaml.SequenceNode {
		return nil
	}
	var out []policyEntry
	for _, e := range l.Content {
		e = deref(e)
		if e.Kind != yaml.MappingNode {
			continue
		}
		pe := policyEntry{fields: map[string]string{}, line: e.Line, pos: fmt.Sprintf("%s:%d", pf.pos, e.Line)}
		for i := 0; i+1 < len(e.Content); i += 2 {
			pe.fields[e.Content[i].Value] = strings.TrimSpace(scalar(e.Content[i+1]))
		}
		out = append(out, pe)
	}
	return out
}

type policyEntry struct {
	fields map[string]string
	line   int
	pos    string
}

// policyOps is the set of operationIds a policy section names.
func (t *tree) policyOps(section string) map[string]policyEntry {
	out := map[string]policyEntry{}
	for _, e := range t.policyEntries(section) {
		if op := e.fields["operation"]; op != "" {
			out[op] = e
		}
	}
	return out
}
