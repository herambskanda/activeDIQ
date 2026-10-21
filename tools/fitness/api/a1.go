package main

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// checkA1 enforces ADR-0004 rule 1, the source layout: files only in the rule 1 places, tag files
// matching the module list and the platform packages, one tag per operation equal to its file's,
// unique operationIds and component names, and references that mirror the import graph. A stale
// bundle is not checked here: make gen-api-check owns it.
func checkA1(t *tree) []Violation {
	var vs []Violation
	vs = append(vs, t.misplaced...)
	vs = append(vs, t.parseErrs...)

	root := t.byRel["openapi.yaml"]
	if root == nil {
		vs = append(vs, Violation{"A1", specDir + "/openapi.yaml", "the root document is missing (ADR-0004 rule 1)"})
	}

	for _, f := range t.files {
		switch f.kind {
		case "module":
			if !moduleIDRe.MatchString(f.id) {
				vs = append(vs, Violation{"A1", f.pos, fmt.Sprintf("%q is not a module ID (^[a-z][a-z0-9]{1,30}$) (ADR-0004 rule 1: modules/<id>.yaml)", f.id)})
			} else if !t.modules[f.id] {
				vs = append(vs, Violation{"A1", f.pos, fmt.Sprintf("module %q is not in the module list: there is no internal/modules/%s (ADR-0004 rule 1: modules/<id>.yaml per server module that serves API)", f.id, f.id)})
			}
		case "platform":
			if !platformRe.MatchString(f.id) {
				vs = append(vs, Violation{"A1", f.pos, fmt.Sprintf("%q is not a kernel package name (ADR-0004 rule 1: platform/<pkg>.yaml)", f.id)})
			} else if !t.platformPkg[f.id] {
				vs = append(vs, Violation{"A1", f.pos, fmt.Sprintf("kernel package %q has no internal/platform/%s (ADR-0004 rule 1: platform/<pkg>.yaml)", f.id, f.id)})
			}
		}
		if f.doc == nil || f.kind == "policy" {
			continue
		}
		for i := 0; i+1 < len(f.doc.Content); i += 2 {
			k := f.doc.Content[i].Value
			ok := k == "components" || (k == "paths" && (f.kind == "module" || f.kind == "platform")) || f.kind == "root"
			if !ok {
				vs = append(vs, Violation{"A1", fmt.Sprintf("%s:%d", f.pos, f.doc.Content[i].Line), fmt.Sprintf("top-level key %q is not allowed in a %s file (ADR-0004 rule 1)", k, f.kind)})
			}
		}
	}

	for _, b := range t.badPathKeys {
		vs = append(vs, Violation{"A1", b.pos, fmt.Sprintf("path item key %q is not an HTTP method the contract uses (get, put, post, delete, patch, head) (ADR-0004 rule 1)", b.key)})
	}

	// Operations: exactly one tag, equal to the file's; operationId unique.
	seenID := map[string]operation{}
	for _, o := range t.ops {
		where := fmt.Sprintf("%s:%d", o.file.pos, o.line)
		name := strings.ToUpper(o.method) + " " + o.path
		if len(o.tags) != 1 {
			vs = append(vs, Violation{"A1", where, fmt.Sprintf("%s (%s) has %d tags; an operation has exactly one, %q (ADR-0004 rule 1: tags)", name, o.id, len(o.tags), o.file.tag)})
		} else if o.tags[0] != o.file.tag {
			vs = append(vs, Violation{"A1", where, fmt.Sprintf("%s (%s) has tag %q but is declared in %s, whose tag is %q (ADR-0004 rule 1: tags)", name, o.id, o.tags[0], o.file.rel, o.file.tag)})
		}
		if o.id == "" {
			vs = append(vs, Violation{"A1", where, fmt.Sprintf("%s has no operationId (ADR-0004 rule 1: names)", name)})
			continue
		}
		if prev, dup := seenID[o.id]; dup {
			vs = append(vs, Violation{"A1", where, fmt.Sprintf("duplicate operationId %q: also %s %s at %s:%d (ADR-0004 rule 1: names, unique across the bundle)", o.id, strings.ToUpper(prev.method), prev.path, prev.file.pos, prev.line)})
			continue
		}
		seenID[o.id] = o
	}

	// Component names: unique per section across the bundle, PascalCase.
	seenComp := map[string]component{} // "section/name"
	owner := map[string]*srcFile{}
	for _, c := range t.comps {
		where := fmt.Sprintf("%s:%d", c.file.pos, c.line)
		if !contains(sections, c.section) {
			vs = append(vs, Violation{"A1", where, fmt.Sprintf("components.%s is not a section the contract may declare (allowed: %s) (ADR-0004 rule 1)", c.section, strings.Join(sections, ", "))})
			continue
		}
		if !componentRe.MatchString(c.name) {
			vs = append(vs, Violation{"A1", where, fmt.Sprintf("component %s/%s is not PascalCase (ADR-0004 rule 1: names)", c.section, c.name)})
		}
		k := c.section + "/" + c.name
		if prev, dup := seenComp[k]; dup {
			vs = append(vs, Violation{"A1", where, fmt.Sprintf("duplicate component %s/%s: also declared at %s:%d (ADR-0004 rule 1: names, a collision fails, never last-one-wins)", c.section, c.name, prev.file.pos, prev.line)})
			continue
		}
		seenComp[k] = c
		owner[k] = c.file
	}

	vs = append(vs, checkRefs(t, owner)...)
	vs = append(vs, checkRootTags(t, root)...)

	sort.SliceStable(vs, func(i, j int) bool {
		if vs[i].Pos != vs[j].Pos {
			return vs[i].Pos < vs[j].Pos
		}
		return vs[i].Msg < vs[j].Msg
	})
	return vs
}

// checkRefs enforces "references mirror the import graph": a tag file references only its own
// components and shared/, shared/ only shared/, and nothing climbs out of api/openapi.
func checkRefs(t *tree, owner map[string]*srcFile) []Violation {
	var vs []Violation
	for _, r := range t.refs {
		where := fmt.Sprintf("%s:%d", r.file.pos, r.line)
		m := refRe.FindStringSubmatch(r.value)
		if m == nil {
			vs = append(vs, Violation{"A1", where, fmt.Sprintf("$ref %q is not of the form <file>#/components/<section>/<Name> or #/components/<section>/<Name> (ADR-0004 rule 1)", r.value)})
			continue
		}
		filePart, section, name := m[1], m[2], m[3]
		target := r.file
		if filePart != "" {
			if strings.HasPrefix(filePart, "/") || strings.Contains(filePart, "://") || strings.HasPrefix(path.Clean(filePart), "..") || strings.Contains(filePart, "\\") {
				vs = append(vs, Violation{"A1", where, fmt.Sprintf("$ref %q leaves api/openapi: an upward reference (ADR-0004 rule 1: references mirror the import graph)", r.value)})
				continue
			}
			target = t.byRel[path.Clean(filePart)]
			if target == nil {
				vs = append(vs, Violation{"A1", where, fmt.Sprintf("$ref %q names no file under api/openapi (ADR-0004 rule 1)", r.value)})
				continue
			}
		}
		decl := owner[section+"/"+name]
		if decl == nil {
			vs = append(vs, Violation{"A1", where, fmt.Sprintf("$ref %q points at %s/%s, which no file declares (ADR-0004 rule 1)", r.value, section, name)})
			continue
		}
		if decl != target {
			vs = append(vs, Violation{"A1", where, fmt.Sprintf("$ref %q: %s/%s is declared in %s, not in %s (ADR-0004 rule 1)", r.value, section, name, decl.rel, target.rel)})
			continue
		}
		if target == r.file {
			continue
		}
		switch r.file.kind {
		case "shared":
			if target.kind != "shared" {
				vs = append(vs, Violation{"A1", where, fmt.Sprintf("$ref %q: shared/ may reference only shared/, not %s (ADR-0004 rule 1: a cross-module reference)", r.value, target.rel)})
			}
		case "module", "platform":
			if target.kind != "shared" {
				vs = append(vs, Violation{"A1", where, fmt.Sprintf("$ref %q: a tag file may reference only its own components and shared/; %s is %s (ADR-0004 rule 1: a cross-module reference; move %s to shared/)", r.value, target.rel, target.kind, name)})
			}
		}
	}
	return vs
}

// checkRootTags: the root's tag list names exactly the tags the files provide (rule 1: "the root's
// tag list names each tag's file").
func checkRootTags(t *tree, root *srcFile) []Violation {
	if root == nil || root.doc == nil {
		return nil
	}
	provided := map[string]*srcFile{}
	for _, f := range t.files {
		if f.tag != "" {
			provided[f.tag] = f
		}
	}
	var vs []Violation
	listed := map[string]bool{}
	if tg := get(root.doc, "tags"); tg != nil && tg.Kind == yaml.SequenceNode {
		for _, e := range tg.Content {
			name := scalar(get(e, "name"))
			listed[name] = true
			if provided[name] == nil {
				vs = append(vs, Violation{"A1", fmt.Sprintf("%s:%d", root.pos, e.Line), fmt.Sprintf("tag %q has no file (modules/<id>.yaml or platform/<pkg>.yaml) (ADR-0004 rule 1)", name)})
			}
		}
	}
	for tag, f := range provided {
		if !listed[tag] {
			vs = append(vs, Violation{"A1", f.pos, fmt.Sprintf("declares tag %q, which is missing from the root tag list (ADR-0004 rule 1)", tag)})
		}
	}
	return vs
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
