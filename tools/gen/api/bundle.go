package main

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Doc is a decoded YAML or JSON object.
type Doc = map[string]any

var (
	moduleIDRe   = regexp.MustCompile(`^[a-z][a-z0-9]{1,30}$`)
	platformRe   = regexp.MustCompile(`^[a-z][a-z0-9]{0,30}$`)
	componentRe  = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	operationRe  = regexp.MustCompile(`^[a-z][A-Za-z0-9]*$`)
	pathRe       = regexp.MustCompile(`^/([a-z0-9]+(-[a-z0-9]+)*|\{[a-z][A-Za-z0-9]*\})(/([a-z0-9]+(-[a-z0-9]+)*|\{[a-z][A-Za-z0-9]*\}))*$`)
	httpMethods  = []string{"get", "put", "post", "delete", "patch", "head"}
	sections     = []string{"schemas", "parameters", "responses"}
	tagExtension = "x-activediq-tag"
)

// srcFile is one YAML file under api/openapi.
type srcFile struct {
	rel  string // slash path relative to api/openapi
	kind string // root, shared, module, platform
	tag  string // OpenAPI tag, for module and platform files
	doc  Doc
}

// Bundle is the merged contract (ADR-0004 rule 1) and what the generators need to know about it.
type Bundle struct {
	JSON []byte // the committed openapi.gen.json
	Doc  Doc    // the same content, decoded
}

// errList collects problems so one run reports every one.
type errList struct{ msgs []string }

func (e *errList) addf(format string, a ...any) { e.msgs = append(e.msgs, fmt.Sprintf(format, a...)) }
func (e *errList) err() error {
	if len(e.msgs) == 0 {
		return nil
	}
	sort.Strings(e.msgs)
	return errors.New(strings.Join(e.msgs, "\n"))
}

// BuildBundle reads api/openapi under root and merges it under rule 1. Collisions, cross-module
// references and anything outside the rule 1 places fail, naming the offenders.
func BuildBundle(root string) (*Bundle, error) {
	var el errList
	files, err := loadFiles(root, &el)
	if err != nil {
		return nil, err
	}
	var rootFile *srcFile
	byRel := map[string]*srcFile{}
	for _, f := range files {
		byRel[f.rel] = f
		if f.kind == "root" {
			rootFile = f
		}
	}
	if rootFile == nil {
		return nil, fmt.Errorf("%s/openapi.yaml: the root document is missing", root)
	}

	// Component names are global (rule 1): index them first.
	type owner struct{ file *srcFile }
	comps := map[string]map[string]owner{}
	for _, s := range sections {
		comps[s] = map[string]owner{}
	}
	for _, f := range files {
		if f.kind == "root" {
			continue
		}
		cs, _ := f.doc["components"].(Doc)
		for k := range cs {
			if !contains(sections, k) {
				el.addf("%s: components.%s is not a section the contract may declare (allowed: %s)", f.rel, k, strings.Join(sections, ", "))
			}
		}
		for _, s := range sections {
			m, _ := cs[s].(Doc)
			for name := range m {
				if !componentRe.MatchString(name) {
					el.addf("%s: component %s/%s is not PascalCase", f.rel, s, name)
				}
				if prev, dup := comps[s][name]; dup {
					el.addf("component %s/%s is declared in both %s and %s", s, name, prev.file.rel, f.rel)
					continue
				}
				comps[s][name] = owner{f}
			}
		}
	}

	// Rewrite every $ref to the bundle form, enforcing who may reference whom.
	for _, f := range files {
		rewriteRefs(f, byRel, func(s, name string) (*srcFile, bool) { o, ok := comps[s][name]; return o.file, ok }, &el)
	}

	out := Doc{}
	for _, k := range []string{"openapi", "info", "servers", "security"} {
		if v, ok := rootFile.doc[k]; ok {
			out[k] = v
		}
	}
	checkRoot(rootFile, &el)

	// Components, stamped with the owning tag so the generators can filter by tag from the bundle alone.
	outComps := Doc{}
	for _, s := range sections {
		m := Doc{}
		for name, o := range comps[s] {
			src := ((o.file.doc["components"].(Doc))[s].(Doc))[name]
			if sch, ok := src.(Doc); ok && o.file.tag != "" {
				if _, bad := sch[tagExtension]; bad {
					el.addf("%s: %s/%s sets %s, which only the bundler writes", o.file.rel, s, name, tagExtension)
				}
				c := Doc{}
				for k, v := range sch {
					c[k] = v
				}
				c[tagExtension] = o.file.tag
				src = c
			}
			m[name] = src
		}
		if len(m) > 0 {
			outComps[s] = m
		}
	}
	if rc, ok := rootFile.doc["components"].(Doc); ok {
		for k, v := range rc {
			if k != "securitySchemes" {
				el.addf("%s: components.%s: the root declares securitySchemes only", rootFile.rel, k)
				continue
			}
			outComps[k] = v
		}
	}
	out["components"] = outComps

	// Paths and tags.
	paths := Doc{}
	opIDs := map[string]string{}
	tagSet := map[string]string{}
	for _, f := range files {
		if f.kind != "module" && f.kind != "platform" {
			continue
		}
		tagSet[f.tag] = f.rel
		ps, _ := f.doc["paths"].(Doc)
		for p, item := range ps {
			where := f.rel + ": " + p
			if !pathRe.MatchString(p) {
				el.addf("%s is not a kebab-case path with no trailing slash", where)
			}
			if prev, dup := paths[p]; dup {
				_ = prev
				el.addf("path %s is declared in more than one file (second: %s)", p, f.rel)
				continue
			}
			it, ok := item.(Doc)
			if !ok {
				el.addf("%s: a path item must be an object", where)
				continue
			}
			for m, op := range it {
				if !contains(httpMethods, m) {
					el.addf("%s: path item key %q is not a method the contract uses (%s)", where, m, strings.Join(httpMethods, ", "))
					continue
				}
				od, _ := op.(Doc)
				if od == nil {
					el.addf("%s %s: the operation must be an object", strings.ToUpper(m), where)
					continue
				}
				tags, _ := od["tags"].([]any)
				if len(tags) != 1 || tags[0] != f.tag {
					el.addf("%s %s: an operation has exactly one tag and it must be %q, the tag of %s (found %v)", strings.ToUpper(m), where, f.tag, f.rel, tags)
				}
				id, _ := od["operationId"].(string)
				if !operationRe.MatchString(id) {
					el.addf("%s %s: operationId %q is not camelCase", strings.ToUpper(m), where, id)
				} else if prev, dup := opIDs[id]; dup {
					el.addf("operationId %s is used by %s and by %s %s", id, prev, strings.ToUpper(m), where)
				} else {
					opIDs[id] = strings.ToUpper(m) + " " + where
				}
			}
			paths[p] = item
		}
	}
	out["paths"] = paths

	// The root tag list must name exactly the tags the files provide.
	rootTags, _ := rootFile.doc["tags"].([]any)
	listed := map[string]bool{}
	var outTags []any
	for _, t := range rootTags {
		td, _ := t.(Doc)
		name, _ := td["name"].(string)
		if _, ok := tagSet[name]; !ok {
			el.addf("%s: tag %q has no file (modules/<id>.yaml or platform/<pkg>.yaml)", rootFile.rel, name)
		}
		for k := range td {
			if k != "name" && k != "description" {
				el.addf("%s: tag %q: key %q is not allowed (name and description only)", rootFile.rel, name, k)
			}
		}
		listed[name] = true
		outTags = append(outTags, td)
	}
	for tag, rel := range tagSet {
		if !listed[tag] {
			el.addf("%s declares tag %q, which is missing from the root tag list", rel, tag)
		}
	}
	sort.Slice(outTags, func(i, j int) bool { return outTags[i].(Doc)["name"].(string) < outTags[j].(Doc)["name"].(string) })
	if outTags == nil {
		outTags = []any{}
	}
	out["tags"] = outTags

	if err := el.err(); err != nil {
		return nil, err
	}
	norm, err := normalize(out, "")
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(norm, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	var doc Doc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return &Bundle{JSON: b, Doc: doc}, nil
}

func checkRoot(f *srcFile, el *errList) {
	d := f.doc
	if v, _ := d["openapi"].(string); !strings.HasPrefix(v, "3.1.") {
		el.addf("%s: openapi must be 3.1.x (found %v)", f.rel, d["openapi"])
	}
	for k := range d {
		if !contains([]string{"openapi", "info", "servers", "security", "tags", "components"}, k) {
			el.addf("%s: root key %q is not allowed (paths come from the tag files)", f.rel, k)
		}
	}
	servers, _ := d["servers"].([]any)
	if len(servers) != 1 {
		el.addf("%s: servers must be exactly [{url: /api/v1}]", f.rel)
	} else if s, _ := servers[0].(Doc); s["url"] != "/api/v1" {
		el.addf("%s: servers[0].url must be /api/v1", f.rel)
	}
	if _, ok := d["info"].(Doc); !ok {
		el.addf("%s: info is missing", f.rel)
	}
}

// loadFiles reads every YAML file under root/api/openapi and classifies it by rule 1.
func loadFiles(root string, el *errList) ([]*srcFile, error) {
	base := root
	var files []*srcFile
	err := filepath.WalkDir(base, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(base, p)
		rel = filepath.ToSlash(rel)
		if rel == "policy.yaml" || rel == ".vacuum.yaml" {
			return nil // owned by security-architect / the linter; not part of the bundle
		}
		f := &srcFile{rel: rel}
		parts := strings.Split(rel, "/")
		ext := strings.ToLower(path.Ext(rel))
		stem := strings.TrimSuffix(parts[len(parts)-1], path.Ext(rel))
		switch {
		case ext != ".yaml":
			el.addf("%s: only .yaml files may live under api/openapi", rel)
			return nil
		case rel == "openapi.yaml":
			f.kind = "root"
		case len(parts) == 2 && parts[0] == "shared":
			f.kind = "shared"
		case len(parts) == 2 && parts[0] == "modules":
			f.kind, f.tag = "module", stem
			if !moduleIDRe.MatchString(stem) {
				el.addf("%s: %q is not a module ID (^[a-z][a-z0-9]{1,30}$)", rel, stem)
			}
		case len(parts) == 2 && parts[0] == "platform":
			f.kind, f.tag = "platform", "platform."+stem
			if !platformRe.MatchString(stem) {
				el.addf("%s: %q is not a kernel package name", rel, stem)
			}
		default:
			el.addf("%s: outside the rule 1 places (openapi.yaml, shared/*.yaml, modules/<id>.yaml, platform/<pkg>.yaml, policy.yaml)", rel)
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var raw any
		if err := yaml.Unmarshal(b, &raw); err != nil {
			el.addf("%s: cannot parse: %v", rel, err)
			return nil
		}
		n, err := normalize(raw, rel)
		if err != nil {
			el.addf("%s", err)
			return nil
		}
		doc, ok := n.(Doc)
		if !ok {
			el.addf("%s: the file must hold an object", rel)
			return nil
		}
		if f.kind != "root" {
			for k := range doc {
				if k != "components" && !(k == "paths" && (f.kind == "module" || f.kind == "platform")) {
					el.addf("%s: top-level key %q is not allowed in a %s file", rel, k, f.kind)
				}
			}
		}
		f.doc = doc
		files = append(files, f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	return files, nil
}

// normalize converts yaml.v3 values into plain JSON-compatible values, rejecting what JSON cannot
// carry faithfully (non-string keys, unquoted dates yaml turned into timestamps).
func normalize(v any, where string) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		out := make(Doc, len(x))
		for k, e := range x {
			n, err := normalize(e, where)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	case map[any]any:
		out := make(Doc, len(x))
		for k, e := range x {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("%s: mapping key %v is not a string (quote it)", where, k)
			}
			n, err := normalize(e, where)
			if err != nil {
				return nil, err
			}
			out[ks] = n
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			n, err := normalize(e, where)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case time.Time:
		return nil, fmt.Errorf("%s: an unquoted date or timestamp (%s) is read as a time value; quote it", where, x.Format(time.RFC3339))
	}
	return v, nil
}

var refRe = regexp.MustCompile(`^(?:([a-z]+/[a-z0-9-]+\.yaml))?#/components/([A-Za-z]+)/([A-Za-z0-9]+)$`)

// rewriteRefs resolves each $ref in f and rewrites it to #/components/<section>/<Name>.
func rewriteRefs(f *srcFile, byRel map[string]*srcFile, owner func(section, name string) (*srcFile, bool), el *errList) {
	var walk func(v any, loc string)
	walk = func(v any, loc string) {
		switch x := v.(type) {
		case Doc:
			if r, ok := x["$ref"].(string); ok {
				x["$ref"] = resolveRef(f, r, loc, byRel, owner, el)
			}
			for k, e := range x {
				walk(e, loc+"."+k)
			}
		case []any:
			for i, e := range x {
				walk(e, fmt.Sprintf("%s[%d]", loc, i))
			}
		}
	}
	walk(f.doc, "")
}

func resolveRef(f *srcFile, ref, loc string, byRel map[string]*srcFile, owner func(string, string) (*srcFile, bool), el *errList) string {
	m := refRe.FindStringSubmatch(ref)
	if m == nil {
		el.addf("%s%s: $ref %q is not of the form <file>#/components/<section>/<Name> or #/components/<section>/<Name>", f.rel, loc, ref)
		return ref
	}
	file, section, name := m[1], m[2], m[3]
	target := f
	if file != "" {
		t, ok := byRel[file]
		if !ok {
			el.addf("%s%s: $ref %q names no file under api/openapi", f.rel, loc, ref)
			return ref
		}
		target = t
	}
	o, ok := owner(section, name)
	if !ok {
		el.addf("%s%s: $ref %q points at %s/%s, which no file declares", f.rel, loc, ref, section, name)
		return ref
	}
	if o != target {
		if file == "" {
			el.addf("%s%s: $ref %q: %s/%s is declared in %s, not here; write the file part (%s#/components/%s/%s)", f.rel, loc, ref, section, name, o.rel, o.rel, section, name)
		} else {
			el.addf("%s%s: $ref %q: %s/%s is not declared in %s", f.rel, loc, ref, section, name, file)
		}
		return ref
	}
	if target != f {
		switch f.kind {
		case "shared":
			if target.kind != "shared" {
				el.addf("%s%s: $ref %q: shared/ may reference only shared/ (cross-module reference, ADR-0004 rule 1)", f.rel, loc, ref)
			}
		case "module", "platform":
			if target.kind != "shared" {
				el.addf("%s%s: $ref %q: a tag file may reference only its own components and shared/; %s belongs to another tag (cross-module reference, ADR-0004 rule 1; move %s to shared/)", f.rel, loc, ref, o.rel, name)
			}
		}
	}
	return "#/components/" + section + "/" + name
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// writeIfChanged writes b to p, creating parent directories.
func writeFile(p string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if old, err := os.ReadFile(p); err == nil && bytes.Equal(old, b) {
		return nil
	}
	return os.WriteFile(p, b, 0o644)
}
