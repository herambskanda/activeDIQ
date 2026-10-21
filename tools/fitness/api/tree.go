package main

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Violation is one broken rule at one place.
type Violation struct {
	Check string // A1, A13, or "self-test"
	Pos   string // file:line relative to the repository root
	Msg   string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: [ADR-0004 %s] %s", v.Pos, v.Check, v.Msg)
}

var (
	moduleIDRe  = regexp.MustCompile(`^[a-z][a-z0-9]{1,30}$`)
	platformRe  = regexp.MustCompile(`^[a-z][a-z0-9]{0,30}$`)
	componentRe = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	httpMethods = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "patch": true, "head": true}
	sections    = []string{"schemas", "parameters", "responses"}
	// A reference is rooted at api/openapi (runbook api-contract-workflow.md), with an optional file part.
	refRe = regexp.MustCompile(`^(?:([^#]+))?#/components/([A-Za-z]+)/([A-Za-z0-9]+)$`)
)

const specDir = "api/openapi"

// srcFile is one file under api/openapi, classified by ADR-0004 rule 1.
type srcFile struct {
	rel  string // slash path relative to api/openapi
	pos  string // slash path relative to the repository root
	kind string // root, shared, module, platform, policy
	tag  string // OpenAPI tag, for module and platform files
	id   string // module ID or kernel package name
	text string
	doc  *yaml.Node // the mapping node; nil if the file did not parse
}

type operation struct {
	file   *srcFile
	method string // lower case
	path   string
	id     string
	tags   []string
	perm   string
	line   int
}

type component struct {
	file    *srcFile
	section string
	name    string
	line    int
}

type refUse struct {
	file  *srcFile
	value string
	line  int
}

// tree is everything the checks read: the sources under api/openapi plus the two facts about the
// rest of the repository that rule 1 refers to.
type tree struct {
	root        string
	files       []*srcFile
	byRel       map[string]*srcFile
	ops         []operation
	comps       []component
	refs        []refUse
	rawOpIDs    int             // operationId lines counted by text, independent of the YAML parse
	modules     map[string]bool // directory names under internal/modules (the generated module list's input)
	platformPkg map[string]bool // directory names under internal/platform
	bundleOps   int             // operations in the committed bundle, -1 when it is absent
	misplaced   []Violation     // rule 1 placement violations found while walking
	parseErrs   []Violation
	badPathKeys []badKey // path item keys that are not methods
}

type badKey struct{ pos, key string }

var rawOpIDRe = regexp.MustCompile(`(?m)^\s*operationId\s*:`)

// load reads the tree. It returns an error only when the tree cannot be read at all.
func load(root string) (*tree, error) {
	t := &tree{root: root, byRel: map[string]*srcFile{}, bundleOps: -1}
	base := filepath.Join(root, filepath.FromSlash(specDir))
	if st, err := os.Stat(base); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", specDir)
	}
	t.modules = subdirs(filepath.Join(root, "internal", "modules"))
	t.platformPkg = subdirs(filepath.Join(root, "internal", "platform"))

	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(base, p)
		rel = filepath.ToSlash(rel)
		f := &srcFile{rel: rel, pos: specDir + "/" + rel}
		parts := strings.Split(rel, "/")
		stem := strings.TrimSuffix(parts[len(parts)-1], path.Ext(rel))
		switch {
		case rel == ".vacuum.yaml":
			return nil // the linter's ruleset, not a contract source
		case rel == "policy.yaml":
			f.kind = "policy"
		case path.Ext(rel) != ".yaml":
			t.misplaced = append(t.misplaced, Violation{"A1", f.pos, "only .yaml files may live under api/openapi (ADR-0004 rule 1)"})
			return nil
		case rel == "openapi.yaml":
			f.kind = "root"
		case len(parts) == 2 && parts[0] == "shared":
			f.kind = "shared"
		case len(parts) == 2 && parts[0] == "modules":
			f.kind, f.id, f.tag = "module", stem, stem
		case len(parts) == 2 && parts[0] == "platform":
			f.kind, f.id, f.tag = "platform", stem, "platform."+stem
		default:
			t.misplaced = append(t.misplaced, Violation{"A1", f.pos, "outside the rule 1 places (openapi.yaml, shared/*.yaml, modules/<id>.yaml, platform/<pkg>.yaml, policy.yaml) (ADR-0004 rule 1)"})
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f.text = string(b)
		var n yaml.Node
		if err := yaml.Unmarshal(b, &n); err != nil {
			t.parseErrs = append(t.parseErrs, Violation{"A1", f.pos, "cannot parse (and so cannot be bundled or checked by T5): " + err.Error()})
		} else if len(n.Content) == 1 && deref(n.Content[0]).Kind == yaml.MappingNode {
			f.doc = deref(n.Content[0])
		} else {
			t.parseErrs = append(t.parseErrs, Violation{"A1", f.pos, "the file must hold a YAML object (ADR-0004 rule 1)"})
		}
		t.files = append(t.files, f)
		t.byRel[rel] = f
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(t.files, func(i, j int) bool { return t.files[i].rel < t.files[j].rel })

	for _, f := range t.files {
		if f.kind == "module" || f.kind == "platform" {
			t.rawOpIDs += len(rawOpIDRe.FindAllString(f.text, -1))
		}
		if f.doc == nil || f.kind == "policy" || f.kind == "root" {
			continue
		}
		t.collect(f)
	}
	t.bundleOps = countBundleOps(filepath.Join(root, "internal", "platform", "apihost", "spec", "openapi.gen.json"))
	return t, nil
}

func subdirs(dir string) map[string]bool {
	out := map[string]bool{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range ents {
		if e.IsDir() {
			out[e.Name()] = true
		}
	}
	return out
}

// countBundleOps counts the operations of the committed bundle (JSON is YAML), or -1 if absent.
func countBundleOps(p string) int {
	b, err := os.ReadFile(p)
	if err != nil {
		return -1
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return -1
	}
	n := 0
	for _, item := range doc.Paths {
		for m := range item {
			if httpMethods[m] {
				n++
			}
		}
	}
	return n
}

// collect indexes the operations, components and references of one parsed file.
func (t *tree) collect(f *srcFile) {
	if cs := get(f.doc, "components"); cs != nil && cs.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(cs.Content); i += 2 {
			sec := cs.Content[i].Value
			m := deref(cs.Content[i+1])
			if m.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(m.Content); j += 2 {
				t.comps = append(t.comps, component{f, sec, m.Content[j].Value, m.Content[j].Line})
			}
		}
	}
	if f.kind == "module" || f.kind == "platform" {
		if ps := get(f.doc, "paths"); ps != nil && ps.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(ps.Content); i += 2 {
				p := ps.Content[i].Value
				item := deref(ps.Content[i+1])
				if item.Kind != yaml.MappingNode {
					continue
				}
				for j := 0; j+1 < len(item.Content); j += 2 {
					method := item.Content[j].Value
					if !httpMethods[method] {
						t.badPathKeys = append(t.badPathKeys, badKey{fmt.Sprintf("%s:%d", f.pos, item.Content[j].Line), method})
						continue
					}
					od := deref(item.Content[j+1])
					o := operation{file: f, method: method, path: p, line: item.Content[j].Line}
					if od.Kind == yaml.MappingNode {
						o.id = scalar(get(od, "operationId"))
						o.perm = scalar(get(od, "x-permission"))
						if tg := get(od, "tags"); tg != nil && tg.Kind == yaml.SequenceNode {
							for _, e := range tg.Content {
								o.tags = append(o.tags, deref(e).Value)
							}
						}
					}
					t.ops = append(t.ops, o)
				}
			}
		}
	}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		n = deref(n)
		switch n.Kind {
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == "$ref" && n.Content[i+1].Kind == yaml.ScalarNode {
					t.refs = append(t.refs, refUse{f, n.Content[i+1].Value, n.Content[i+1].Line})
				}
				walk(n.Content[i+1])
			}
		case yaml.SequenceNode:
			for _, e := range n.Content {
				walk(e)
			}
		}
	}
	walk(f.doc)
}

// deref follows YAML aliases.
func deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// get returns the value node of key in a mapping node, or nil.
func get(m *yaml.Node, key string) *yaml.Node {
	m = deref(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return deref(m.Content[i+1])
		}
	}
	return nil
}

// scalar returns a scalar node's text, or "".
func scalar(n *yaml.Node) string {
	n = deref(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}
