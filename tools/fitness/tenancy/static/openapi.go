package static

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// OpenAPIDir is where the public contract lives (blueprint §1).
const OpenAPIDir = "api/openapi"

// ScopeExtension marks an operation as platform scope. Every other operation is tenant scope.
const ScopeExtension = "x-activediq-scope"

// tenantName matches the names a tenant-scope operation must not accept: the tenant comes from the
// authenticated principal only (ADR-0002, Request row).
var tenantName = regexp.MustCompile(`(?i)^(x-tenant-.*|tenant[_-]?id)$`)

var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// Finding is one violation located at a file (and a line when known).
type Finding struct {
	Rule, File string
	Line       int
	Msg        string
}

func (f Finding) String() string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d: [%s] %s", f.File, f.Line, f.Rule, f.Msg)
	}
	return fmt.Sprintf("%s: [%s] %s", f.File, f.Rule, f.Msg)
}

// CheckOpenAPI scans every OpenAPI document under root/api/openapi. It reports present=false when
// there is none: the check activates when its subject exists.
func CheckOpenAPI(root string) (fs []Finding, present bool, err error) {
	base := filepath.Join(root, OpenAPIDir)
	var files []string
	_ = filepath.WalkDir(base, func(p string, d os.DirEntry, werr error) error {
		if werr == nil && !d.IsDir() {
			switch strings.ToLower(filepath.Ext(p)) {
			case ".yaml", ".yml", ".json":
				files = append(files, p)
			}
		}
		return nil
	})
	sort.Strings(files)
	for _, f := range files {
		present = true
		rel, _ := filepath.Rel(root, f)
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, true, err
		}
		var doc map[string]any
		if err := yaml.Unmarshal(b, &doc); err != nil {
			fs = append(fs, Finding{"openapi-parse", filepath.ToSlash(rel), 0, "cannot parse the OpenAPI document: " + err.Error()})
			continue
		}
		fs = append(fs, checkDoc(filepath.ToSlash(rel), doc)...)
	}
	return fs, present, nil
}

func checkDoc(file string, doc map[string]any) []Finding {
	var fs []Finding
	paths, _ := doc["paths"].(map[string]any)
	names := make([]string, 0, len(paths))
	for p := range paths {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		item, _ := paths[p].(map[string]any)
		if item == nil {
			continue
		}
		if v, _ := item[ScopeExtension].(string); v == "platform" {
			continue
		}
		pathParams, _ := item["parameters"].([]any)
		for _, m := range methods {
			op, _ := item[m].(map[string]any)
			if op == nil {
				continue
			}
			if v, _ := op[ScopeExtension].(string); v == "platform" {
				continue
			}
			where := strings.ToUpper(m) + " " + p
			add := func(what string) {
				fs = append(fs, Finding{"openapi-tenant-param", file, 0,
					where + " is a tenant-scope operation and declares " + what + ": the tenant comes from the authenticated principal, never from a parameter, header or body field (mark a platform operation with " + ScopeExtension + ": platform)"})
			}
			params, _ := op["parameters"].([]any)
			for _, pr := range append(append([]any{}, pathParams...), params...) {
				pm := resolve(doc, pr)
				if name, _ := pm["name"].(string); tenantName.MatchString(name) {
					in, _ := pm["in"].(string)
					add(fmt.Sprintf("the %s parameter %q", in, name))
				}
			}
			if body := resolve(doc, op["requestBody"]); body != nil {
				content, _ := body["content"].(map[string]any)
				for _, mt := range sortedKeys(content) {
					media, _ := content[mt].(map[string]any)
					for _, field := range tenantFields(doc, media["schema"], map[string]bool{}, 0) {
						add(fmt.Sprintf("the body field %q (%s)", field, mt))
					}
				}
			}
		}
	}
	return fs
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// resolve follows a local $ref ("#/a/b/c").
func resolve(doc map[string]any, v any) map[string]any {
	m, _ := v.(map[string]any)
	for i := 0; i < 8 && m != nil; i++ {
		ref, _ := m["$ref"].(string)
		if !strings.HasPrefix(ref, "#/") {
			return m
		}
		var cur any = doc
		for _, seg := range strings.Split(ref[2:], "/") {
			seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
			cm, _ := cur.(map[string]any)
			cur = cm[seg]
		}
		m, _ = cur.(map[string]any)
	}
	return m
}

// tenantFields returns the names of tenant fields reachable in a request schema.
func tenantFields(doc map[string]any, schema any, seen map[string]bool, depth int) []string {
	m, _ := schema.(map[string]any)
	if m == nil || depth > 12 {
		return nil
	}
	if ref, _ := m["$ref"].(string); ref != "" {
		if seen[ref] {
			return nil
		}
		seen[ref] = true
		return tenantFields(doc, resolve(doc, m), seen, depth+1)
	}
	var out []string
	if props, _ := m["properties"].(map[string]any); props != nil {
		for _, k := range sortedKeys(props) {
			if tenantName.MatchString(k) {
				out = append(out, k)
			}
			out = append(out, tenantFields(doc, props[k], seen, depth+1)...)
		}
	}
	for _, key := range []string{"items", "additionalProperties", "not"} {
		out = append(out, tenantFields(doc, m[key], seen, depth+1)...)
	}
	for _, key := range []string{"allOf", "anyOf", "oneOf"} {
		list, _ := m[key].([]any)
		for _, s := range list {
			out = append(out, tenantFields(doc, s, seen, depth+1)...)
		}
	}
	return out
}
