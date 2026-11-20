package directory_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/modules/directory/api"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
)

// Contract tests of the AD Explorer operations (T-2087, spec ad-explorer-read-api.md section 3; fitness EX3).
// They read the bundled contract the server serves.

var explorerOps = []struct{ id, path string }{
	{"listExplorerRoots", "/directory/explorer/roots"},
	{"getExplorerNode", "/directory/explorer/nodes/{objectGuid}"},
	{"listExplorerChildren", "/directory/explorer/nodes/{objectGuid}/children"},
}

// AC1: the three operations exist as permissioned reads under directory.read.
func TestExplorerOperationsExist(t *testing.T) {
	doc, err := apihost.LoadDocument()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]apihost.Operation{}
	for _, op := range doc.Operations() {
		got[op.ID] = op
	}
	for _, want := range explorerOps {
		op, ok := got[want.id]
		if !ok {
			t.Errorf("operation %s is missing", want.id)
			continue
		}
		if op.Method != "GET" || op.Path != want.path || op.Permission != "directory.read" || op.Class != "read" || op.Tag != "directory" {
			t.Errorf("%s = %+v", want.id, op)
		}
	}
}

// AC1/EX3: every path identifier is a uuid; no parameter takes a DN, a filter or a free-form key; the
// cursor is opaque and bounded.
func TestExplorerParametersAreUUIDsAndTypedOnly(t *testing.T) {
	d := loadBundle(t)
	allowed := map[string]bool{"objectGuid": true, "connection_id": true, "view": true, "limit": true, "cursor": true}
	for _, op := range explorerOps {
		get := sub(t, d, "paths", op.path, "get")
		params, _ := get["parameters"].([]any)
		for _, p := range params {
			pm := resolveParam(t, d, p.(map[string]any))
			name, _ := pm["name"].(string)
			if !allowed[name] {
				t.Errorf("%s: unexpected parameter %q (no filter, dn or free-form input is accepted)", op.id, name)
			}
			sch, _ := pm["schema"].(map[string]any)
			switch name {
			case "objectGuid", "connection_id":
				if sch["type"] != "string" || sch["format"] != "uuid" {
					t.Errorf("%s: %s must be a uuid, got %v", op.id, name, sch)
				}
			case "cursor":
				if sch["type"] != "string" || sch["maxLength"] != float64(512) {
					t.Errorf("%s: cursor must be an opaque string of at most 512, got %v", op.id, sch)
				}
			}
			if name == "objectGuid" && pm["in"] != "path" {
				t.Errorf("%s: objectGuid must be a path parameter", op.id)
			}
		}
		if _, has := get["requestBody"]; has {
			t.Errorf("%s: a GET read takes no body", op.id)
		}
	}
}

func resolveParam(t *testing.T, d map[string]any, p map[string]any) map[string]any {
	t.Helper()
	if ref, ok := p["$ref"].(string); ok {
		return sub(t, d, "components", "parameters", ref[strings.LastIndex(ref, "/")+1:])
	}
	return p
}

// EX3: no Explorer schema, however deep, has a dn property or any property named like a DN.
func TestExplorerSchemasCarryNoDN(t *testing.T) {
	d := loadBundle(t)
	seen := map[string]bool{}
	var walk func(name string)
	walk = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		s := schema(t, d, name)
		props, _ := s["properties"].(map[string]any)
		for prop, v := range props {
			l := strings.ToLower(prop)
			if l == "dn" || strings.Contains(l, "distinguishedname") {
				t.Errorf("%s has property %q: a DN is never returned (spec X8)", name, prop)
			}
			collectRefs(v, walk)
		}
		collectRefs(s["items"], walk)
	}
	for _, root := range []string{"ExplorerRoots", "ExplorerNode", "ExplorerChildren"} {
		walk(root)
	}
	for _, must := range []string{"ExplorerEntry", "ExplorerPathItem"} {
		if !seen[must] {
			t.Errorf("%s is not reachable from the Explorer responses", must)
		}
	}
}

func collectRefs(v any, f func(string)) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	if r, ok := m["$ref"].(string); ok && strings.Contains(r, "/schemas/Explorer") {
		f(r[strings.LastIndex(r, "/")+1:])
	}
	collectRefs(m["items"], f)
	for _, k := range []string{"oneOf", "anyOf", "allOf"} {
		if l, ok := m[k].([]any); ok {
			for _, e := range l {
				collectRefs(e, f)
			}
		}
	}
}

// Every identifier an Explorer entry carries is a uuid, and the entry shape has the spec's fields.
func TestExplorerEntryShape(t *testing.T) {
	d := loadBundle(t)
	e := schema(t, d, "ExplorerEntry")
	props := e["properties"].(map[string]any)
	for _, f := range []string{"objectGuid", "connectionId"} {
		p := props[f].(map[string]any)
		if p["format"] != "uuid" {
			t.Errorf("%s is not a uuid: %v", f, p)
		}
	}
	for _, f := range []string{"parentGuid", "kind", "objectClass", "name", "isContainer", "hasChildren", "tier0", "readOnly", "samAccountName", "upn", "enabled", "whenChanged"} {
		if _, ok := props[f]; !ok {
			t.Errorf("ExplorerEntry lacks %s", f)
		}
	}
	for _, name := range []string{"ExplorerRoots", "ExplorerNode", "ExplorerChildren"} {
		if _, ok := schema(t, d, name)["properties"].(map[string]any)["asOf"]; !ok {
			t.Errorf("%s lacks asOf", name)
		}
	}
	if _, has := schema(t, d, "ExplorerChildren")["properties"].(map[string]any)["total"]; has {
		t.Error("ExplorerChildren must not carry a total count (LF-39)")
	}
}

// Until T-2089 lands the read model, the operations answer 501 and never a made-up tree.
func TestExplorerAnswersNotImplementedUntilItsReadModelLands(t *testing.T) {
	h := directory.Handlers{}
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"roots":    func() error { _, err := h.ListExplorerRoots(ctx, api.ListExplorerRootsInput{}); return err },
		"node":     func() error { _, err := h.GetExplorerNode(ctx, api.GetExplorerNodeInput{}); return err },
		"children": func() error { _, err := h.ListExplorerChildren(ctx, api.ListExplorerChildrenInput{}); return err },
	} {
		var p *apitypes.Problem
		if err := call(); !errors.As(err, &p) || p.Status != 501 {
			t.Errorf("%s: want a 501 problem, got %v", name, err)
		}
	}
}
