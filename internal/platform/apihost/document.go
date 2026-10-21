package apihost

import (
	_ "embed"
	"encoding/json/v2"
	"fmt"
	"sort"
	"strings"
)

//go:embed spec/openapi.gen.json
var embeddedDocument []byte

// Operation is one operation of the contract as the router checks it.
type Operation struct {
	ID         string
	Tag        string
	Method     string
	Path       string
	Permission string
	Scope      string
	Class      string
}

// Document is the parsed contract: the operations of the embedded openapi.gen.json.
type Document struct {
	ops []Operation
}

// Operations returns the operations ordered by ID.
func (d Document) Operations() []Operation { return append([]Operation(nil), d.ops...) }

// LoadDocument parses the embedded contract (spec/openapi.gen.json), the one the server serves.
func LoadDocument() (Document, error) { return ParseDocument(embeddedDocument) }

// ParseDocument parses a bundled contract. Build and fitness-api use LoadDocument; tests use this.
func ParseDocument(b []byte) (Document, error) {
	var raw struct {
		Paths map[string]map[string]struct {
			OperationID string   `json:"operationId"`
			Tags        []string `json:"tags"`
			Permission  string   `json:"x-permission"`
			Scope       string   `json:"x-activediq-scope"`
			Limits      struct {
				Class string `json:"class"`
			} `json:"x-activediq-limits"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return Document{}, fmt.Errorf("apihost: the contract does not parse: %w", err)
	}
	var d Document
	for path, item := range raw.Paths {
		for method, o := range item {
			m := strings.ToUpper(method)
			switch m {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
			default:
				continue // path-level keys such as "parameters"
			}
			if len(o.Tags) != 1 {
				return Document{}, fmt.Errorf("apihost: %s %s must have exactly one tag", m, path)
			}
			scope := o.Scope
			if scope == "" {
				scope = "tenant"
			}
			d.ops = append(d.ops, Operation{ID: o.OperationID, Tag: o.Tags[0], Method: m, Path: path, Permission: o.Permission, Scope: scope, Class: o.Limits.Class})
		}
	}
	sort.Slice(d.ops, func(i, j int) bool { return d.ops[i].ID < d.ops[j].ID })
	return d, nil
}

// PermissionCatalogue is the EP-6 permission set. Build refuses an operation whose x-permission is
// not in it.
type PermissionCatalogue interface {
	Has(permission string) bool
}

// Permissions is a PermissionCatalogue over a fixed list.
type Permissions []string

// Has reports whether the permission is in the list.
func (p Permissions) Has(permission string) bool {
	for _, s := range p {
		if s == permission {
			return true
		}
	}
	return false
}
