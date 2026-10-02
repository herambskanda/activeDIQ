// Package registry loads and validates the tenancy exemption registry of ADR-0002 (rule 4): the one
// place a global table, a SECURITY DEFINER function, a platform-scope call site or a platform job is
// allowed to exist. Every entry carries a reason; every global table also names its owning package.
//
// The registry is data (JSON) so that the fitness job reads the same file the product embeds
// (internal/platform/store/exempt, T-0037): there is no second list to drift. A missing file is an
// empty registry, which is the state before the tenancy foundation lands.
package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// DefaultPath is where the product keeps the registry (blueprint §1.1), relative to the repository root.
const DefaultPath = "internal/platform/store/exempt/registry.json"

// GlobalTable is a table that is deliberately not tenant-scoped: it carries no tenant_id and no RLS.
// Because RLS does not cover it, any tenant transaction can read it, so only Owner's SQL may name it.
type GlobalTable struct {
	Table  string `json:"table"`  // schema-qualified: public.tenants
	Reason string `json:"reason"` // why it cannot be tenant-scoped
	Owner  string `json:"owner"`  // repo-relative package directory that alone may reference it
}

// SecurityDefiner exempts one SECURITY DEFINER function.
type SecurityDefiner struct {
	Function string `json:"function"` // regprocedure text: public.f(uuid)
	Reason   string `json:"reason"`
}

// PlatformPath is a function allowed to act outside any tenant: to call store.WithPlatform and/or to
// mint a tenant.ID. Enrollment, tenant provisioning and first-run bootstrap are the first entries.
type PlatformPath struct {
	Package       string `json:"package"`  // repo-relative package directory
	Function      string `json:"function"` // function or Receiver.Method name
	Reason        string `json:"reason"`
	WithPlatform  bool   `json:"withPlatform"`  // the function calls WithPlatform
	MintsTenantID bool   `json:"mintsTenantID"` // the function constructs a tenant.ID
}

// PlatformJob is a job type that carries no tenant (a registered platform job).
type PlatformJob struct {
	Type   string `json:"type"` // repo-relative package directory + "." + type name
	Reason string `json:"reason"`
}

// ProbeValue overrides the value the isolation probes (T4) put in one column when the generated
// value cannot satisfy a CHECK constraint or a domain. It is a bound text parameter, never SQL.
type ProbeValue struct {
	Column string `json:"column"` // schema.table.column
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// Registry is the whole exemption registry.
type Registry struct {
	GlobalTables    []GlobalTable     `json:"globalTables"`
	SecurityDefiner []SecurityDefiner `json:"securityDefiner"`
	PlatformPaths   []PlatformPath    `json:"platformPaths"`
	PlatformJobs    []PlatformJob     `json:"platformJobs"`
	ProbeValues     []ProbeValue      `json:"probeValues"`
}

// Load reads the registry at path. A missing file is an empty registry. Unknown fields are an error,
// so a misspelt key cannot silently exempt nothing.
func Load(path string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Registry{}, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes registry JSON strictly.
func Parse(b []byte) (*Registry, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Registry
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	if dec.More() {
		return nil, errors.New("registry: trailing data after the JSON document")
	}
	return &r, nil
}

// Problem is one structural defect of the registry (a missing reason or owner, a duplicate).
type Problem struct{ Entry, Msg string }

func (p Problem) String() string { return p.Entry + ": " + p.Msg }

// Validate reports entries without a reason, global tables without an owning package, entries that are
// not well formed and duplicates. It does not look at the database or the source: staleness (an entry
// naming something that no longer exists) is checked where the object is visible.
func (r *Registry) Validate() []Problem {
	var ps []Problem
	add := func(entry, msg string) { ps = append(ps, Problem{entry, msg}) }
	need := func(entry, reason string) {
		if strings.TrimSpace(reason) == "" {
			add(entry, "registry entry has no reason")
		}
	}
	seen := map[string]bool{}
	dup := func(kind, key string) {
		if seen[kind+"\x00"+key] {
			add(key, "duplicate "+kind+" entry")
		}
		seen[kind+"\x00"+key] = true
	}
	for _, g := range r.GlobalTables {
		e := "globalTables[" + g.Table + "]"
		dup("globalTable", g.Table)
		need(e, g.Reason)
		if strings.Count(g.Table, ".") != 1 || strings.HasPrefix(g.Table, ".") || strings.HasSuffix(g.Table, ".") {
			add(e, "table must be schema-qualified: schema.table")
		}
		if strings.TrimSpace(g.Owner) == "" {
			add(e, "global table names no owning package (the only package whose SQL may reference it)")
		} else if strings.HasPrefix(g.Owner, "/") || strings.Contains(g.Owner, "..") {
			add(e, "owner must be a repo-relative package directory")
		}
	}
	for _, s := range r.SecurityDefiner {
		e := "securityDefiner[" + s.Function + "]"
		dup("securityDefiner", s.Function)
		need(e, s.Reason)
		if !strings.Contains(s.Function, "(") {
			add(e, "function must be regprocedure text with its argument types: schema.name(argtypes)")
		}
	}
	for _, p := range r.PlatformPaths {
		e := "platformPaths[" + p.Package + "." + p.Function + "]"
		dup("platformPath", p.Package+"."+p.Function)
		need(e, p.Reason)
		if p.Package == "" || p.Function == "" {
			add(e, "package and function are both required")
		}
		if !p.WithPlatform && !p.MintsTenantID {
			add(e, "entry exempts nothing: set withPlatform and/or mintsTenantID")
		}
	}
	for _, j := range r.PlatformJobs {
		e := "platformJobs[" + j.Type + "]"
		dup("platformJob", j.Type)
		need(e, j.Reason)
		if !strings.Contains(j.Type, ".") {
			add(e, "type must be package-directory.TypeName")
		}
	}
	for _, v := range r.ProbeValues {
		e := "probeValues[" + v.Column + "]"
		dup("probeValue", v.Column)
		need(e, v.Reason)
		if strings.Count(v.Column, ".") != 2 {
			add(e, "column must be schema.table.column")
		}
	}
	return ps
}

// Global returns the global-table entry for a schema-qualified table name.
func (r *Registry) Global(table string) (GlobalTable, bool) {
	for _, g := range r.GlobalTables {
		if g.Table == table {
			return g, true
		}
	}
	return GlobalTable{}, false
}
