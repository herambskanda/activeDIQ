package apihost

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

// embeddedPolicy is api/openapi/policy.yaml, copied byte for byte by `make gen-api` (and held
// current by `make gen-api-check`), so the router the server builds and the file fitness-api reads
// cannot drift apart.
//
//go:embed spec/policy.gen.yaml
var embeddedPolicy []byte

// LoadPolicy parses the embedded policy.yaml, the one the server enforces.
func LoadPolicy() (Policy, error) { return ParsePolicy(embeddedPolicy) }

// ParsePolicy parses policy.yaml into the Policy apihost enforces. It is the single parser of that
// file for the server and for fitness-api A4. Unknown top-level sections and unknown host binding
// names fail, so a typo cannot silently widen what is anonymous or served on every hostname.
// Entries that name a route by method and path (the non-API routes and the console's own) are not
// operations of the document and are fitness-api's to check; an entry with neither an operation nor
// a route fails. Policy.Hosts is configuration, not part of the file.
func ParsePolicy(b []byte) (Policy, error) {
	var raw struct {
		Anonymous       []policyEntry `yaml:"anonymous"`
		Authenticated   []policyEntry `yaml:"authenticated"`
		NonAPIRoutes    []policyEntry `yaml:"nonApiRoutes"`
		SecretResponses []policyEntry `yaml:"secretResponses"`
		StepUp          []policyEntry `yaml:"stepUp"`
		LargeBodies     []policyEntry `yaml:"largeBodies"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return Policy{}, fmt.Errorf("apihost: policy.yaml does not parse: %w", err)
	}
	var p Policy
	seen := map[string]bool{}
	for i, e := range raw.Anonymous {
		if e.Host != "" {
			if _, ok := LookupHostBinding(e.Host); !ok {
				return Policy{}, fmt.Errorf("apihost: policy.yaml anonymous[%d] names unknown host binding %q", i, e.Host)
			}
		}
		if e.Operation == "" {
			if e.Method == "" || e.Path == "" {
				return Policy{}, fmt.Errorf("apihost: policy.yaml anonymous[%d] names neither an operation nor a method and path", i)
			}
			continue
		}
		if seen[e.Operation] {
			return Policy{}, fmt.Errorf("apihost: policy.yaml anonymous names operation %q twice", e.Operation)
		}
		seen[e.Operation] = true
		p.Anonymous = append(p.Anonymous, AnonymousRow{Operation: e.Operation, Host: e.Host, Gate: e.Gate})
	}
	for i, e := range raw.Authenticated {
		if e.Operation == "" {
			return Policy{}, fmt.Errorf("apihost: policy.yaml authenticated[%d] names no operation", i)
		}
		p.Authenticated = append(p.Authenticated, e.Operation)
	}
	for i, e := range raw.StepUp {
		if e.Permission == "" {
			return Policy{}, fmt.Errorf("apihost: policy.yaml stepUp[%d] names no permission", i)
		}
		p.StepUp = append(p.StepUp, e.Permission)
	}
	return p, nil
}

// policyEntry is the union of the scalar fields a policy entry may carry (fitness-api A13 checks
// which fields each section allows).
type policyEntry struct {
	Operation  string `yaml:"operation"`
	Method     string `yaml:"method"`
	Path       string `yaml:"path"`
	Permission string `yaml:"permission"`
	Schema     string `yaml:"schema"`
	Host       string `yaml:"host"`
	Gate       string `yaml:"gate"`
	Reason     string `yaml:"reason"`
	Ref        string `yaml:"ref"`
}
