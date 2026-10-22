package apihost

import (
	_ "embed"
	"encoding/json/v2"
	"fmt"
)

// fieldString is a policy field that, when present, must be a non-empty string. A null or empty
// value (YAML `host:` with nothing after it) would otherwise read as "not set" and silently unbind
// a host-bound row, so it fails the parse instead.
type fieldString string

// UnmarshalJSON rejects null and the empty string.
func (f *fieldString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("must be a non-empty string")
	}
	if s == "" {
		return fmt.Errorf("must be a non-empty string")
	}
	*f = fieldString(s)
	return nil
}

// embeddedPolicy is api/openapi/policy.yaml converted to JSON by `make gen-api` (and held current by
// `make gen-api-check`), so the shipped binary links no YAML parser (ADR-0004 F3) and the router
// the server builds cannot drift from the file fitness-api reads.
//
//go:embed spec/policy.gen.json
var embeddedPolicy []byte

// LoadPolicy parses the embedded policy.yaml, the one the server enforces.
func LoadPolicy() (Policy, error) { return ParsePolicy(embeddedPolicy) }

// ParsePolicy parses policy.yaml, as the JSON tools/gen/policyjson makes of it, into the Policy
// apihost enforces. It is the single parser of that file for the server and for fitness-api A4.
// A field that is present but null or empty fails, naming nothing is not "unbound". Unknown top-level sections and unknown host binding
// names fail, so a typo cannot silently widen what is anonymous or served on every hostname.
// Entries that name a route by method and path (the non-API routes and the console's own) are not
// operations of the document and are fitness-api's to check; an entry with neither an operation nor
// a route fails. Policy.Hosts is configuration, not part of the file.
func ParsePolicy(b []byte) (Policy, error) {
	var raw struct {
		Anonymous       []policyEntry `json:"anonymous"`
		Authenticated   []policyEntry `json:"authenticated"`
		NonAPIRoutes    []policyEntry `json:"nonApiRoutes"`
		SecretResponses []policyEntry `json:"secretResponses"`
		StepUp          []policyEntry `json:"stepUp"`
		LargeBodies     []policyEntry `json:"largeBodies"`
	}
	if err := json.Unmarshal(b, &raw, json.RejectUnknownMembers(true)); err != nil {
		return Policy{}, fmt.Errorf("apihost: policy does not parse: %w", err)
	}
	var p Policy
	seen := map[string]bool{}
	for i, e := range raw.Anonymous {
		if e.Host != "" {
			if _, ok := LookupHostBinding(string(e.Host)); !ok {
				return Policy{}, fmt.Errorf("apihost: policy anonymous[%d] names unknown host binding %q", i, e.Host)
			}
		}
		if e.Operation == "" {
			if e.Method == "" || e.Path == "" {
				return Policy{}, fmt.Errorf("apihost: policy anonymous[%d] names neither an operation nor a method and path", i)
			}
			continue
		}
		if seen[string(e.Operation)] {
			return Policy{}, fmt.Errorf("apihost: policy anonymous names operation %q twice", e.Operation)
		}
		seen[string(e.Operation)] = true
		p.Anonymous = append(p.Anonymous, AnonymousRow{Operation: string(e.Operation), Host: string(e.Host), Gate: string(e.Gate)})
	}
	for i, e := range raw.Authenticated {
		if e.Operation == "" {
			return Policy{}, fmt.Errorf("apihost: policy authenticated[%d] names no operation", i)
		}
		p.Authenticated = append(p.Authenticated, string(e.Operation))
	}
	for i, e := range raw.StepUp {
		if e.Permission == "" {
			return Policy{}, fmt.Errorf("apihost: policy stepUp[%d] names no permission", i)
		}
		p.StepUp = append(p.StepUp, string(e.Permission))
	}
	return p, nil
}

// policyEntry is the union of the scalar fields a policy entry may carry (fitness-api A13 checks
// which fields each section allows).
type policyEntry struct {
	Operation  fieldString `json:"operation"`
	Method     fieldString `json:"method"`
	Path       fieldString `json:"path"`
	Permission fieldString `json:"permission"`
	Schema     fieldString `json:"schema"`
	Host       fieldString `json:"host"`
	Gate       fieldString `json:"gate"`
	Reason     fieldString `json:"reason"`
	Ref        fieldString `json:"ref"`
}
