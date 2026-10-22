package main

import (
	"fmt"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"path"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Policy entry shape (ADR-0004 rule 9). api/openapi/policy.yaml has six sections, each a list of
// entries with scalar fields only:
//
//	operation   an operationId of the contract
//	method,path an HTTP method and path (relative to /api/v1, or with the /api/v1 prefix)
//	permission  a permission ID some operation declares in x-permission (stepUp)
//	schema      a response schema name (secretResponses)
//	host        a hostname binding name (optional)
//	gate        the gate that guards an anonymous route (optional)
//	reason      why the entry exists (required)
//	ref         the AN-n row or TM reference that justifies it (required)
type policySection struct {
	name     string
	allowed  []string
	byOp     bool // identified by operation
	byRoute  bool // identified by method+path
	either   bool // by operation, or by method+path (anonymous)
	byPerm   bool
	nonAPI   bool // a route outside the document
	needsSch bool
}

var policySections = []policySection{
	{name: "anonymous", allowed: []string{"operation", "method", "path", "host", "gate", "reason", "ref"}, either: true},
	{name: "authenticated", allowed: []string{"operation", "reason", "ref"}, byOp: true},
	{name: "nonApiRoutes", allowed: []string{"method", "path", "host", "reason", "ref"}, byRoute: true, nonAPI: true},
	{name: "secretResponses", allowed: []string{"operation", "schema", "reason", "ref"}, byOp: true, needsSch: true},
	{name: "stepUp", allowed: []string{"permission", "reason", "ref"}, byPerm: true},
	{name: "largeBodies", allowed: []string{"operation", "reason", "ref"}, byOp: true},
}

var (
	refTokenRe = regexp.MustCompile(`\b(AN-[0-9]+|TM-[A-Za-z0-9][A-Za-z0-9._-]*)`)
	apiPrefix  = "/api/v1"
)

// checkA13 fails a policy.yaml entry that is stale (names a missing route, operation, permission,
// schema or hostname binding) or unexplained (no reason, or no AN/TM reference).
func checkA13(t *tree) []Violation {
	pf := t.byRel["policy.yaml"]
	if pf == nil {
		return []Violation{{"A13", specDir + "/policy.yaml", "policy.yaml is missing (ADR-0004 rule 9)"}}
	}
	if pf.doc == nil {
		return nil // reported by A1 as a parse error; nothing more can be read
	}
	vs := append([]Violation(nil), t.policyDups...)

	ops := map[string]operation{}
	routes := map[string]bool{} // "method path"
	paths := map[string]bool{}
	perms := map[string]bool{}
	for _, o := range t.ops {
		ops[o.id] = o
		routes[o.method+" "+o.path] = true
		paths[o.path] = true
		if o.perm != "" && o.perm != "anonymous" && o.perm != "authenticated" {
			perms[o.perm] = true
		}
	}
	schemas := map[string]bool{}
	for _, c := range t.comps {
		if c.section == "schemas" {
			schemas[c.name] = true
		}
	}

	known := map[string]policySection{}
	for _, s := range policySections {
		known[s.name] = s
	}
	for i := 0; i+1 < len(pf.doc.Content); i += 2 {
		if _, ok := known[pf.doc.Content[i].Value]; !ok {
			vs = append(vs, Violation{"A13", fmt.Sprintf("%s:%d", pf.pos, pf.doc.Content[i].Line), fmt.Sprintf("unknown section %q (the rule 9 sections are anonymous, authenticated, nonApiRoutes, secretResponses, stepUp, largeBodies)", pf.doc.Content[i].Value)})
		}
	}

	for _, sec := range policySections {
		list := get(pf.doc, sec.name)
		if list == nil || list.Kind != yaml.SequenceNode {
			vs = append(vs, Violation{"A13", pf.pos, fmt.Sprintf("section %q must be a list (write [] for none): a missing section would hide its entries from this check (ADR-0004 rule 9)", sec.name)})
			continue
		}
		for _, e := range list.Content {
			e = deref(e)
			where := fmt.Sprintf("%s:%d", pf.pos, e.Line)
			if e.Kind != yaml.MappingNode {
				vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s: an entry must be an object", sec.name)})
				continue
			}
			f := map[string]string{}
			for i := 0; i+1 < len(e.Content); i += 2 {
				k := e.Content[i].Value
				v := deref(e.Content[i+1])
				if !contains(sec.allowed, k) {
					vs = append(vs, Violation{"A13", fmt.Sprintf("%s:%d", pf.pos, e.Content[i].Line), fmt.Sprintf("%s: unknown field %q (allowed: %s)", sec.name, k, strings.Join(sec.allowed, ", "))})
					continue
				}
				if v.Kind != yaml.ScalarNode {
					vs = append(vs, Violation{"A13", fmt.Sprintf("%s:%d", pf.pos, e.Content[i].Line), fmt.Sprintf("%s: field %q must be a scalar", sec.name, k)})
					continue
				}
				f[k] = strings.TrimSpace(v.Value)
			}
			label := entryLabel(sec.name, f)

			// Exemptions must not become permanent: a reason and a reference are mandatory.
			if f["reason"] == "" {
				vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s %s: no reason (ADR-0004 rule 9: an exemption states why it exists)", sec.name, label)})
			}
			if !refTokenRe.MatchString(f["ref"]) {
				vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s %s: no AN/TM reference (ref must name an AN-n row or a TM- section; found %q) (ADR-0004 rule 9)", sec.name, label, f["ref"])})
			}
			// An AN-n must be a row of the threat model's anonymous allow-list; TM- tokens are
			// shape-checked only until a follow-up resolves them against the threat model.
			hasAN := false
			for _, tok := range refTokenRe.FindAllString(f["ref"], -1) {
				if strings.HasPrefix(tok, "AN-") {
					hasAN = true
					if len(t.anRows) > 0 && !t.anRows[tok] {
						vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s %s: reference %s is not a row of the threat model's anonymous allow-list (ADR-0004 rule 9)", sec.name, label, tok)})
					}
				}
			}
			if sec.name == "anonymous" && !hasAN {
				vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s %s: an anonymous route must cite the AN-n row that allows it (ref %q) (ADR-0004 rule 9)", sec.name, label, f["ref"])})
			}

			// Stale: it must name something that exists.
			switch {
			case sec.byPerm:
				if f["permission"] == "" {
					vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s: names no permission", sec.name)})
				} else if !perms[f["permission"]] {
					vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s %s: stale: no operation declares x-permission %q (ADR-0004 rule 9)", sec.name, label, f["permission"])})
				}
			case sec.byRoute:
				vs = append(vs, checkRouteEntry(sec, where, label, f, routes, paths)...)
			default: // by operation, or either
				if f["operation"] == "" {
					if sec.either && f["method"] != "" && f["path"] != "" {
						vs = append(vs, checkRouteEntry(sec, where, label, f, routes, paths)...)
					} else {
						vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s: names no operation%s", sec.name, map[bool]string{true: " or method+path", false: ""}[sec.either])})
					}
					break
				}
				o, ok := ops[f["operation"]]
				if !ok {
					vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s %s: stale: operation %q is not in the contract (ADR-0004 rule 9)", sec.name, label, f["operation"])})
					break
				}
				if f["method"] != "" && !strings.EqualFold(f["method"], o.method) || f["path"] != "" && trimAPI(f["path"]) != o.path {
					vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s %s: stale: operation %q is %s %s, not %s %s", sec.name, label, o.id, strings.ToUpper(o.method), o.path, f["method"], f["path"])})
				}
			}
			if sec.needsSch && f["schema"] == "" {
				vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s %s: names no response schema (a secret response names its single schema) (ADR-0004 rule 9)", sec.name, label)})
			}
			if sec.needsSch && f["schema"] != "" && !schemas[f["schema"]] {
				vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s %s: stale: response schema %q is not declared in the contract (ADR-0004 rule 9)", sec.name, label, f["schema"])})
			}
			if h := f["host"]; h != "" {
				b, ok := apihost.LookupHostBinding(h)
				switch {
				case !ok:
					vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s %s: stale: hostname binding %q is not in apihost's binding table (%s) (ADR-0004 rule 9)", sec.name, label, h, bindingNames())})
				case sec.name == "anonymous" && !refCitesAN(f["ref"], b.Ref):
					vs = append(vs, Violation{"A13", where, fmt.Sprintf("%s %s: hostname binding %q is justified by %s but the entry's ref is %q (ADR-0004 rule 9)", sec.name, label, h, b.Ref, f["ref"])})
				}
			}
		}
	}
	return vs
}

func trimAPI(p string) string {
	if p == apiPrefix {
		return "/"
	}
	return strings.TrimPrefix(p, apiPrefix)
}

// checkRouteEntry validates a method+path entry. A route inside the document (under /api/v1) must
// be an operation; a route outside it cannot be verified until apihost serves one (A4).
func checkRouteEntry(sec policySection, where, label string, f map[string]string, routes, paths map[string]bool) []Violation {
	m, p := f["method"], f["path"]
	if m == "" || p == "" {
		return []Violation{{"A13", where, fmt.Sprintf("%s: names no route (method and path are both required)", sec.name)}}
	}
	if m != strings.ToUpper(m) || !httpMethods[strings.ToLower(m)] {
		return []Violation{{"A13", where, fmt.Sprintf("%s %s: method %q is not an upper-case HTTP method", sec.name, label, m)}}
	}
	if !strings.HasPrefix(p, "/") || path.Clean(p) != p {
		return []Violation{{"A13", where, fmt.Sprintf("%s %s: path %q is not a clean absolute path", sec.name, label, p)}}
	}
	inDoc := p == apiPrefix || strings.HasPrefix(p, apiPrefix+"/")
	rel := trimAPI(p)
	if sec.nonAPI {
		switch {
		case inDoc || strings.HasPrefix(p, "/api/"):
			return []Violation{{"A13", where, fmt.Sprintf("%s %s: a non-API route cannot live under /api/ (it would be an operation of the document) (ADR-0004 rule 5)", sec.name, label)}}
		case paths[p]:
			return []Violation{{"A13", where, fmt.Sprintf("%s %s: stale: %s is a path of the document, not a route outside it", sec.name, label, p)}}
		}
		return servedRoute(sec, where, label, m, p)
	}
	if inDoc {
		if !routes[strings.ToLower(m)+" "+rel] {
			return []Violation{{"A13", where, fmt.Sprintf("%s %s: stale: the contract has no operation %s %s (ADR-0004 rule 9)", sec.name, label, m, rel)}}
		}
		return nil
	}
	if routes[strings.ToLower(m)+" "+p] {
		return nil
	}
	if paths[p] {
		return []Violation{{"A13", where, fmt.Sprintf("%s %s: stale: the contract has no operation %s %s (ADR-0004 rule 9)", sec.name, label, m, p)}}
	}
	return servedRoute(sec, where, label, m, p)
}

func entryLabel(section string, f map[string]string) string {
	switch {
	case f["operation"] != "":
		return f["operation"]
	case f["permission"] != "":
		return f["permission"]
	case f["method"] != "" || f["path"] != "":
		return strings.TrimSpace(f["method"] + " " + f["path"])
	}
	return "(unnamed)"
}

func bindingNames() string {
	var n []string
	for _, b := range apihost.HostBindings {
		n = append(n, b.Name)
	}
	return strings.Join(n, ", ")
}

// servedOutsideDocument is the set of "METHOD /path" the servers mount outside the document, over
// every profile. ok is false while no server mounts any: then an entry cannot be matched, which
// A13's inactive part says, and nothing is failed on a guess.
func servedOutsideDocument() (map[string]bool, bool) {
	out := map[string]bool{}
	any := false
	for _, p := range []string{"windows", "linux-oci", "saas"} {
		if r, ok := nonAPIServedSource(p); ok {
			any = true
			for _, k := range r {
				out[k] = true
			}
		}
	}
	return out, any
}

// servedRoute checks that a route outside the document is one the router serves.
func servedRoute(sec policySection, where, label, m, p string) []Violation {
	served, ok := servedOutsideDocument()
	if !ok || served[m+" "+p] {
		return nil
	}
	return []Violation{{"A13", where, fmt.Sprintf("%s %s: stale: no server mounts %s %s (ADR-0004 rule 9)", sec.name, label, m, p)}}
}
