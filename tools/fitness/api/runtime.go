package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/skenzeriq/activediq/internal/compose/profile"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

// The runtime half of fitness-api (A4, A7 closure/corpus, A14) builds the real router with
// apihost.Build, the same function compose/server calls, and probes it in process. Three seams
// keep it testable and honest about what exists:
//   - tagSource says which routes a deployment profile mounts. The real source is the module list;
//     no module contributes API routes yet (Registrar.API is unbuilt), so it returns nothing and
//     the checks say so in their inactive part. Fixtures substitute their own.
//   - nonAPIServed enumerates routes mounted outside the document (/healthz, the console). Nothing
//     serves one yet, so it reports unavailable and A4/A13 name that as inactive.
//   - the corpus and cross-check run against the bundle at internal/platform/apihost/spec.

// runtimeEnv is everything one runtime run needs.
type runtimeEnv struct {
	root      string
	doc       apihost.Document
	bundle    []byte
	policy    apihost.Policy
	nonAPI    []policyRoute // nonApiRoutes entries
	profiles  []string
	tags      func(profile string) ([]apihost.TagHandlers, error)
	nonAPISrv func(profile string) (routes []string, available bool)
}

type policyRoute struct{ Method, Path string }

// tagSource is the real source of mounted routes per profile: the module list's API contributions.
var tagSource = func(string) ([]apihost.TagHandlers, error) { return nil, nil }

// nonAPIServedSource lists "METHOD /path" routes mounted outside the document; ok is false while
// no server mounts any.
var nonAPIServedSource = func(string) ([]string, bool) { return nil, false }

const bundleRel = "internal/platform/apihost/spec/openapi.gen.json"

// hostFor is the hostname the probe gives a binding: a reserved name that cannot be a real host.
func hostFor(binding string) string { return binding + ".fitness.invalid" }

// loadRuntime reads the bundle and the policy of the tree. A problem is returned as violations of
// the named check so a broken input fails the job instead of skipping the check.
func loadRuntime(t *tree, check string) (*runtimeEnv, []Violation) {
	env := &runtimeEnv{root: t.root, tags: tagSource, nonAPISrv: nonAPIServedSource}
	for _, m := range []profile.Manifest{profile.Windows(), profile.LinuxOCI(), profile.SaaS()} {
		env.profiles = append(env.profiles, m.Name)
	}
	b, err := os.ReadFile(filepath.Join(t.root, filepath.FromSlash(bundleRel)))
	if err != nil {
		return nil, []Violation{{check, bundleRel, "cannot read the embedded contract, so the router cannot be built: " + err.Error() + " (ADR-0004)"}}
	}
	doc, err := apihost.ParseDocument(b)
	if err != nil {
		return nil, []Violation{{check, bundleRel, "the embedded contract does not parse: " + err.Error() + " (ADR-0004)"}}
	}
	env.doc, env.bundle = doc, b
	env.policy, env.nonAPI = policyFromTree(t, doc)
	return env, nil
}

// policyFromTree turns policy.yaml into the apihost.Policy the server loads. An anonymous entry
// naming a route is matched to its operation; entries A13 rejects are ignored here.
func policyFromTree(t *tree, doc apihost.Document) (apihost.Policy, []policyRoute) {
	p := apihost.Policy{Hosts: map[string]string{}}
	var non []policyRoute
	for _, b := range apihost.HostBindings {
		p.Hosts[b.Name] = hostFor(b.Name)
	}
	pf := t.byRel["policy.yaml"]
	if pf == nil || pf.doc == nil {
		return p, nil
	}
	byRoute := map[string]string{}
	for _, o := range doc.Operations() {
		byRoute[o.Method+" "+apiPrefix+o.Path] = o.ID
	}
	for _, sec := range []string{"anonymous", "authenticated", "stepUp", "nonApiRoutes"} {
		list := get(pf.doc, sec)
		if list == nil || list.Kind != yaml.SequenceNode {
			continue
		}
		for _, e := range list.Content {
			e = deref(e)
			if e.Kind != yaml.MappingNode {
				continue
			}
			f := map[string]string{}
			for i := 0; i+1 < len(e.Content); i += 2 {
				f[e.Content[i].Value] = strings.TrimSpace(deref(e.Content[i+1]).Value)
			}
			op := f["operation"]
			if op == "" && f["method"] != "" {
				op = byRoute[strings.ToUpper(f["method"])+" "+f["path"]]
			}
			switch sec {
			case "anonymous":
				if op != "" {
					p.Anonymous = append(p.Anonymous, apihost.AnonymousRow{Operation: op, Host: f["host"], Gate: f["gate"]})
				}
			case "authenticated":
				if op != "" {
					p.Authenticated = append(p.Authenticated, op)
				}
			case "stepUp":
				if f["permission"] != "" {
					p.StepUp = append(p.StepUp, f["permission"])
				}
			case "nonApiRoutes":
				non = append(non, policyRoute{strings.ToUpper(f["method"]), f["path"]})
			}
		}
	}
	return p, non
}

// catalogueOf is every permission the document names. A3's catalogue half owns whether each is
// declared by a Registrar; the route probe only needs Build to accept them.
func catalogueOf(doc apihost.Document) apihost.Permissions {
	seen := map[string]bool{}
	var out apihost.Permissions
	for _, o := range doc.Operations() {
		if o.Permission != "" && o.Permission != "anonymous" && o.Permission != "authenticated" && !seen[o.Permission] {
			seen[o.Permission] = true
			out = append(out, o.Permission)
		}
	}
	sort.Strings(out)
	return out
}

// probePorts are the fake kernel ports of the route probe. The principal is chosen by header so
// one router answers every case: none → unauthenticated, nobody → a token with no permissions,
// session → a cookie session whose CSRF header is the request's X-CSRF-Token.
type probePorts struct{}

const principalHeader = "X-Fitness-Principal"

func (probePorts) Authenticate(r *http.Request) (apihost.Principal, error) {
	switch r.Header.Get(principalHeader) {
	case "nobody":
		return apihost.Principal{ID: "nobody", Kind: apihost.KindToken}, nil
	case "session":
		return apihost.Principal{ID: "nobody", Kind: apihost.KindSession}, nil
	}
	return apihost.Principal{}, apihost.ErrUnauthenticated
}

func (probePorts) CheckCSRF(r *http.Request, _ apihost.Principal) error {
	if r.Header.Get("X-CSRF-Token") == "" {
		return apihost.ErrCSRF
	}
	return nil
}

func (probePorts) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return false, nil // the principal has no permissions
}
func (probePorts) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (probePorts) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (probePorts) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

func (probePorts) ports() apihost.Ports {
	return apihost.Ports{Authn: probePorts{}, Authz: probePorts{}, Limits: probePorts{}, StepUp: probePorts{}}
}

// concretePath replaces ServeMux wildcards with a fixed segment.
func concretePath(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] != '{' {
			b.WriteByte(p[i])
			continue
		}
		j := strings.IndexByte(p[i:], '}')
		if j < 0 {
			b.WriteString(p[i:])
			break
		}
		if strings.HasSuffix(p[i:i+j], "...") {
			b.WriteString("x/y")
		} else {
			b.WriteString("x")
		}
		i += j
	}
	return b.String()
}

func fail(check, pos, format string, a ...any) Violation {
	return Violation{check, pos, fmt.Sprintf(format, a...)}
}

// quiet keeps Build's "tag not mounted" notes out of the job's output: the status table says it.
var quiet = apihost.WithLogger(slog.New(slog.DiscardHandler))
