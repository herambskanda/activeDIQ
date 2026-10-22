package main

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// secretWords is the rule 9 secret-name list. credentialWords adds names that are never legitimate
// in a query string (a credential travels in the Authorization header or the session cookie).
var (
	secretWords     = []string{"password", "pwd", "secret", "token", "apiKey", "privateKey", "recoveryKey", "clientSecret"}
	credentialWords = append(append([]string{}, secretWords...), "authorization", "credential", "credentials", "passphrase")
	tokenCreateRe   = regexp.MustCompile(`(?i)(token.*(create|issue|mint)|(create|issue|mint).*token)`)
)

// nameMatches implements rule 9's matching: exact (ignoring case) or by camelCase suffix, never by
// substring or prefix. snake_case and kebab-case names are read as their camelCase spelling, so
// api_key and api-key match apiKey.
func nameMatches(name string, words []string) (string, bool) {
	name = camel(name)
	for _, w := range words {
		if strings.EqualFold(name, w) {
			return w, true
		}
		if len(name) > len(w) && strings.EqualFold(name[len(name)-len(w):], w) {
			if r := rune(name[len(name)-len(w)]); unicode.IsUpper(r) {
				return w, true
			}
		}
	}
	return "", false
}

func camel(s string) string {
	if !strings.ContainsAny(s, "_-") {
		return s
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '_' || r == '-' })
	for i := 1; i < len(parts); i++ {
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

// checkA8 is the linter half of TM-F-SECRETOUT: nothing reachable from a response of an operation
// outside policy.secretResponses carries a secret marker or a secret-named property; no
// credential-named query parameter; no apiKey scheme in a query string; and a secretResponses
// operation is class reveal with a secret.* or token-creation permission. The runtime canary is
// T-0033 / T-0034 and is reported as inactive.
func checkA8(t *tree) []Violation {
	var vs []Violation
	add := func(pos, f string, a ...any) {
		vs = append(vs, Violation{"A8", pos, fmt.Sprintf(f, a...)})
	}
	secretOps := t.policyOps("secretResponses")

	for _, o := range t.ops {
		if _, exempt := secretOps[o.id]; !exempt {
			for _, r := range t.responses(o) {
				if r.node == nil {
					continue
				}
				seen := map[*yaml.Node]bool{}
				onSchema := func(s *yaml.Node, f *srcFile) {
					pos := fmt.Sprintf("%s:%d", f.pos, s.Line)
					switch {
					case scalar(get(s, "x-activediq-secret")) == "true":
						add(pos, "%s response %s reaches a schema marked x-activediq-secret: a secret may be returned only by an operation listed in policy secretResponses (ADR-0004 rule 9, A8)", o.label(), r.status)
					case scalar(get(s, "writeOnly")) == "true":
						add(pos, "%s response %s reaches a writeOnly schema: write-only values never appear in a response (ADR-0004 rule 9, A8)", o.label(), r.status)
					case scalar(get(s, "format")) == "password":
						add(pos, "%s response %s reaches a format: password schema (ADR-0004 rule 9, A8)", o.label(), r.status)
					}
				}
				onProp := func(name string, line int, f *srcFile) {
					if w, ok := nameMatches(name, secretWords); ok {
						add(fmt.Sprintf("%s:%d", f.pos, line), "%s response %s reaches property %q, which matches the secret-name %q: list the operation in policy secretResponses or rename the member (ADR-0004 rule 9, A8)", o.label(), r.status, name, w)
					}
				}
				for _, m := range mediaSchemas(get(r.node, "content")) {
					if m.schema != nil {
						t.walkSchema(r.file, m.schema, seen, onSchema, onProp)
					}
				}
				// Response headers are reachable from the response too, and proxies and access logs keep them.
				if hs := get(r.node, "headers"); hs != nil && hs.Kind == yaml.MappingNode {
					for i := 0; i+1 < len(hs.Content); i += 2 {
						h, hf, ok := t.resolve(r.file, hs.Content[i+1])
						if !ok || h == nil {
							continue
						}
						if w, bad := nameMatches(hs.Content[i].Value, secretWords); bad {
							add(fmt.Sprintf("%s:%d", hf.pos, hs.Content[i].Line), "%s response %s has header %q, which matches the secret-name %q: a secret does not travel in a response header (ADR-0004 rule 9, A8)", o.label(), r.status, hs.Content[i].Value, w)
						}
						if sc := get(h, "schema"); sc != nil {
							t.walkSchema(hf, sc, seen, onSchema, onProp)
						}
					}
				}
			}
		}

		// Query parameters: operation level, resolved through $ref.
		if ps := get(o.node, "parameters"); ps != nil && ps.Kind == yaml.SequenceNode {
			for _, p := range ps.Content {
				n, _, ok := t.resolve(o.file, p)
				if !ok || n == nil || scalar(get(n, "in")) != "query" {
					continue
				}
				if w, bad := nameMatches(scalar(get(n, "name")), credentialWords); bad {
					add(fmt.Sprintf("%s:%d", o.file.pos, n.Line), "%s has query parameter %q, which matches the credential name %q: credentials travel in the Authorization header or the session cookie, never in a URL (ADR-0004 rule 9, A8)", o.label(), scalar(get(n, "name")), w)
				}
			}
		}
	}

	// Shared parameter components named like a credential in a query, even if no operation uses them yet.
	for _, f := range t.files {
		if f.doc == nil {
			continue
		}
		if sec := get(get(f.doc, "components"), "securitySchemes"); sec != nil && sec.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(sec.Content); i += 2 {
				s := deref(sec.Content[i+1])
				if scalar(get(s, "type")) == "apiKey" && scalar(get(s, "in")) == "query" {
					add(fmt.Sprintf("%s:%d", f.pos, sec.Content[i].Line), "security scheme %q is an apiKey in the query string: only bearer tokens and the session cookie are security schemes (ADR-0004 rule 9, A8)", sec.Content[i].Value)
				}
			}
		}
		if prm := get(get(f.doc, "components"), "parameters"); prm != nil && prm.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(prm.Content); i += 2 {
				p := deref(prm.Content[i+1])
				if scalar(get(p, "in")) == "query" {
					if w, bad := nameMatches(scalar(get(p, "name")), credentialWords); bad {
						add(fmt.Sprintf("%s:%d", f.pos, prm.Content[i].Line), "parameter component %q is a query parameter named %q, which matches the credential name %q (ADR-0004 rule 9, A8)", prm.Content[i].Value, scalar(get(p, "name")), w)
					}
				}
			}
		}
	}

	// secretResponses operations: class reveal; permission secret.* or token creation.
	for id, e := range secretOps {
		for _, o := range t.ops {
			if o.id != id {
				continue
			}
			if c := limitClass(o); c != "reveal" {
				add(e.pos, "secretResponses operation %q has rate class %q, not reveal (ADR-0004 rule 10, A8)", id, orDefault(c, "(default)"))
			}
			if !strings.HasPrefix(o.perm, "secret.") && !tokenCreateRe.MatchString(o.perm) {
				add(e.pos, "secretResponses operation %q has permission %q: a secret is returned only under a secret.* permission or a token-creation permission (ADR-0004 rule 9, A8)", id, o.perm)
			}
		}
	}
	return vs
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
