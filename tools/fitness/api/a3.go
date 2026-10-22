package main

import (
	"fmt"
	"go.yaml.in/yaml/v3"
	"regexp"
	"strings"
)

var (
	anIDRe     = regexp.MustCompile(`^AN-[0-9]+$`)
	permIDRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]*$`)
	anOpAllows = map[string]bool{"AN-1": true, "AN-4": true, "AN-5": true, "AN-7": true, "AN-8": true, "AN-10": true}
)

// checkA3 is the document half of ADR-0004 A3: every operation carries exactly one x-permission;
// anonymous names its allow-list row and has a policy.anonymous entry; authenticated has a
// policy.authenticated entry. The runtime half (a permission no Registrar declares) needs the EP-6
// catalogue and is reported as inactive.
func checkA3(t *tree) []Violation {
	var vs []Violation
	add := func(pos, f string, a ...any) {
		vs = append(vs, Violation{"A3", pos, fmt.Sprintf(f, a...)})
	}
	anon := t.policyOps("anonymous")
	authn := t.policyOps("authenticated")
	byID := map[string]operation{}
	for _, o := range t.ops {
		byID[o.id] = o
	}

	for _, o := range t.ops {
		var perms []string
		bad := false
		if o.node != nil {
			for i := 0; i+1 < len(o.node.Content); i += 2 {
				if o.node.Content[i].Value != "x-permission" {
					continue
				}
				v := deref(o.node.Content[i+1])
				perms = append(perms, scalar(v))
				if v.Kind != yaml.ScalarNode {
					bad = true
				}
			}
		}
		switch {
		case len(perms) == 0:
			add(o.where(), "%s has no x-permission: every operation names exactly one permission, authenticated or anonymous (ADR-0004 rule 3, A3)", o.label())
			continue
		case len(perms) > 1 || bad:
			add(o.where(), "%s has more than one x-permission, or one that is not a single scalar: an operation names exactly one (ADR-0004 rule 3, A3)", o.label())
			continue
		case perms[0] == "" || !permIDRe.MatchString(perms[0]):
			add(o.where(), "%s has x-permission %q, which is not a permission ID, authenticated or anonymous (ADR-0004 rule 3, A3)", o.label(), perms[0])
			continue
		}
		an := scalar(get(o.node, "x-activediq-anonymous"))
		switch o.perm {
		case "anonymous":
			if an == "" {
				add(o.where(), "%s is anonymous but has no x-activediq-anonymous naming its allow-list row (ADR-0004 rule 3, A3)", o.label())
			} else if !anIDRe.MatchString(an) || !anOpAllows[an] {
				add(o.where(), "%s: x-activediq-anonymous %q is not an operation row of the allow-list (AN-1, AN-4, AN-5, AN-7, AN-8, AN-10) (ADR-0004 rule 3, A3)", o.label(), an)
			} else if len(t.anRows) > 0 && !t.anRows[an] {
				add(o.where(), "%s: x-activediq-anonymous %s is not a row of the threat model's anonymous allow-list (ADR-0004 rule 9, A3)", o.label(), an)
			}
			e, ok := anon[o.id]
			switch {
			case !ok:
				add(o.where(), "%s is anonymous but policy.yaml anonymous has no entry for operation %q: an anonymous operation needs a reviewed policy row (ADR-0004 rule 9, A3)", o.label(), o.id)
			case an != "" && !strings.Contains(e.fields["ref"], an):
				add(e.pos, "policy anonymous entry for %q cites %q but the operation declares %s (ADR-0004 rule 9, A3)", o.id, e.fields["ref"], an)
			}
		case "authenticated":
			if an != "" {
				add(o.where(), "%s carries x-activediq-anonymous %s but is not anonymous (ADR-0004 rule 3, A3)", o.label(), an)
			}
			if _, ok := authn[o.id]; !ok {
				add(o.where(), "%s is authenticated but policy.yaml authenticated has no entry for operation %q: an operation with no specific permission needs a reviewed policy row (ADR-0004 rule 9, A3)", o.label(), o.id)
			}
		default:
			if an != "" {
				add(o.where(), "%s carries x-activediq-anonymous %s but its permission is %q (ADR-0004 rule 3, A3)", o.label(), an, o.perm)
			}
		}
	}

	// The converse: a policy row that exempts an operation which does not declare the matching literal.
	for _, c := range []struct {
		section, literal string
		rows             map[string]policyEntry
	}{{"anonymous", "anonymous", anon}, {"authenticated", "authenticated", authn}} {
		for id, e := range c.rows {
			if o, ok := byID[id]; ok && o.perm != c.literal {
				add(e.pos, "policy %s lists operation %q but its x-permission is %q, not %q: the row would exempt a permissioned operation (ADR-0004 rule 9, A3)", c.section, id, o.perm, c.literal)
			}
		}
	}
	return vs
}
