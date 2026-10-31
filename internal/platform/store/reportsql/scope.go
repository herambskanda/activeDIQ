package reportsql

import (
	"fmt"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
)

// This file renders a ReadScope and a Narrowing into SQL (contract §4.3, §4.4). Every part is
// parenthesised, every place where SQL could yield NULL is closed explicitly, and nothing that
// cannot be rendered renders as TRUE.

type term struct {
	kind       authz.TermKind
	conn, root string // canonical GUID text, bound as uuid
}

type layer struct{ include, exclude []term }

// scopePlan is the ReadScope after the fail-closed decisions (§4.3): grants that can admit
// something, the token layer, or "empty" meaning the whole scope renders FALSE.
type scopePlan struct {
	empty  bool
	grants []layer
	token  *layer
}

func knownKind(k authz.TermKind) bool {
	return k == authz.TermNamingContext || k == authz.TermSubtree || k == authz.TermOneLevel
}

func (b *builder) reason(r string) {
	for _, have := range b.reasons {
		if have == r {
			return
		}
	}
	b.reasons = append(b.reasons, r)
}

func toTerm(t authz.ScopeTerm) term {
	return term{kind: t.Kind, conn: report.GUIDString(t.Connection), root: report.GUIDString(t.Root)}
}

func (b *builder) planScope(s authz.ReadScope) (*scopePlan, error) {
	p := &scopePlan{}
	if s.Empty() {
		b.reason("scope_empty")
		p.empty = true
		return p, nil
	}
	grants := s.Terms()
	tok, hasTok := s.Token()
	n := 0
	for _, g := range grants {
		n += len(g.Include) + len(g.Exclude)
	}
	n += len(tok.Include) + len(tok.Exclude)
	if n > MaxScopeTerms {
		return nil, ErrScopeTooLarge
	}
	for _, g := range grants {
		var l layer
		dropped := false
		for _, t := range g.Include {
			switch {
			case t.Connection.IsZero() || t.Root.IsZero():
				b.reason("scope_term_invalid")
				dropped = true
			case !knownKind(t.Kind):
				b.reason(fmt.Sprintf("scope_term_unsupported:%d", t.Kind))
			default:
				l.include = append(l.include, toTerm(t))
			}
		}
		for _, t := range g.Exclude {
			switch {
			case t.Connection.IsZero() || t.Root.IsZero():
				b.reason("scope_term_invalid")
				dropped = true
			case !knownKind(t.Kind):
				b.reason(fmt.Sprintf("scope_term_unsupported:%d", t.Kind))
				dropped = true
			default:
				l.exclude = append(l.exclude, toTerm(t))
			}
		}
		if !dropped && len(l.include) > 0 {
			p.grants = append(p.grants, l)
		}
	}
	if len(p.grants) == 0 {
		p.empty = true
		return p, nil
	}
	if hasTok {
		var l layer
		for _, t := range append(append([]authz.ScopeTerm{}, tok.Include...), tok.Exclude...) {
			if t.Connection.IsZero() || t.Root.IsZero() {
				b.reason("scope_term_invalid")
				p.empty = true
			} else if !knownKind(t.Kind) {
				b.reason(fmt.Sprintf("scope_term_unsupported:%d", t.Kind))
				p.empty = true
			}
		}
		if p.empty {
			return p, nil
		}
		for _, t := range tok.Include {
			l.include = append(l.include, toTerm(t))
		}
		for _, t := range tok.Exclude {
			l.exclude = append(l.exclude, toTerm(t))
		}
		p.token = &l
	}
	return p, nil
}

// scopeSQL is scope(a) of §4.3 over the alias.
func (b *builder) scopeSQL(a *anchor, alias string) string {
	if b.plan.empty {
		return "FALSE"
	}
	var g []string
	for _, l := range b.plan.grants {
		g = append(g, "("+b.layerSQL(a, alias, l)+")")
	}
	s := "(" + alias + "." + a.done + ") AND (" + strings.Join(g, " OR ") + ")"
	if b.plan.token != nil {
		s += " AND (" + b.layerSQL(a, alias, *b.plan.token) + ")"
	}
	return "COALESCE(" + s + ", false)"
}

// layerSQL is inc(...) [AND NOT exc(...)] for a grant or the token layer.
func (b *builder) layerSQL(a *anchor, alias string, l layer) string {
	s := "(" + b.termsSQL(a, alias, l.include, "false") + ")"
	if len(l.exclude) > 0 {
		s += " AND NOT (" + b.termsSQL(a, alias, l.exclude, "true") + ")"
	}
	return s
}

// termsSQL ORs the terms, each closed with COALESCE(term, unknown): an include's NULL is "no", an
// exclude's NULL is "excluded".
func (b *builder) termsSQL(a *anchor, alias string, ts []term, unknown string) string {
	if len(ts) == 0 {
		return "FALSE"
	}
	parts := make([]string, 0, len(ts))
	for _, t := range ts {
		parts = append(parts, "(COALESCE("+b.termSQL(a, alias, t)+", "+unknown+"))")
	}
	return strings.Join(parts, " OR ")
}

func (b *builder) termSQL(a *anchor, alias string, t term) string {
	conn := alias + "." + a.conn + " = " + b.bind("uuid", t.conn)
	root := b.bind("uuid", t.root)
	switch t.kind {
	case authz.TermNamingContext:
		return "(" + conn + " AND " + alias + "." + a.nc + " = " + root + ")"
	case authz.TermSubtree:
		return "(" + conn + " AND (" + alias + "." + a.obj + " = " + root + " OR " + alias + "." + a.anc + " @> ARRAY[" + root + "]::uuid[]))"
	case authz.TermOneLevel:
		return "(" + conn + " AND " + alias + "." + a.parent + " = " + root + ")"
	}
	return "FALSE" // unreachable: planScope drops unknown kinds
}

// narrowSQL is narrowing(t) of §4.4: it narrows, it never renders TRUE, and an empty narrowing
// renders nothing ("").
func (b *builder) narrowSQL(n report.Narrowing, a *anchor, alias string) string {
	var parts []string
	if len(n.Connections) > 0 {
		ids := make([]string, 0, len(n.Connections))
		for _, c := range n.Connections {
			ids = append(ids, report.GUIDString(c))
		}
		parts = append(parts, "("+alias+"."+a.conn+" = ANY("+b.bindList("uuid[]", ids)+"))")
	}
	conv := func(rs []report.NarrowRoot) []term {
		out := make([]term, 0, len(rs))
		for _, r := range rs {
			k := authz.TermSubtree
			if r.Depth == report.DepthOneLevel {
				k = authz.TermOneLevel
			}
			out = append(out, term{kind: k, conn: report.GUIDString(r.Connection), root: report.GUIDString(r.Root)})
		}
		return out
	}
	if len(n.Include) > 0 {
		parts = append(parts, "("+b.termsSQL(a, alias, conv(n.Include), "false")+")")
	}
	if len(n.Exclude) > 0 {
		parts = append(parts, "NOT ("+b.termsSQL(a, alias, conv(n.Exclude), "true")+")")
	}
	return strings.Join(parts, " AND ")
}

// checkNarrowing refuses a zero GUID or an unknown depth: a 400, never a silently dropped clause.
func checkNarrowing(n report.Narrowing) error {
	bad := report.ValidationError{Code: report.CodeBadNarrowing, Path: "narrowing"}
	for _, c := range n.Connections {
		if c.IsZero() {
			return bad
		}
	}
	for _, list := range [][]report.NarrowRoot{n.Include, n.Exclude} {
		for _, r := range list {
			if r.Connection.IsZero() || r.Root.IsZero() || (r.Depth != report.DepthSubtree && r.Depth != report.DepthOneLevel) {
				return bad
			}
		}
	}
	return nil
}
