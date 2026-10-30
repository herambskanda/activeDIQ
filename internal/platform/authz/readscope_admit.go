package authz

import "slices"

// ObjectView is what a ReadScope is asked about one directory object when the object was found by a
// live directory query rather than read from an inventory row (search, T-0875). It carries the same
// facts Evaluator.AuthorizeRead is given: the connection the object lives in and its live parent
// chain.
//
// Ancestors and Complete must be set only by a resolver that read the chain from the directory, never
// from request input. A chain that was not read in full (a loop, a parent that vanished, a budget
// that ran out) is Complete false, and an incomplete chain is never admitted.
type ObjectView struct {
	Connection ObjectID
	ID         ObjectID
	// Ancestors are the GUIDs of the parent chain, nearest parent first, up to the naming context head.
	Ancestors []ObjectID
	Complete  bool
}

// Admits reports whether the scope lets its holder read the object: some grant includes it and none
// of that grant's excludes does, and the token layer, when there is one, includes it and does not
// exclude it. It is the same decision Evaluator.AuthorizeRead makes per target and the SQL renderer
// makes per row (reports contract §4.3); the rbac property test holds all three together.
//
// It fails closed at every step. The zero scope admits nothing. An incomplete chain, a zero ID or a
// zero element in the chain admits nothing. An include of an unknown kind, or with a zero root,
// matches nothing; an exclude of an unknown kind, or with a zero root, makes its whole grant admit
// nothing. In the token layer either of those makes the scope admit nothing, because a token only
// ever narrows.
func (s ReadScope) Admits(v ObjectView) bool {
	if s.Empty() || v.ID.IsZero() || v.Connection.IsZero() || !v.Complete || slices.Contains(v.Ancestors, ObjectID{}) {
		return false
	}
	ok := false
	for _, g := range s.grants {
		if layerAdmits(g.Include, g.Exclude, v) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	if s.token == nil {
		return true
	}
	if layerInvalid(s.token.Include, s.token.Exclude) {
		return false
	}
	return layerAdmits(s.token.Include, s.token.Exclude, v)
}

// layerAdmits is "some include matches and no exclude matches", with an unusable exclude excluding
// everything.
func layerAdmits(include, exclude []ScopeTerm, v ObjectView) bool {
	for _, e := range exclude {
		if !termUsable(e) {
			return false
		}
		if termMatches(e, v) {
			return false
		}
	}
	for _, i := range include {
		if termUsable(i) && termMatches(i, v) {
			return true
		}
	}
	return false
}

// layerInvalid reports whether a token layer has a term that cannot be bound anywhere.
func layerInvalid(include, exclude []ScopeTerm) bool {
	return slices.ContainsFunc(include, func(t ScopeTerm) bool { return !termUsable(t) }) ||
		slices.ContainsFunc(exclude, func(t ScopeTerm) bool { return !termUsable(t) })
}

func termUsable(t ScopeTerm) bool {
	if t.Connection.IsZero() || t.Root.IsZero() {
		return false
	}
	switch t.Kind {
	case TermNamingContext, TermSubtree, TermOneLevel:
		return true
	}
	return false
}

// termMatches mirrors Scope.covers and the SQL term renderer. The connection must be the object's.
// A naming-context root and a subtree root both mean "the object or one of its ancestors is the root"
// (the head of a naming context is the last ancestor). A one-level root means the nearest parent is
// the root; a one-level root that is the connection itself reaches nothing, because the connection
// is not a container.
func termMatches(t ScopeTerm, v ObjectView) bool {
	if t.Connection != v.Connection {
		return false
	}
	switch t.Kind {
	case TermNamingContext, TermSubtree:
		return t.Root == v.ID || slices.Contains(v.Ancestors, t.Root)
	case TermOneLevel:
		return t.Root != v.Connection && len(v.Ancestors) > 0 && v.Ancestors[0] == t.Root
	}
	return false
}

// SearchRoot is where a directory query may start for a scope, and how far below it reaches.
type SearchRoot struct {
	Kind TermKind // TermNamingContext and TermSubtree reach the whole subtree, TermOneLevel the children
	Root ObjectID
}

// SearchRoots returns the include roots a directory query in connection conn may be started from, so
// the directory itself never returns objects outside every include. It narrows the query only: a
// caller still decides each result with Admits, because excludes, the token layer and chain
// completeness are not expressible as roots. The list is deduplicated and never contains a root of
// an unusable term. An empty list means the scope reaches nothing in conn and no query may be made.
//
// Grants that cannot admit anything (an unusable exclude) contribute no roots, and neither does a
// scope whose token layer is invalid or whose zero value grants nothing.
func (s ReadScope) SearchRoots(conn ObjectID) []SearchRoot {
	if s.Empty() || conn.IsZero() {
		return nil
	}
	if s.token != nil && layerInvalid(s.token.Include, s.token.Exclude) {
		return nil
	}
	var out []SearchRoot
	for _, g := range s.grants {
		if slices.ContainsFunc(g.Exclude, func(t ScopeTerm) bool { return !termUsable(t) }) {
			continue
		}
		for _, i := range g.Include {
			if !termUsable(i) || i.Connection != conn {
				continue
			}
			if i.Kind == TermOneLevel && i.Root == conn {
				continue
			}
			r := SearchRoot{Kind: i.Kind, Root: i.Root}
			if i.Kind == TermNamingContext {
				r.Kind = TermSubtree // the head of the naming context is the root of its subtree
			}
			if !slices.Contains(out, r) {
				out = append(out, r)
			}
		}
	}
	return out
}
