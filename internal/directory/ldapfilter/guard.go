package ldapfilter

import (
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// Caller answers the one question the parsers cannot: may the person behind this filter read the
// object a DN-valued assertion names? Without it `(memberOf=CN=Restricted,…)` would let an
// admin tell an empty group from one they may not see (safe-primitives §3.3, LF-36). The check is
// by the caller's own rights, never the service account's. An error is "could not find out" and
// fails the parse; so does a nil Caller, for any filter that names a DN.
type Caller interface {
	CanReadObject(d dn.DN) (bool, error)
}

// Limits tighten the §3.3 rule 9 bounds for one parse. A zero field, or one above the package
// bound, means the package bound: callers can narrow the limits, never widen them.
type Limits struct {
	MaxFilterBytes int // input text (ParseAdminFilter) or its JSON form (ParseFilterASTJSON)
	MaxDepth       int
	MaxNodes       int
	MaxFanOut      int
	MaxValueBytes  int
}

func clampLimit(v, max int) int {
	if v <= 0 || v > max {
		return max
	}
	return v
}

func (l Limits) effective() Limits {
	return Limits{
		MaxFilterBytes: clampLimit(l.MaxFilterBytes, MaxFilterBytes),
		MaxDepth:       clampLimit(l.MaxDepth, MaxDepth),
		MaxNodes:       clampLimit(l.MaxNodes, MaxNodes),
		MaxFanOut:      clampLimit(l.MaxFanOut, MaxFanOut),
		MaxValueBytes:  clampLimit(l.MaxValueBytes, MaxValueBytes),
	}
}

// guard is the state both parsers share: limits, node count, schema and caller.
type guard struct {
	lim    Limits
	nodes  int
	sc     *Schema
	caller Caller
}

func newGuard(sc *Schema, caller Caller, lim Limits) *guard {
	return &guard{lim: lim.effective(), sc: sc, caller: caller}
}

// enter accounts for one node at the given depth (the root is 1) before anything is built under it,
// so hostile nesting is refused at depth+1 and the recursion is bounded by MaxDepth.
func (g *guard) enter(depth int) error {
	if depth > g.lim.MaxDepth {
		return fail(TooDeep)
	}
	if g.nodes++; g.nodes > g.lim.MaxNodes {
		return fail(TooManyNodes)
	}
	return nil
}

func isStaticSecret(name string) bool {
	for _, s := range secretattr.Static() {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

// attr resolves a name from untrusted input. Secrets are refused by name before the schema is
// consulted, so the answer does not depend on what the schema happens to contain (LF-22, LF-34).
func (g *guard) attr(name string) (AttrName, AttrInfo, error) {
	n, err := parseAttrGrammar(name)
	if err != nil {
		return AttrName{}, AttrInfo{}, err
	}
	if isStaticSecret(n.name) {
		return AttrName{}, AttrInfo{}, fail(ForbiddenAttribute)
	}
	n, err = ParseAttrName(name, g.sc)
	if err != nil {
		return AttrName{}, AttrInfo{}, err
	}
	info, _ := g.sc.lookup(n.name)
	switch {
	case info.Secret:
		return AttrName{}, AttrInfo{}, fail(ForbiddenAttribute)
	case info.Constructed:
		return AttrName{}, AttrInfo{}, fail(ConstructedNotFilterable)
	}
	return n, info, nil
}

// readable returns d once the caller is known to be able to read the object it names.
func (g *guard) readable(d dn.DN) (dn.DN, error) {
	if g.caller == nil {
		return dn.DN{}, fail(ReferencedObjectNotReadable)
	}
	ok, err := g.caller.CanReadObject(d)
	switch {
	case err != nil:
		return dn.DN{}, fail(ReferenceCheckFailed)
	case !ok:
		return dn.DN{}, fail(ReferencedObjectNotReadable)
	}
	return d, nil
}

// finish validates the whole tree once more through Render, the same gate every filter passes, so
// a Filter returned by a parser has rendered against this schema.
func (g *guard) finish(f Filter) (Filter, error) {
	if _, err := Render(f, g.sc); err != nil {
		return nil, err
	}
	return f, nil
}
