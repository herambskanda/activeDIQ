package authz

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"slices"
)

// TermKind says how a ScopeTerm's root reaches rows. The zero value, and every value this package
// does not define, is unknown: a consumer must render an unknown include as matching nothing and
// refuse a grant that carries an unknown exclude (fail closed).
type TermKind uint8

// Term kinds of Milestone 2a (reports spec §8.1). The zero value is deliberately not a kind.
const (
	// TermNamingContext matches every object of the naming context whose head is Root.
	TermNamingContext TermKind = iota + 1
	// TermSubtree matches Root and every object below it.
	TermSubtree
	// TermOneLevel matches the direct children of Root, not Root itself.
	TermOneLevel
)

// String returns the root-kind name the term kind stands for ("unknown" for any other value).
func (k TermKind) String() string {
	switch k {
	case TermNamingContext:
		return "naming_context"
	case TermSubtree:
		return "ou_subtree"
	case TermOneLevel:
		return "ou_one_level"
	}
	return "unknown"
}

// ScopeTerm is one directory region: a root object in one connection and how far it reaches. A term
// with a zero Connection or a zero Root is invalid and grants nothing; in an exclude it makes the
// whole grant grant nothing, so an exclude that could not be bound never widens a scope.
type ScopeTerm struct {
	Kind       TermKind
	Connection ObjectID
	Root       ObjectID
}

// ScopeGrant is the read reach of one assignment: the union of Include, minus the union of Exclude.
type ScopeGrant struct{ Include, Exclude []ScopeTerm }

// TokenLayer is an API token's narrowing (DM-32 scope_narrowing). It is AND-ed with the union of the
// account's grants, never merged into them: "(A ∪ B) ∩ T" is not a union of grants. It mirrors
// Evaluator.Authorize, which checks Token.Scope separately from the assignments.
type TokenLayer struct{ Include, Exclude []ScopeTerm }

// ScopeReason is a stable, machine-readable, log-safe note on why a scope is narrower than the
// account's assignments suggest, for example "scope_kind_unsupported:group_members".
type ScopeReason string

// ReadScope is the directory read reach of one principal for one permission: the input of every
// consumer that filters directory rows in a query (reports, later search).
//
// It has no exported fields and the zero value grants nothing, so the only non-empty scope a caller
// can hold is one produced by NewReadScope, which only the rbac producer calls (RP2). Methods return
// copies, so a holder cannot widen a scope it received.
type ReadScope struct {
	grants  []ScopeGrant
	token   *TokenLayer
	reasons []ScopeReason
	summary string
}

// NewReadScope builds a ReadScope. It is for the rbac producer (and authztest) only; no other
// package may call it (RP2, enforced by fitness-reports RP2). A nil token adds no
// narrowing layer; a non-nil token with an empty Include narrows to nothing.
func NewReadScope(grants []ScopeGrant, token *TokenLayer, reasons []ScopeReason, summary string) ReadScope {
	s := ReadScope{
		grants:  cloneGrants(grants),
		reasons: slices.Clone(reasons),
		summary: summary,
	}
	if token != nil {
		t := cloneLayer(*token)
		s.token = &t
	}
	return s
}

// Empty reports whether the scope grants nothing: it has no grants, or its token layer has no
// include. A consumer renders an empty scope as FALSE; there is no "empty means everything" path.
func (s ReadScope) Empty() bool {
	return len(s.grants) == 0 || (s.token != nil && len(s.token.Include) == 0)
}

// Terms returns the account's grants, one per assignment. Callers: reportsql and authz only (RP2).
func (s ReadScope) Terms() []ScopeGrant { return cloneGrants(s.grants) }

// Token returns the token layer and true, or false when the token adds no narrowing (a session, or
// a token without a Scope). Callers: reportsql and authz only (RP2).
func (s ReadScope) Token() (TokenLayer, bool) {
	if s.token == nil {
		return TokenLayer{}, false
	}
	return cloneLayer(*s.token), true
}

// Reasons returns why the scope is narrower than the assignments suggest.
func (s ReadScope) Reasons() []ScopeReason { return slices.Clone(s.reasons) }

// Summary is the human text for a report run's scope_applied.
func (s ReadScope) Summary() string { return s.summary }

// Fingerprint is the SHA-256 of the canonical form of the grants and the token layer, the key for
// run reuse and run reads. Grants are sorted, terms are sorted by (kind, connection, root) within
// each list, and the token layer follows the grants after a presence byte. Reasons and the summary
// are not part of it. Two scopes that grant the same rows by different routes may differ; that
// costs a re-run, never a leak.
func (s ReadScope) Fingerprint() [32]byte {
	h := sha256.New()
	h.Write([]byte("activediq/readscope/v1\x00"))
	enc := make([][]byte, 0, len(s.grants))
	for _, g := range s.grants {
		enc = append(enc, canonLayer(g.Include, g.Exclude))
	}
	slices.SortFunc(enc, bytes.Compare)
	putUint32(h, uint32(len(enc)))
	for _, e := range enc {
		h.Write(e)
	}
	if s.token == nil {
		h.Write([]byte{0})
	} else {
		h.Write([]byte{1})
		h.Write(canonLayer(s.token.Include, s.token.Exclude))
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func putUint32(w io.Writer, n uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	_, _ = w.Write(b[:])
}

// canonLayer is the length-prefixed encoding of an include list and an exclude list, each sorted.
func canonLayer(include, exclude []ScopeTerm) []byte {
	var b bytes.Buffer
	for _, list := range [][]ScopeTerm{include, exclude} {
		terms := slices.Clone(list)
		slices.SortFunc(terms, compareTerms)
		putUint32(&b, uint32(len(terms)))
		for _, t := range terms {
			b.WriteByte(byte(t.Kind))
			b.Write(t.Connection[:])
			b.Write(t.Root[:])
		}
	}
	return b.Bytes()
}

func compareTerms(a, b ScopeTerm) int {
	if a.Kind != b.Kind {
		if a.Kind < b.Kind {
			return -1
		}
		return 1
	}
	if c := bytes.Compare(a.Connection[:], b.Connection[:]); c != 0 {
		return c
	}
	return bytes.Compare(a.Root[:], b.Root[:])
}

func cloneGrants(in []ScopeGrant) []ScopeGrant {
	if in == nil {
		return nil
	}
	out := make([]ScopeGrant, len(in))
	for i, g := range in {
		out[i] = ScopeGrant{Include: slices.Clone(g.Include), Exclude: slices.Clone(g.Exclude)}
	}
	return out
}

func cloneLayer(l TokenLayer) TokenLayer {
	return TokenLayer{Include: slices.Clone(l.Include), Exclude: slices.Clone(l.Exclude)}
}

// ScopeEvaluator is the EP-6 extension point that turns an assignment root of one kind into the
// ScopeTerm the read-scope consumers filter by. A module registers one per root kind through
// module.Registrar.ScopeEvaluator; Boot refuses a second evaluator for the same kind.
type ScopeEvaluator interface {
	// RootKind is the assignment root kind this evaluator owns, for example "ou_subtree".
	RootKind() string
	// Term returns the term for a root of this kind in a connection. A zero connection or root is
	// ErrInvalidObjectID: the caller fails closed and never builds a term from it.
	Term(connection, root ObjectID) (ScopeTerm, error)
}
