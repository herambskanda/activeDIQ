// Package authority is the leaf of the identity vocabulary the operation pipeline shares (ADR-0005
// rule 13): who is acting (Principal, Chain), what they act on (TargetRef) and the live facts an
// authorisation decision reads about it (FactsQuery, Facts). It imports only tenant-free standard
// library code, so the step token (operation/step) and the LiveFacts port can name these types
// without importing authz or operation.
package authority

import "errors"

// PrincipalKind says what kind of subject a Principal is.
type PrincipalKind string

// Principal kinds. Only a Human can approve an operation (ADR-0005 rule 8).
const (
	Human      PrincipalKind = "human"
	APIToken   PrincipalKind = "api_token"
	Automation PrincipalKind = "automation"
	System     PrincipalKind = "system"
)

// PrincipalID is the pseudonymous, stable identifier of a principal. It is never a name or an
// address, so it can be logged and chained.
type PrincipalID string

// Principal is one subject in an initiator chain.
type Principal struct {
	ID   PrincipalID
	Kind PrincipalKind
}

// Chain is the initiator chain of an operation: the requester (the real human behind a delegated
// account) and, innermost last, the API token or automation policy that acted for them. Authorisation
// always evaluates this chain, never an approver (ADR-0005 rule 7).
type Chain struct {
	Requester Principal
	Via       []Principal
}

// ErrInvalidChain is returned by Validate for a chain with no requester.
var ErrInvalidChain = errors.New("authority: chain has no requester")

// Validate reports whether the chain names a requester.
func (c Chain) Validate() error {
	if c.Requester.ID == "" || c.Requester.Kind == "" {
		return ErrInvalidChain
	}
	return nil
}

// Contains reports whether id is the requester or any principal the requester acted through.
func (c Chain) Contains(id PrincipalID) bool {
	if id == "" {
		return false
	}
	if c.Requester.ID == id {
		return true
	}
	for _, p := range c.Via {
		if p.ID == id {
			return true
		}
	}
	return false
}

// NamingContextID names one directory partition the operation reads or writes (a domain naming
// context, or the single Entra tenant of a connection).
type NamingContextID string

// Pins maps each naming context the operation touches to the one DC host pinned for it (rule 5).
type Pins map[NamingContextID]string

// TargetRef names the object a step acts on. Directory objects are keyed by objectGUID, never by DN
// (domain-model X3). A target "to be created" carries the planned parent GUID and RDN instead of a GUID.
type TargetRef struct {
	Connection string // connection ID; empty for activeDIQ's own store
	GUID       string // objectGUID (or the store row key)
	Class      string // object class, for example "user"
	Parent     string // planned parent GUID, only for a create
	RDN        string // planned RDN, only for a create
}

// Membership is the answer to "is the target in this root": fail-closed by design.
type Membership string

// Membership answers. Unknown covers a read error, a timeout, a partial batch and a hidden-membership
// root; it refuses the target whether the root is an include or an exclude (ADR-0005 rule 7).
const (
	Member    Membership = "member"
	NotMember Membership = "not_member"
	Unknown   Membership = "unknown"
)

// Root names one scope root a decision may depend on.
type Root struct {
	Kind string // DM-35 root_kind
	ID   string // OU GUID, group GUID, AU ID, ...
}

// FactsQuery names what the Apply-time re-check must read live about one target: the roots of every
// include and exclude entry that could decide it, plus the Tier-0 fact.
type FactsQuery struct {
	Target TargetRef
	Roots  []Root
	Tier0  bool
}

// Facts is what a live read returned for a FactsQuery.
type Facts struct {
	Exists bool
	Tier0  bool
	Roots  map[Root]Membership
}

// Of returns the membership answer for r, Unknown when the read did not cover it.
func (f Facts) Of(r Root) Membership {
	if m, ok := f.Roots[r]; ok && (m == Member || m == NotMember) {
		return m
	}
	return Unknown
}
