// Package provider is EP-11, the directory-provider extension point (blueprint §4.3). A provider is
// the per-binding adapter between the connector's handlers and one directory: it wires live reads
// into the Tier-0 classifiers and holds no policy of its own. The core interface Provider is what
// the write guard needs from any directory; the facets (DCBound, ObjectReader, Searcher,
// RightsSource) are one interface per contract group, and a handler asserts the facet it needs at
// construction. Capabilities are derived from the facets by Supports, never declared.
//
// This package imports no handler and no variant: provider/ad and provider/entra implement it, and
// only the composition roots import them (M13a).
package provider

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Basis is a row of threat-model §6.4.
type Basis = connectorv1.Tier0Basis

// Verdict is the connector's own classification of one object from a live re-read.
type Verdict struct {
	Tier0 bool
	Bases []Basis
	// Regrants are the groups a restore re-grants, by group: the retained memberOf values and the
	// primary group (contract §8.10.3 kind 6 step 4, §8.10.9 R2). Set only on a clean restore verdict.
	Regrants []Regrant
}

// Regrant is one group membership a restore brings back.
type Regrant struct {
	Group guid.GUID
	DN    string // the group's DN as the DC sent it; display only
}

// Anchors are the identifiers of an object as re-read live, against which a correlation
// statement's evidence is checked (contract §8.3 F4).
type Anchors struct {
	// Source are byte strings a CorrelationEvidence.source_anchor may equal: AD objectGUID (both
	// byte orders) and ms-DS-ConsistencyGuid; Entra onPremisesImmutableId, decoded.
	Source [][]byte
	// SIDs are the binary SIDs a CorrelationEvidence.security_identifier may equal: AD objectSid,
	// Entra onPremisesSecurityIdentifier.
	SIDs [][]byte
}

// Provider is what the guard needs from a directory: who it is, and live answers about objects.
// Every method re-reads on each call and never serves a cached answer; an error is an unknown
// answer, which the guard counts as tier0.
type Provider interface {
	Kind() connectorv1.ProviderKind
	// Identity is the directory identity this connector is bound to (the DM-13.I2 binding).
	Identity() *connectorv1.DirectoryIdentity
	// Classify re-reads the object's live facts (the bases marked live in §8.1) and the object's
	// membership in any of the designated groups, and returns the bases found.
	Classify(ctx context.Context, id guid.GUID, designated []guid.GUID) (Verdict, error)
	// Anchors re-reads the identifiers F4 compares evidence with.
	Anchors(ctx context.Context, id guid.GUID) (Anchors, error)
	// PropertyGuard returns the dynamic-group property guard for this connection (contract §8.9). It
	// is never nil: a provider with no snapshot returns a guard that refuses every write.
	PropertyGuard(ctx context.Context) (PropertyGuard, error)
}

// PropertyGuard is the §8.9 check. *tier0.Set implements it; a nil *tier0.Set refuses every write,
// which is the fail-closed answer when no snapshot of the closure exists.
type PropertyGuard interface {
	CheckPropertyWrite(ctx context.Context, w tier0.PropertyWrite) (tier0.DynamicRuleRefusal, error)
}

var _ PropertyGuard = (*tier0.Set)(nil)

// GuardOrRefuse is g, or the refuse-everything guard when g is nil.
func GuardOrRefuse(g PropertyGuard) PropertyGuard {
	if g == nil {
		return (*tier0.Set)(nil)
	}
	return g
}

// PinStore persists the C13 group pins server-side, per connection. Pins only ever grow: a group
// that was once a default-privileged group stays one whatever it is renamed to. Implementations
// are durable (a pin held only in memory is lost on restart, which re-opens the rename hole).
type PinStore interface {
	// PinnedC13 returns every pinned GUID. An error is an unknown answer.
	PinnedC13(ctx context.Context) ([]guid.GUID, error)
	// PinC13 adds GUIDs to the pins (idempotent) and returns only once they are durable.
	PinC13(ctx context.Context, groups []guid.GUID) error
}

var (
	// ErrNoPins is returned when the provider has no pin store; the guard counts it as tier0.
	ErrNoPins = errors.New("provider: C13 pin store not configured")
	// ErrNoBoundDC is returned when the provider cannot say which DC it is bound to.
	ErrNoBoundDC = errors.New("provider: bound DC identity not available")
	// ErrPerDCUnavailable is returned by a PerDCReader that is not configured to open per-DC
	// sessions; the read group answers it with CAPABILITY_UNSUPPORTED.
	ErrPerDCUnavailable = errors.New("provider: per-DC reads not configured")
	// ErrNoAnchors is returned when the provider cannot read the identifiers F4 needs; the guard then
	// refuses (fail closed).
	ErrNoAnchors = errors.New("provider: sync anchors cannot be read")
)

// ErrKindFacets is returned by Plane for a provider whose kind and facets disagree.
var ErrKindFacets = errors.New("provider: kind and facets disagree")

// Plane is the single answer to "which Tier-0 plane does this provider write on". The pairing is a
// construction-time invariant: PROVIDER_KIND_AD must implement DCBound (a provider with DCs pins,
// ADR-0005 rule 5); any other known kind must not; UNSPECIFIED and unknown kinds are refused. A
// wrapper that hides the facet therefore fails here rather than silently dropping the DC pin.
func Plane(p Provider) (tier0.Plane, error) {
	if p == nil {
		return 0, errors.New("provider: nil provider")
	}
	_, hasDC := p.(DCBound)
	switch p.Kind() {
	case connectorv1.ProviderKind_PROVIDER_KIND_AD:
		if !hasDC {
			return 0, ErrKindFacets
		}
		return tier0.PlaneAD, nil
	case connectorv1.ProviderKind_PROVIDER_KIND_ENTRA:
		if hasDC {
			return 0, ErrKindFacets
		}
		return tier0.PlaneEntra, nil
	}
	return 0, ErrKindFacets
}
