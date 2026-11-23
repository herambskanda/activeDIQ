// Package entra is the Entra provider of EP-11 (blueprint §4.3): the Tier-0 classifier of
// threat-model E1 to E5 over the read-only Graph client. It implements the core only; an Entra
// directory has no DCs, so it is not DCBound. The RightsSource facet arrives with T-0615, the
// object-reading facets with their specs. Only composition roots and conformance import this
// package (M13a).
package entra

import (
	"context"

	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/provider"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// AnchorReader reads an Entra object's sync anchors (onPremisesImmutableId, base64-decoded, and
// onPremisesSecurityIdentifier, binary).
type AnchorReader interface {
	EntraAnchors(ctx context.Context, id guid.GUID) (provider.Anchors, error)
}

// EntraReader is the Graph read surface the Entra provider needs.
type EntraReader interface {
	tier0.Reader
}

// EntraProvider classifies through the Entra classifier of T-0095.
type EntraProvider struct {
	Reader   EntraReader
	TenantID string
	// AnchorReader may be nil: statements with evidence are then refused (provider.ErrNoAnchors).
	Anchor AnchorReader
	// Dynamic is the snapshot of the designated closure. Nil refuses every property write.
	Dynamic provider.PropertyGuard
}

var _ provider.Provider = (*EntraProvider)(nil)

func (p *EntraProvider) Kind() connectorv1.ProviderKind {
	return connectorv1.ProviderKind_PROVIDER_KIND_ENTRA
}

func (p *EntraProvider) Identity() *connectorv1.DirectoryIdentity {
	return &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: p.TenantID}}
}

// Classify snapshots E1 to E4 live. Membership of a designated group is checked against the
// group's direct members; nested membership of a designated group is not recomputed live (it is
// part of the request's context and of the connector's set).
func (p *EntraProvider) Classify(ctx context.Context, id guid.GUID, designated []guid.GUID) (provider.Verdict, error) {
	unknown := provider.Verdict{Tier0: true}
	r, err := tier0.New(p.Reader).Classify(ctx, id.String(), tier0.Input{CorrelationKnown: true})
	if err != nil {
		return unknown, err
	}
	v := provider.Verdict{Tier0: r.Tier0, Bases: r.Bases}
	for _, d := range designated {
		members, err := p.Reader.GroupMembers(ctx, d)
		if err != nil {
			if graph.CodeOf(err) == graph.CodeNotFound {
				continue
			}
			return unknown, err
		}
		for _, m := range members {
			if mg, err := guid.Parse(m.ID); err == nil && mg == id {
				v.Tier0 = true
				v.Bases = append(v.Bases, tier0.Designated)
			}
		}
	}
	return v, nil
}

// PropertyGuard returns the snapshot, or the refuse-everything guard when there is none.
func (p *EntraProvider) PropertyGuard(context.Context) (provider.PropertyGuard, error) {
	return provider.GuardOrRefuse(p.Dynamic), nil
}

func (p *EntraProvider) Anchors(ctx context.Context, id guid.GUID) (provider.Anchors, error) {
	if p.Anchor == nil {
		return provider.Anchors{}, provider.ErrNoAnchors
	}
	return p.Anchor.EntraAnchors(ctx, id)
}
