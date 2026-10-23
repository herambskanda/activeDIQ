package write

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Verdict is the connector's own classification of one object from a live re-read.
type Verdict struct {
	Tier0 bool
	Bases []Basis
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
}

// ADProvider classifies through the AD classifier of T-0093 over an ADDirectory.
type ADProvider struct {
	Dir tier0.ADDirectory
	ID  *connectorv1.DirectoryIdentity
}

var _ Provider = (*ADProvider)(nil)

func (p *ADProvider) Kind() connectorv1.ProviderKind {
	return connectorv1.ProviderKind_PROVIDER_KIND_AD
}

func (p *ADProvider) Identity() *connectorv1.DirectoryIdentity { return p.ID }

// Classify runs the full live classification (it snapshots the directory on every call) and then
// checks the object's token groups against the designated groups.
func (p *ADProvider) Classify(ctx context.Context, id guid.GUID, designated []guid.GUID) (Verdict, error) {
	unknown := Verdict{Tier0: true}
	// C9 (TM-D23 rule 10): a GPO whose cn is not a GUID is tier0 with no further reads.
	ge, err := p.Dir.Get(ctx, dn.GUIDRef(id), []string{"objectClass", "cn"})
	if err != nil {
		return unknown, err
	}
	if gpoCNInvalid(ge) {
		return Verdict{Tier0: true, Bases: []Basis{tier0.C9}}, nil
	}
	// The correlation facts are the request's and were applied at steps 3 to 6; this is the live half.
	r, err := tier0.NewAD(p.Dir).Classify(ctx, dn.GUIDRef(id), tier0.ADInput{CorrelationKnown: true})
	if err != nil {
		return unknown, err
	}
	if r.Unknown {
		return unknown, errors.New("write: classification unknown")
	}
	if r.GUID != id {
		return unknown, errors.New("write: classifier resolved another object")
	}
	v := Verdict{Tier0: r.Tier0, Bases: r.Bases}
	if len(designated) == 0 {
		return v, nil
	}
	e, err := p.Dir.Get(ctx, dn.GUIDRef(id), []string{"tokenGroups"})
	if err != nil {
		return unknown, err
	}
	tokens, err := e.SIDs("tokenGroups")
	if err != nil {
		return unknown, err
	}
	have := map[string]bool{}
	for _, s := range tokens {
		have[s.String()] = true
	}
	for _, d := range designated {
		ge, err := p.Dir.Get(ctx, dn.GUIDRef(d), []string{"objectSid"})
		if err != nil {
			if ad.CodeOf(err) == ad.CodeObjectNotFound {
				continue // designates nothing that exists
			}
			return unknown, err
		}
		sids, err := ge.SIDs("objectSid")
		if err != nil {
			return unknown, err
		}
		for _, s := range sids {
			if have[s.String()] {
				v.Tier0 = true
				v.Bases = append(v.Bases, tier0.Designated)
			}
		}
	}
	return v, nil
}

// gpoCNInvalid is true for a groupPolicyContainer whose cn does not parse as a GUID (CC-WRITE-20 g).
func gpoCNInvalid(e *ad.Entry) bool {
	isGPO := false
	for _, c := range e.Strings("objectClass") {
		if strings.EqualFold(c, "groupPolicyContainer") {
			isGPO = true
		}
	}
	if !isGPO {
		return false
	}
	cn := e.Strings("cn")
	if len(cn) != 1 {
		return true
	}
	_, err := guid.Parse(cn[0])
	return err != nil
}

func (p *ADProvider) Anchors(ctx context.Context, id guid.GUID) (Anchors, error) {
	e, err := p.Dir.Get(ctx, dn.GUIDRef(id), []string{"objectGUID", "ms-DS-ConsistencyGuid", "objectSid"})
	if err != nil {
		return Anchors{}, err
	}
	var a Anchors
	a.Source = append(a.Source, e.Raw("objectGUID")...)
	a.Source = append(a.Source, e.Raw("ms-DS-ConsistencyGuid")...)
	for _, raw := range e.Raw("objectGUID") { // RFC 4122 order as well: both name the same object
		if g, err := guid.FromBytes(raw); err == nil {
			a.Source = append(a.Source, toWire(g).GetValue())
		}
	}
	a.SIDs = e.Raw("objectSid")
	return a, nil
}

// AnchorReader reads an Entra object's sync anchors (onPremisesImmutableId, base64-decoded, and
// onPremisesSecurityIdentifier, binary).
type AnchorReader interface {
	EntraAnchors(ctx context.Context, id guid.GUID) (Anchors, error)
}

// ErrNoAnchors is returned when the provider cannot read the identifiers F4 needs; the guard then
// refuses (fail closed).
var ErrNoAnchors = errors.New("write: sync anchors cannot be read")

// EntraReader is the Graph read surface the Entra provider needs.
type EntraReader interface {
	tier0.Reader
}

// EntraProvider classifies through the Entra classifier of T-0095.
type EntraProvider struct {
	Reader   EntraReader
	TenantID string
	// AnchorReader may be nil: statements with evidence are then refused (ErrNoAnchors).
	Anchor AnchorReader
}

var _ Provider = (*EntraProvider)(nil)

func (p *EntraProvider) Kind() connectorv1.ProviderKind {
	return connectorv1.ProviderKind_PROVIDER_KIND_ENTRA
}

func (p *EntraProvider) Identity() *connectorv1.DirectoryIdentity {
	return &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: p.TenantID}}
}

// Classify snapshots E1 to E4 live. Membership of a designated group is checked against the
// group's direct members; nested membership of a designated group is not recomputed live (it is
// part of the request's context and of the connector's set).
func (p *EntraProvider) Classify(ctx context.Context, id guid.GUID, designated []guid.GUID) (Verdict, error) {
	unknown := Verdict{Tier0: true}
	r, err := tier0.New(p.Reader).Classify(ctx, id.String(), tier0.Input{CorrelationKnown: true})
	if err != nil {
		return unknown, err
	}
	v := Verdict{Tier0: r.Tier0, Bases: r.Bases}
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

func (p *EntraProvider) Anchors(ctx context.Context, id guid.GUID) (Anchors, error) {
	if p.Anchor == nil {
		return Anchors{}, ErrNoAnchors
	}
	return p.Anchor.EntraAnchors(ctx, id)
}

// matches reports whether evidence names the object whose live anchors are a (F4).
func (a Anchors) matches(ev *connectorv1.CorrelationEvidence) bool {
	switch x := ev.GetEvidence().(type) {
	case *connectorv1.CorrelationEvidence_SourceAnchor:
		for _, s := range a.Source {
			if len(x.SourceAnchor) > 0 && bytes.Equal(s, x.SourceAnchor) {
				return true
			}
		}
	case *connectorv1.CorrelationEvidence_SecurityIdentifier:
		for _, s := range a.SIDs {
			if len(x.SecurityIdentifier.GetValue()) > 0 && bytes.Equal(s, x.SecurityIdentifier.GetValue()) {
				return true
			}
		}
	}
	return false
}
