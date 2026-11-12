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

// DCBinder is what an AD provider needs for rule 5: the identity of the DC its binding uses, read
// live on that binding. An AD provider that is not a DCBinder refuses every write.
type DCBinder interface {
	BoundDC(ctx context.Context) (*connectorv1.DcIdentity, error)
}

// SessionDC reads the bound DC from an *ad.Session.
type SessionDC struct{ S *ad.Session }

func (d SessionDC) BoundDC(ctx context.Context) (*connectorv1.DcIdentity, error) {
	id, err := d.S.DCIdentity(ctx)
	if err != nil {
		return nil, err
	}
	return &connectorv1.DcIdentity{DsaGuid: toWire(id.DSAGUID), InvocationId: toWire(id.InvocationID), DnsHostname: id.DNSHostName, Site: id.Site}, nil
}

// NewADProvider is the production constructor. Dir, Bound (and, through the caller, the write ops)
// are all built over the one sess, so the DC whose identity rule 5 checks is the DC the reads and
// writes reach. A binder on another session would re-open the TOCTOU rule 5 closes.
func NewADProvider(sess *ad.Session, gc *ad.GCResolver, id *connectorv1.DirectoryIdentity, pins PinStore) *ADProvider {
	p := &ADProvider{
		Dir:   tier0.SessionDirectory{S: sess, GC: gc},
		ID:    id,
		Pins:  pins,
		Bound: SessionDC{S: sess},
	}
	if sess != nil {
		p.Accounts = sess
		p.Writes = sess
	}
	return p
}

// WriteDirectory is the session the object kinds write through (nil: those kinds answer unsupported).
func (p *ADProvider) WriteDirectory() ObjectDirectory { return p.Writes }

// sameSession is false when Dir and Bound are both session-backed but over different sessions.
// Anything else (a test double on either side) is not a session mismatch.
func (p *ADProvider) sameSession() bool {
	var ds *ad.Session
	switch d := p.Dir.(type) {
	case tier0.SessionDirectory:
		ds = d.S
	case *tier0.SessionDirectory:
		if d != nil {
			ds = d.S
		}
	}
	var bs *ad.Session
	switch b := p.Bound.(type) {
	case SessionDC:
		bs = b.S
	case *SessionDC:
		if b != nil {
			bs = b.S
		}
	}
	return ds == nil || bs == nil || ds == bs
}

// OverSession is true only when the provider's directory and its bound-DC binder are both
// session-backed and both over s. A test double on either side is false: a caller that needs the
// reads, the classification and the DC identity to come from one DC (the Read pin) must not accept
// anything it cannot prove.
func (p *ADProvider) OverSession(s *ad.Session) bool {
	if p == nil || s == nil {
		return false
	}
	var ds, bs *ad.Session
	switch d := p.Dir.(type) {
	case tier0.SessionDirectory:
		ds = d.S
	case *tier0.SessionDirectory:
		if d != nil {
			ds = d.S
		}
	}
	switch b := p.Bound.(type) {
	case SessionDC:
		bs = b.S
	case *SessionDC:
		if b != nil {
			bs = b.S
		}
	}
	return ds == s && bs == s
}

// ADProvider classifies through the AD classifier of T-0093 over an ADDirectory.
type ADProvider struct {
	Dir tier0.ADDirectory
	ID  *connectorv1.DirectoryIdentity
	// Pins is the server-side store of the C13 group GUIDs pinned at first discovery (TM-D26 rule 10).
	// It is required: with none, every Classify fails closed, because a renamed DnsAdmins or Exchange
	// group would otherwise stop being tier0.
	Pins PinStore
	// classify is the base classifier; nil means the T-0093 classifier over Dir. Tests substitute it.
	// in is the ADInput the production path builds (see classifierInput): pins and designations.
	classify func(ctx context.Context, id guid.GUID, in tier0.ADInput) (tier0.ADResult, error)
	// Dynamic is the Entra snapshot whose designated closure the AD plane's property writes are
	// checked against (the synced AD user is matched by rules on the Entra side, TM-D25 7f). Nil
	// refuses every property write.
	Dynamic PropertyGuard
	// Bound reports the DC the connector is bound to (rule 5). Nil refuses every write.
	Bound DCBinder
	// Writes runs the object writes (kinds 1 to 3). It must be over the same session as Dir and Bound.
	Writes ObjectDirectory
	// Accounts is the session the account kinds (T-1583) read and write on: the same session as Dir and
	// Bound, so the DC whose identity rule 5 checks is the DC the write reaches. Nil: those kinds answer
	// CAPABILITY_UNSUPPORTED.
	Accounts AccountSession
}

var _ Provider = (*ADProvider)(nil)

// PinStore persists the C13 group pins server-side, per connection. Pins only ever grow: a group
// that was once a default-privileged group stays one whatever it is renamed to. Implementations
// are durable (a pin held only in memory is lost on restart, which re-opens the rename hole).
type PinStore interface {
	// PinnedC13 returns every pinned GUID. An error is an unknown answer.
	PinnedC13(ctx context.Context) ([]guid.GUID, error)
	// PinC13 adds GUIDs to the pins (idempotent) and returns only once they are durable.
	PinC13(ctx context.Context, groups []guid.GUID) error
}

// ErrNoPins is returned when the provider has no pin store; the guard counts it as tier0.
var ErrNoPins = errors.New("write: C13 pin store not configured")

func (p *ADProvider) Kind() connectorv1.ProviderKind {
	return connectorv1.ProviderKind_PROVIDER_KIND_AD
}

// BoundDC implements DCBinder; with no Bound configured it fails closed.
func (p *ADProvider) BoundDC(ctx context.Context) (*connectorv1.DcIdentity, error) {
	if p.Bound == nil {
		return nil, ErrNoBoundDC
	}
	if !p.sameSession() {
		return nil, ErrNoBoundDC // binder and directory on different sessions: not the DC the writes reach
	}
	return p.Bound.BoundDC(ctx)
}

// ErrNoBoundDC is returned when the provider cannot say which DC it is bound to.
var ErrNoBoundDC = errors.New("write: bound DC identity not available")

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
	// The pins ride on every Classify (TM-D26 rule 10); a store that cannot answer fails closed.
	if p.Pins == nil {
		return unknown, ErrNoPins
	}
	pins, err := p.Pins.PinnedC13(ctx)
	if err != nil {
		return unknown, err
	}
	// The correlation facts are the request's and were applied at steps 3 to 6; this is the live half.
	base := p.classify
	if base == nil {
		base = func(ctx context.Context, id guid.GUID, in tier0.ADInput) (tier0.ADResult, error) {
			return tier0.NewAD(p.Dir).Classify(ctx, dn.GUIDRef(id), in)
		}
	}
	r, err := base(ctx, id, classifierInput(pins, designated))
	if err != nil {
		return unknown, err
	}
	// Pin what this snapshot found before answering, so a rename after this call cannot lose it.
	if len(r.C13Groups) > 0 {
		if err := p.Pins.PinC13(ctx, r.C13Groups); err != nil {
			return unknown, err
		}
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

// classifierInput is what the live classifier is given: the pinned C13 groups (TM-D26 rule 10) and the
// customer designations, so C18 closes over them (a sIDHistory value naming a designated object makes
// its holder tier0 even though tokenGroups does not carry the holder's own sIDHistory).
func classifierInput(pins, designated []guid.GUID) tier0.ADInput {
	in := tier0.ADInput{CorrelationKnown: true, PinnedC13: pins}
	for _, d := range designated {
		in.Designated = append(in.Designated, dn.GUIDRef(d))
	}
	return in
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
	// Dynamic is the snapshot of the designated closure. Nil refuses every property write.
	Dynamic PropertyGuard
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

// PropertyGuard returns the snapshot, or the refuse-everything guard when there is none.
func (p *EntraProvider) PropertyGuard(context.Context) (PropertyGuard, error) {
	return guardOrRefuse(p.Dynamic), nil
}

// PropertyGuard returns the snapshot, or the refuse-everything guard when there is none.
func (p *ADProvider) PropertyGuard(context.Context) (PropertyGuard, error) {
	return guardOrRefuse(p.Dynamic), nil
}

func guardOrRefuse(g PropertyGuard) PropertyGuard {
	if g == nil {
		return (*tier0.Set)(nil)
	}
	return g
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
