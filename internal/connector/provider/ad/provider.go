// Package ad is the AD provider of EP-11 (blueprint §4.3): the classifier over one *ad.Session
// with its C13 pins, plus every facet (DCBound, ObjectReader, Searcher, RightsSource) built from that
// same session. One constructor, NewADProvider, builds all of them, which holds the rule 5 / Read-pin
// invariant: the DC whose identity a call is pinned to is the DC the reads, the classification and
// the writes reach. Only composition roots and conformance import this package (M13a).
package ad

import (
	"context"
	"errors"
	"strings"

	adconn "github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/provider"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// SessionDC reads the bound DC from an *adconn.Session.
type SessionDC struct{ S *adconn.Session }

func (d SessionDC) BoundDC(ctx context.Context) (*connectorv1.DcIdentity, error) {
	id, err := d.S.DCIdentity(ctx)
	if err != nil {
		return nil, err
	}
	return &connectorv1.DcIdentity{DsaGuid: provider.GUIDToWire(id.DSAGUID), InvocationId: provider.GUIDToWire(id.InvocationID), DnsHostname: id.DNSHostName, Site: id.Site}, nil
}

// NewADProvider is the production constructor. Dir, Bound and every facet (the object reader, the
// searcher, the rights directory; and, through the caller, the write ops) are all built over the one
// sess, so the DC whose identity rule 5 checks is the DC the reads and
// writes reach. A binder on another session would re-open the TOCTOU rule 5 closes.
func NewADProvider(sess *adconn.Session, gc *adconn.GCResolver, id *connectorv1.DirectoryIdentity, pins provider.PinStore) *ADProvider {
	p := &ADProvider{
		Dir:   tier0.SessionDirectory{S: sess, GC: gc},
		ID:    id,
		Pins:  pins,
		Bound: SessionDC{S: sess},
		sess:  sess,
	}
	if sess != nil {
		p.Accounts = sess
		p.Writes = sess
	}
	return p
}

// sameSession is false when Dir and Bound are both session-backed but over different sessions.
// Anything else (a test double on either side) is not a session mismatch.
func (p *ADProvider) sameSession() bool {
	var ds *adconn.Session
	switch d := p.Dir.(type) {
	case tier0.SessionDirectory:
		ds = d.S
	case *tier0.SessionDirectory:
		if d != nil {
			ds = d.S
		}
	}
	var bs *adconn.Session
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
func (p *ADProvider) OverSession(s *adconn.Session) bool {
	if p == nil || s == nil {
		return false
	}
	var ds, bs *adconn.Session
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
	Pins provider.PinStore
	// classify is the base classifier; nil means the T-0093 classifier over Dir. Tests substitute it.
	// in is the ADInput the production path builds (see classifierInput): pins and designations.
	classify func(ctx context.Context, id guid.GUID, in tier0.ADInput) (tier0.ADResult, error)
	// Dynamic is the Entra snapshot whose designated closure the AD plane's property writes are
	// checked against (the synced AD user is matched by rules on the Entra side, TM-D25 7f). Nil
	// refuses every property write.
	Dynamic provider.PropertyGuard
	// Bound reports the DC the connector is bound to (rule 5). Nil refuses every write.
	Bound provider.DCBound
	// Writes runs the object writes (kinds 1 to 3). It must be over the same session as Dir and Bound.
	Writes provider.ObjectDirectory
	// Accounts is the session the account kinds read and write on: the same session as Dir and Bound,
	// so the DC whose identity rule 5 checks is the DC the write reaches. Nil: those kinds answer
	// CAPABILITY_UNSUPPORTED.
	Accounts provider.AccountSession
	// Self is the connector's own account (the identity of every step-7 read), by GUID or DN. Kind 6
	// proves List Contents on Deleted Objects for this identity's token; unset, restore is refused
	// with INSUFFICIENT_RIGHTS (TM-D33 rule 4).
	Self dn.ObjectRef
	// sess is the session NewADProvider built every part over; the object-reading and rights facets
	// use it, and only while the provider is still over it (see sessionOK). It is unexported, so a
	// struct literal has no facets: the zero value fails every Read at the DC-identity step.
	sess *adconn.Session
}

var (
	_ provider.Provider      = (*ADProvider)(nil)
	_ provider.SessionBacked = (*ADProvider)(nil)
)

// Directory implements provider.SessionBacked.
func (p *ADProvider) Directory() tier0.ADDirectory { return p.Dir }

// PinStore implements provider.SessionBacked.
func (p *ADProvider) PinStore() provider.PinStore { return p.Pins }

// SelfRef implements provider.SessionBacked.
func (p *ADProvider) SelfRef() dn.ObjectRef { return p.Self }

// WriteDirectory implements provider.SessionBacked.
func (p *ADProvider) WriteDirectory() provider.ObjectDirectory { return p.Writes }

// AccountSession implements provider.SessionBacked.
func (p *ADProvider) AccountSession() provider.AccountSession {
	if p == nil || p.Accounts == nil {
		return nil
	}
	return p.Accounts
}

// OneSession implements provider.SessionBacked: the session when Dir and Bound are both over it.
func (p *ADProvider) OneSession() *adconn.Session {
	if !p.sessionOK() {
		return nil
	}
	return p.sess
}

func (p *ADProvider) Kind() connectorv1.ProviderKind {
	return connectorv1.ProviderKind_PROVIDER_KIND_AD
}

// BoundDC implements provider.DCBound; with no Bound configured it fails closed.
func (p *ADProvider) BoundDC(ctx context.Context) (*connectorv1.DcIdentity, error) {
	if p.Bound == nil {
		return nil, provider.ErrNoBoundDC
	}
	if !p.sameSession() {
		return nil, provider.ErrNoBoundDC // binder and directory on different sessions: not the DC the writes reach
	}
	return p.Bound.BoundDC(ctx)
}

func (p *ADProvider) Identity() *connectorv1.DirectoryIdentity { return p.ID }

// Classify runs the full live classification (it snapshots the directory on every call) and then
// checks the object's token groups against the designated groups.
func (p *ADProvider) Classify(ctx context.Context, id guid.GUID, designated []guid.GUID) (provider.Verdict, error) {
	unknown := provider.Verdict{Tier0: true}
	// C9 (TM-D23 rule 10): a GPO whose cn is not a GUID is tier0 with no further reads.
	ge, err := p.Dir.Get(ctx, dn.GUIDRef(id), []string{"objectClass", "cn"})
	if err != nil {
		return unknown, err
	}
	if gpoCNInvalid(ge) {
		return provider.Verdict{Tier0: true, Bases: []provider.Basis{tier0.C9}}, nil
	}
	// The pins ride on every Classify (TM-D26 rule 10); a store that cannot answer fails closed.
	if p.Pins == nil {
		return unknown, provider.ErrNoPins
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
	v := provider.Verdict{Tier0: r.Tier0, Bases: r.Bases}
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
			if adconn.CodeOf(err) == adconn.CodeObjectNotFound {
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
func gpoCNInvalid(e *adconn.Entry) bool {
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

func (p *ADProvider) Anchors(ctx context.Context, id guid.GUID) (provider.Anchors, error) {
	e, err := p.Dir.Get(ctx, dn.GUIDRef(id), []string{"objectGUID", "ms-DS-ConsistencyGuid", "objectSid"})
	if err != nil {
		return provider.Anchors{}, err
	}
	var a provider.Anchors
	a.Source = append(a.Source, e.Raw("objectGUID")...)
	a.Source = append(a.Source, e.Raw("ms-DS-ConsistencyGuid")...)
	for _, raw := range e.Raw("objectGUID") { // RFC 4122 order as well: both name the same object
		if g, err := guid.FromBytes(raw); err == nil {
			a.Source = append(a.Source, provider.GUIDToWire(g).GetValue())
		}
	}
	a.SIDs = e.Raw("objectSid")
	return a, nil
}

// PropertyGuard returns the snapshot, or the refuse-everything guard when there is none.
func (p *ADProvider) PropertyGuard(context.Context) (provider.PropertyGuard, error) {
	return provider.GuardOrRefuse(p.Dynamic), nil
}
