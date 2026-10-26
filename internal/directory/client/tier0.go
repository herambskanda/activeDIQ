package client

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Statement freshness. The connector's maximum statement age is a build-time constant of 15 minutes
// (contract §8.3 F3); the server stops short of it so a statement is not refused for clock skew or for
// the seconds between building and receipt. A statement resting on older facts is re-read live or the
// call is not sent.
const (
	connectorMaxStatementAge = 15 * time.Minute
	statementAgeBudget       = connectorMaxStatementAge - time.Minute
)

// Tier0ContextError is why a Tier0Context could not be built. The write is refused; nothing is sent.
// It carries a reason code only: no object identifier, so it can be logged and audited (DM-24.I5).
type Tier0ContextError struct {
	Reason Tier0Reason
	Cause  error
}

// Tier0Reason is the closed set of reasons a context is not built.
type Tier0Reason string

// Reasons.
const (
	ReasonSourceUnavailable Tier0Reason = "source_unavailable" // a read of inventory, registry or override store failed
	ReasonStaleFacts        Tier0Reason = "stale_facts"        // the facts are older than the connector accepts and no live re-read fixed it
	ReasonInconsistent      Tier0Reason = "inconsistent"       // stored data is outside its domain; fail closed
	ReasonBadRef            Tier0Reason = "bad_reference"      // the operation names no valid object
)

func (e *Tier0ContextError) Error() string { return "client: tier0 context not built: " + string(e.Reason) }
func (e *Tier0ContextError) Unwrap() error { return e.Cause }

func ctxErr(r Tier0Reason, cause error) error { return &Tier0ContextError{Reason: r, Cause: cause} }

// Tier0Sources are the inputs of the standard Tier0Builder. All but Refresh are required.
type Tier0Sources struct {
	Tenant       tenant.ID
	Connections  ConnectionSource
	Correlations CorrelationSource
	Designations Designations
	HybridLinks  HybridLinks
	Overrides    OverrideSource
	Revision     RevisionSource
	// Refresh is optional (see LiveRefresher).
	Refresh LiveRefresher
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// NewTier0Builder returns the Tier0Builder of the write path: one per tenant, reading inventory (DM-20),
// the designations (DM-16.I8), the hybrid links (DM-21), the override store (DM-25) and the revision.
func NewTier0Builder(s Tier0Sources) (Tier0Builder, error) {
	switch {
	case s.Tenant.IsZero(), s.Connections == nil, s.Correlations == nil, s.Designations == nil,
		s.HybridLinks == nil, s.Overrides == nil, s.Revision == nil:
		return nil, errors.New("client: Tier0 builder needs a tenant and every source except the live refresher")
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	return &tier0Builder{s}, nil
}

type tier0Builder struct{ Tier0Sources }

// Build builds the context for the operation's target. The connector derives the touched set from the
// typed change; until a kind carries a typed change, the touched set is the target (for a create, its
// planned parent), and a kind that touches more extends touched() with the same statement shape. The
// context is built from scratch at every stage: Apply does not reuse Plan's.
func (b *tier0Builder) Build(ctx context.Context, _ Stage, op WriteOp) (Tier0, error) {
	conn, objs, err := touched(op)
	if err != nil {
		return Tier0{}, err
	}
	own, err := b.Connections.Get(ctx, b.Tenant, connection.ID(conn))
	if err != nil {
		return Tier0{}, ctxErr(ReasonSourceUnavailable, err)
	}
	_, peerKind, err := kinds(own.Kind)
	if err != nil {
		return Tier0{}, err
	}

	t0 := &connectorv1.Tier0Context{}
	for _, o := range objs {
		st, err := b.statement(ctx, inventory.Ref{Connection: conn, Object: o}, peerKind)
		if err != nil {
			return Tier0{}, err
		}
		t0.Statements = append(t0.Statements, st)
	}
	des, err := b.Designations.DesignationsFor(ctx, b.Tenant, conn, objs)
	if err != nil {
		return Tier0{}, ctxErr(ReasonSourceUnavailable, err)
	}
	for _, d := range des {
		id, err := parseUUID(string(d))
		if err != nil {
			return Tier0{}, ctxErr(ReasonInconsistent, nil)
		}
		t0.Designated = append(t0.Designated, &connectorv1.Guid{Value: id})
	}
	if t0.Tier0Revision, err = b.Revision.Tier0Revision(ctx, b.Tenant); err != nil {
		return Tier0{}, ctxErr(ReasonSourceUnavailable, err)
	}
	ov, err := b.override(ctx, own.ID)
	if err != nil {
		return Tier0{}, err
	}
	return Tier0{Context: t0, Override: ov}, nil
}

// touched names the connection and the objects whose correlations the connector will ask about.
func touched(op WriteOp) (inventory.ConnectionID, []inventory.GUID, error) {
	obj := op.Target.GUID
	if obj == "" {
		obj = op.Target.Parent // an object a create makes has no GUID yet: the parent stands for it (§8.3 F1)
	}
	conn, obj := strings.ToLower(op.Target.Connection), strings.ToLower(obj)
	ref := inventory.Ref{Connection: inventory.ConnectionID(conn), Object: inventory.GUID(obj)}
	if !ref.Valid() {
		return "", nil, ctxErr(ReasonBadRef, nil)
	}
	return ref.Connection, []inventory.GUID{ref.Object}, nil
}

func kinds(k connection.Kind) (own, peer connectorv1.ProviderKind, err error) {
	switch k {
	case connection.KindADForest:
		return connectorv1.ProviderKind_PROVIDER_KIND_AD, connectorv1.ProviderKind_PROVIDER_KIND_ENTRA, nil
	case connection.KindEntraTenant:
		return connectorv1.ProviderKind_PROVIDER_KIND_ENTRA, connectorv1.ProviderKind_PROVIDER_KIND_AD, nil
	}
	return 0, 0, ctxErr(ReasonInconsistent, nil)
}

// statement builds the CorrelationStatement of one touched object.
func (b *tier0Builder) statement(ctx context.Context, ref inventory.Ref, peerKind connectorv1.ProviderKind) (*connectorv1.CorrelationStatement, error) {
	obj, err := parseUUID(string(ref.Object))
	if err != nil {
		return nil, ctxErr(ReasonBadRef, nil)
	}
	st := &connectorv1.CorrelationStatement{Object: &connectorv1.Guid{Value: obj}}
	ls, err := b.Correlations.CorrelationsFor(ctx, b.Tenant, ref)
	if err != nil {
		return nil, ctxErr(ReasonSourceUnavailable, err)
	}
	if len(ls) == 0 && peerKind == connectorv1.ProviderKind_PROVIDER_KIND_ENTRA {
		// no_hybrid_link only when the connection has no HybridLink at all (DM-21). This is read live
		// now, so it is the one empty answer that may be stamped with the time of the read (§8.3 F3).
		has, err := b.HybridLinks.HasHybridLink(ctx, b.Tenant, connection.ID(ref.Connection))
		if err != nil {
			return nil, ctxErr(ReasonSourceUnavailable, err)
		}
		if !has {
			st.Correlation = &connectorv1.CorrelationStatement_NoHybridLink{NoHybridLink: &connectorv1.NoHybridLink{}}
			st.ComputedAt = timestamppb.New(b.Now())
			return st, nil
		}
	}
	ls, asOf, err := b.fresh(ctx, ref, ls)
	if err != nil {
		return nil, err
	}
	peers := &connectorv1.CorrelatedPeers{}
	for _, l := range ls {
		p, err := b.peer(ctx, l, peerKind)
		if err != nil {
			return nil, err
		}
		peers.Peers = append(peers.Peers, p)
	}
	st.Correlation = &connectorv1.CorrelationStatement_Peers{Peers: peers}
	st.ComputedAt = timestamppb.New(asOf)
	return st, nil
}

// fresh returns the correlations with the as-of time of the oldest fact they rest on. An empty answer
// is itself a fact (no link as of the last evaluation) and a link whose tier0 status or evaluation has
// no as-of is just as unknown: neither may be stamped with the time of assembly. Unknown or older than
// the connector accepts means one live re-read; if that does not settle it the write is refused.
func (b *tier0Builder) fresh(ctx context.Context, ref inventory.Ref, ls []inventory.Link) ([]inventory.Link, time.Time, error) {
	if asOf, known := oldestFact(ls); known && b.Now().Sub(asOf) <= statementAgeBudget {
		return ls, asOf, nil
	}
	if b.Refresh == nil {
		return nil, time.Time{}, ctxErr(ReasonStaleFacts, nil)
	}
	read, err := b.Refresh.RefreshCorrelations(ctx, b.Tenant, ref)
	if err != nil {
		return nil, time.Time{}, ctxErr(ReasonSourceUnavailable, err)
	}
	if ls, err = b.Correlations.CorrelationsFor(ctx, b.Tenant, ref); err != nil {
		return nil, time.Time{}, ctxErr(ReasonSourceUnavailable, err)
	}
	if len(ls) == 0 { // the live read found none: the fact is as of that read
		if read.IsZero() || b.Now().Sub(read) > statementAgeBudget {
			return nil, time.Time{}, ctxErr(ReasonStaleFacts, nil)
		}
		return ls, read, nil
	}
	asOf, known := oldestFact(ls)
	if !known || b.Now().Sub(asOf) > statementAgeBudget {
		return nil, time.Time{}, ctxErr(ReasonStaleFacts, nil)
	}
	return ls, asOf, nil
}

// oldestFact is the minimum, over the links, of the correlation's last evaluation and the inventory
// as-of of the tier0 facts (§8.3 F3). A link missing either time, and an empty set, has no known as-of.
func oldestFact(ls []inventory.Link) (oldest time.Time, known bool) {
	if len(ls) == 0 {
		return time.Time{}, false
	}
	for _, l := range ls {
		if l.GateCheckedAt.IsZero() || l.FactsAsOf.IsZero() {
			return time.Time{}, false
		}
		for _, t := range []time.Time{l.GateCheckedAt, l.FactsAsOf} {
			if !known || t.Before(oldest) {
				oldest, known = t, true
			}
		}
	}
	return oldest, known
}

var stateWire = map[inventory.State]connectorv1.CorrelationState{
	inventory.StateCandidate: connectorv1.CorrelationState_CORRELATION_STATE_CANDIDATE,
	inventory.StateMatched:   connectorv1.CorrelationState_CORRELATION_STATE_MATCHED,
	inventory.StateBroken:    connectorv1.CorrelationState_CORRELATION_STATE_BROKEN,
}

// basisWire maps an inventory basis code ("C16", "E1", "designated") to the wire enum, from the
// generated names so a new basis in the contract needs no edit here.
var basisWire = func() map[inventory.Basis]connectorv1.Tier0Basis {
	m := map[inventory.Basis]connectorv1.Tier0Basis{}
	for v, name := range connectorv1.Tier0Basis_name {
		rest := strings.TrimPrefix(name, "TIER0_BASIS_")
		code, _, _ := strings.Cut(rest, "_")
		if rest == "CUSTOMER_DESIGNATED" {
			code = string(inventory.BasisDesignated)
		}
		if v != 0 {
			m[inventory.Basis(code)] = connectorv1.Tier0Basis(v)
		}
	}
	return m
}()

// peer maps one correlation, whatever its state, to a CorrelatedPeer. Anything the wire cannot state
// faithfully (an unknown state or basis, missing evidence, a tier0 peer with no basis) refuses the
// write: a peer must never be dropped or weakened to make the statement easier to send.
func (b *tier0Builder) peer(ctx context.Context, l inventory.Link, kind connectorv1.ProviderKind) (*connectorv1.CorrelatedPeer, error) {
	state, ok := stateWire[l.State]
	if !ok || !l.Peer.Valid() {
		return nil, ctxErr(ReasonInconsistent, nil)
	}
	po, err := parseUUID(string(l.Peer.Object))
	if err != nil {
		return nil, ctxErr(ReasonInconsistent, nil)
	}
	p := &connectorv1.CorrelatedPeer{PeerKind: kind, PeerObject: &connectorv1.Guid{Value: po}, State: state}
	switch l.Match {
	case inventory.MatchAnchor:
		if len(l.AnchorValue) == 0 {
			return nil, ctxErr(ReasonInconsistent, nil)
		}
		p.Evidence = &connectorv1.CorrelationEvidence{Evidence: &connectorv1.CorrelationEvidence_SourceAnchor{SourceAnchor: l.AnchorValue}}
	case inventory.MatchSID:
		if len(l.ADSID) == 0 {
			return nil, ctxErr(ReasonInconsistent, nil)
		}
		p.Evidence = &connectorv1.CorrelationEvidence{Evidence: &connectorv1.CorrelationEvidence_SecurityIdentifier{SecurityIdentifier: &connectorv1.Sid{Value: l.ADSID}}}
	default:
		return nil, ctxErr(ReasonInconsistent, nil)
	}
	// Bases present mean tier0, whatever the flag says: the statement may only widen protection.
	p.PeerTier0 = l.PeerTier0 || len(l.PeerBases) > 0
	for _, bs := range l.PeerBases {
		w, ok := basisWire[bs]
		if !ok {
			return nil, ctxErr(ReasonInconsistent, nil)
		}
		p.PeerTier0Basis = append(p.PeerTier0Basis, w)
	}
	if p.PeerTier0 && len(p.PeerTier0Basis) == 0 {
		return nil, ctxErr(ReasonInconsistent, nil)
	}
	peerConn, err := b.Connections.Get(ctx, b.Tenant, connection.ID(l.Peer.Connection))
	if err != nil {
		return nil, ctxErr(ReasonSourceUnavailable, err)
	}
	if pc, _, err := kinds(peerConn.Kind); err != nil || pc != kind { // the peer connection must be of the peer kind
		return nil, ctxErr(ReasonInconsistent, nil)
	}
	p.PeerDirectory = directoryOf(peerConn)
	return p, nil
}

// directoryOf describes the peer's directory when its identity is known; an unverified connection has
// none and the peer is still listed.
func directoryOf(c connection.Connection) *connectorv1.DirectoryIdentity {
	if c.DirectoryIdentity == "" {
		return nil
	}
	switch c.Kind {
	case connection.KindEntraTenant:
		return &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_EntraTenantId{EntraTenantId: string(c.DirectoryIdentity)}}
	case connection.KindADForest:
		g, err := parseUUID(string(c.DirectoryIdentity))
		if err != nil {
			return nil
		}
		return &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{ForestRootNcGuid: &connectorv1.Guid{Value: g}}}}
	}
	return nil
}

// override is the DM-25 override in force for the connection's credential, from the override store.
func (b *tier0Builder) override(ctx context.Context, id connection.ID) (*connectorv1.WriteGateOverride, error) {
	o, err := b.Overrides.Tier0OverrideInForce(ctx, b.Tenant, id)
	if err != nil {
		return nil, ctxErr(ReasonSourceUnavailable, err)
	}
	if o == nil {
		return nil, nil
	}
	if o.ConnectionID != id { // defence in depth against a provider returning another connection's override
		return nil, ctxErr(ReasonInconsistent, nil)
	}
	oid, err := parseUUID(string(o.ID))
	if err != nil {
		return nil, ctxErr(ReasonInconsistent, nil)
	}
	w := &connectorv1.WriteGateOverride{OverrideId: &connectorv1.Guid{Value: oid}}
	for _, f := range o.AcknowledgedFingerprints {
		raw, err := hex.DecodeString(f)
		if err != nil || len(raw) == 0 {
			return nil, ctxErr(ReasonInconsistent, nil)
		}
		w.AcknowledgedFingerprints = append(w.AcknowledgedFingerprints, raw)
	}
	return w, nil
}

