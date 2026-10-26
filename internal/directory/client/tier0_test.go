package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	adConn    = "6f1c2a40-0000-4000-8000-0000000000a1"
	entraConn = "6f1c2a40-0000-4000-8000-0000000000e1"
	entraObj  = "6f1c2a40-0000-4000-8000-0000000000e2"
	groupObj  = "6f1c2a40-0000-4000-8000-0000000000f1"
	ovID      = "6f1c2a40-0000-4000-8000-0000000000d1"
	tenantID  = "6f1c2a40-0000-4000-8000-0000000000ee"
)

var t0Now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

type fakeConns map[connection.ID]connection.Connection

func (f fakeConns) Get(_ context.Context, _ tenant.ID, id connection.ID) (connection.Connection, error) {
	c, ok := f[id]
	if !ok {
		return connection.Connection{}, errors.New("not found")
	}
	return c, nil
}

type fakeCorr struct {
	links []inventory.Link
	err   error
	calls int
}

func (f *fakeCorr) CorrelationsFor(context.Context, tenant.ID, inventory.Ref) ([]inventory.Link, error) {
	f.calls++
	return f.links, f.err
}

type fakeDes struct{ out []inventory.GUID }

func (f fakeDes) DesignationsFor(context.Context, tenant.ID, inventory.ConnectionID, []inventory.GUID) ([]inventory.GUID, error) {
	return f.out, nil
}

type fakeLinks struct {
	has bool
	err error
}

func (f fakeLinks) Confirmed(context.Context, tenant.ID, connection.ID, connection.NCGUID, connection.ID) (bool, error) {
	return false, nil
}
func (f fakeLinks) HasHybridLink(context.Context, tenant.ID, connection.ID) (bool, error) {
	return f.has, f.err
}

type fakeOv struct {
	o   *connection.Tier0Override
	err error
}

func (f fakeOv) Tier0OverrideInForce(context.Context, tenant.ID, connection.ID) (*connection.Tier0Override, error) {
	return f.o, f.err
}

type fakeRev struct{}

func (fakeRev) Tier0Revision(context.Context, tenant.ID) (uint64, error) { return 42, nil }

type fakeRefresh struct {
	calls int
	at    time.Time
	apply func()
}

func (f *fakeRefresh) RefreshCorrelations(context.Context, tenant.ID, inventory.Ref) (time.Time, error) {
	f.calls++
	if f.apply != nil {
		f.apply()
	}
	if !f.at.IsZero() {
		return f.at, nil
	}
	return t0Now, nil
}

type rig struct {
	corr  *fakeCorr
	des   fakeDes
	links fakeLinks
	ov    fakeOv
	ref   *fakeRefresh
	conns fakeConns
}

func newRig() *rig {
	return &rig{corr: &fakeCorr{}, conns: fakeConns{
		adConn:    {ID: adConn, Kind: connection.KindADForest, DirectoryIdentity: "6f1c2a40-0000-4000-8000-0000000000c9"},
		entraConn: {ID: entraConn, Kind: connection.KindEntraTenant, DirectoryIdentity: "6f1c2a40-0000-4000-8000-0000000000c8"},
	}}
}

func (r *rig) builder(t *testing.T) Tier0Builder {
	t.Helper()
	tid, err := tenant.Parse(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	s := Tier0Sources{Tenant: tid, Connections: r.conns, Correlations: r.corr, Designations: r.des, HybridLinks: r.links,
		Overrides: r.ov, Revision: fakeRev{}, Now: func() time.Time { return t0Now }}
	if r.ref != nil {
		s.Refresh = r.ref
	}
	b, err := NewTier0Builder(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func adOp() WriteOp {
	tg := authority.TargetRef{Connection: adConn, GUID: objGUID, Class: "user", NC: ncGUID}
	return WriteOp{DigestKind: "user.set", Target: tg, Attrs: testAttrs}
}

func link(state inventory.State, tier0 bool, bases ...inventory.Basis) inventory.Link {
	return inventory.Link{
		ID: "l1", Self: inventory.Ref{Connection: adConn, Object: objGUID}, Peer: inventory.Ref{Connection: entraConn, Object: entraObj},
		State: state, PeerKind: "entra_tenant", Match: inventory.MatchAnchor, AnchorValue: bytes.Repeat([]byte{7}, 16),
		PeerTier0: tier0, PeerBases: bases, FactsAsOf: t0Now.Add(-2 * time.Minute), GateCheckedAt: t0Now.Add(-time.Minute),
	}
}

func TestEveryCorrelationStateIsListedWithPeerTier0AndEvidence(t *testing.T) {
	for _, st := range []inventory.State{inventory.StateCandidate, inventory.StateMatched, inventory.StateBroken} {
		t.Run(string(st), func(t *testing.T) {
			r := newRig()
			r.corr.links = []inventory.Link{link(st, true, "E1")}
			got, err := r.builder(t).Build(context.Background(), StagePlan, adOp())
			if err != nil {
				t.Fatal(err)
			}
			peers := got.Context.GetStatements()[0].GetPeers().GetPeers()
			if len(peers) != 1 || !peers[0].GetPeerTier0() || peers[0].GetPeerTier0Basis()[0] != connectorv1.Tier0Basis_TIER0_BASIS_E1_DIRECTORY_ROLE_HOLDER ||
				peers[0].GetEvidence().GetSourceAnchor() == nil || peers[0].GetPeerKind() != connectorv1.ProviderKind_PROVIDER_KIND_ENTRA {
				t.Fatalf("peer = %v", peers)
			}
			if peers[0].GetPeerDirectory().GetEntraTenantId() == "" {
				t.Fatal("peer directory missing")
			}
			if got.Context.GetTier0Revision() != 42 {
				t.Fatal("revision")
			}
		})
	}
}

func TestSIDEvidenceAndNonTier0Peer(t *testing.T) {
	r := newRig()
	l := link(inventory.StateMatched, false)
	l.Match, l.AnchorValue, l.ADSID = inventory.MatchSID, nil, []byte{1, 5, 0, 0, 0, 0, 0, 5, 21}
	r.corr.links = []inventory.Link{l}
	got, err := r.builder(t).Build(context.Background(), StageApply, adOp())
	if err != nil {
		t.Fatal(err)
	}
	p := got.Context.Statements[0].GetPeers().Peers[0]
	if p.GetPeerTier0() || len(p.GetPeerTier0Basis()) != 0 || p.GetEvidence().GetSecurityIdentifier() == nil {
		t.Fatalf("peer = %v", p)
	}
}

func TestNoHybridLinkOnlyWhenTheConnectionHasNone(t *testing.T) {
	r := newRig()
	got, err := r.builder(t).Build(context.Background(), StagePlan, adOp())
	if err != nil {
		t.Fatal(err)
	}
	st := got.Context.Statements[0]
	if st.GetNoHybridLink() == nil || !st.GetComputedAt().AsTime().Equal(t0Now) {
		t.Fatalf("statement = %v", st)
	}
	// A hybrid connection with no stored correlation: the absence is a fact with no known as-of (the
	// correlation job may lag), so without a live read the write is refused, never stamped "now".
	r.links.has = true
	if _, err = r.builder(t).Build(context.Background(), StagePlan, adOp()); !isReason(err, ReasonStaleFacts) {
		t.Fatalf("empty answer on a hybrid connection, no refresher: %v", err)
	}
	// With a refresher the statement is stamped with the time of that read.
	readAt := t0Now.Add(-30 * time.Second)
	r.ref = &fakeRefresh{at: readAt}
	got, err = r.builder(t).Build(context.Background(), StagePlan, adOp())
	if err != nil {
		t.Fatal(err)
	}
	if st := got.Context.Statements[0]; st.GetNoHybridLink() != nil || st.GetPeers() == nil || len(st.GetPeers().Peers) != 0 ||
		!st.GetComputedAt().AsTime().Equal(readAt) {
		t.Fatalf("statement = %v", st)
	}
	r.ref = nil
	r.links.err = errors.New("db down")
	if _, err := r.builder(t).Build(context.Background(), StagePlan, adOp()); err == nil {
		t.Fatal("a failed link read must not become no_hybrid_link")
	}
}

func TestComputedAtIsTheOldestFactNotAssemblyTime(t *testing.T) {
	r := newRig()
	a, b := link(inventory.StateMatched, true, "E1"), link(inventory.StateCandidate, true, "E2")
	b.Peer.Object = "6f1c2a40-0000-4000-8000-0000000000e3"
	b.FactsAsOf, b.GateCheckedAt = t0Now.Add(-9*time.Minute), t0Now.Add(-5*time.Minute)
	r.corr.links = []inventory.Link{a, b}
	got, err := r.builder(t).Build(context.Background(), StagePlan, adOp())
	if err != nil {
		t.Fatal(err)
	}
	if at := got.Context.Statements[0].GetComputedAt().AsTime(); !at.Equal(t0Now.Add(-9 * time.Minute)) {
		t.Fatalf("computed_at = %v", at)
	}
}

func TestStaleFactsAreRefreshedLiveOrTheCallIsNotSent(t *testing.T) {
	old := link(inventory.StateMatched, true, "E1")
	old.FactsAsOf, old.GateCheckedAt = t0Now.Add(-30*time.Minute), t0Now.Add(-40*time.Minute)

	r := newRig()
	r.corr.links = []inventory.Link{old}
	_, err := r.builder(t).Build(context.Background(), StagePlan, adOp())
	var ce *Tier0ContextError
	if !errors.As(err, &ce) || ce.Reason != ReasonStaleFacts {
		t.Fatalf("no refresher: got %v", err)
	}

	r = newRig()
	r.corr.links = []inventory.Link{old}
	r.ref = &fakeRefresh{apply: func() { r.corr.links = []inventory.Link{link(inventory.StateMatched, true, "E1")} }}
	got, err := r.builder(t).Build(context.Background(), StagePlan, adOp())
	if err != nil || r.ref.calls != 1 {
		t.Fatalf("err %v, refreshes %d", err, r.ref.calls)
	}
	if at := got.Context.Statements[0].GetComputedAt().AsTime(); at.Before(t0Now.Add(-3 * time.Minute)) {
		t.Fatalf("computed_at = %v after a live re-read", at)
	}

	r = newRig() // the re-read leaves it stale: refused, not stamped fresh
	r.corr.links = []inventory.Link{old}
	r.ref = &fakeRefresh{}
	if _, err := r.builder(t).Build(context.Background(), StagePlan, adOp()); !errors.As(err, &ce) || ce.Reason != ReasonStaleFacts {
		t.Fatalf("got %v", err)
	}
}

func TestFailClosedOnUnmappableLinks(t *testing.T) {
	bad := map[string]func(*inventory.Link){
		"unknown state":       func(l *inventory.Link) { l.State = "weird" },
		"removed state":       func(l *inventory.Link) { l.State = inventory.StateRemoved },
		"no evidence":         func(l *inventory.Link) { l.AnchorValue = nil },
		"unknown match":       func(l *inventory.Link) { l.Match = "" },
		"tier0 without basis": func(l *inventory.Link) { l.PeerTier0, l.PeerBases = true, nil },
		"unknown basis":       func(l *inventory.Link) { l.PeerBases = []inventory.Basis{"Z9"} },
	}
	for name, mut := range bad {
		t.Run(name, func(t *testing.T) {
			r := newRig()
			l := link(inventory.StateMatched, true, "E1")
			mut(&l)
			r.corr.links = []inventory.Link{l}
			if _, err := r.builder(t).Build(context.Background(), StagePlan, adOp()); err == nil {
				t.Fatal("built a statement from data the wire cannot state")
			}
		})
	}
	// Bases without the flag still mean tier0: the statement only widens.
	r := newRig()
	l := link(inventory.StateMatched, false, "E1")
	r.corr.links = []inventory.Link{l}
	got, err := r.builder(t).Build(context.Background(), StagePlan, adOp())
	if err != nil || !got.Context.Statements[0].GetPeers().Peers[0].GetPeerTier0() {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestSourceErrorsRefuse(t *testing.T) {
	r := newRig()
	r.corr.err = errors.New("db down")
	if _, err := r.builder(t).Build(context.Background(), StagePlan, adOp()); err == nil {
		t.Fatal("correlation read error must refuse")
	}
	r = newRig()
	r.ov.err = errors.New("db down")
	if _, err := r.builder(t).Build(context.Background(), StagePlan, adOp()); err == nil {
		t.Fatal("override read error must refuse")
	}
	r = newRig()
	op := adOp()
	op.Target.Connection = "nope"
	if _, err := r.builder(t).Build(context.Background(), StagePlan, op); err == nil {
		t.Fatal("bad connection must refuse")
	}
}

func TestDesignationsAndCreateParent(t *testing.T) {
	r := newRig()
	r.des = fakeDes{out: []inventory.GUID{groupObj}}
	op := adOp()
	op.Target.GUID, op.Target.Parent = "", groupObj
	got, err := r.builder(t).Build(context.Background(), StagePlan, op)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Context.Designated) != 1 || fmt.Sprintf("%x", got.Context.Designated[0].Value)[:8] != "6f1c2a40" {
		t.Fatalf("designated = %v", got.Context.Designated)
	}
	if id, _ := parseUUID(groupObj); !bytes.Equal(got.Context.Statements[0].GetObject().GetValue(), id) {
		t.Fatal("a create is stated about its parent")
	}
}

func TestOverrideInForceBecomesWriteGateOverride(t *testing.T) {
	r := newRig()
	got, err := r.builder(t).Build(context.Background(), StagePlan, adOp())
	if err != nil || got.Override != nil {
		t.Fatalf("no override in force: %v %v", got.Override, err)
	}
	r.ov.o = &connection.Tier0Override{ID: ovID, ConnectionID: adConn, AcknowledgedFingerprints: []string{"0a0b", "ff"}}
	got, err = r.builder(t).Build(context.Background(), StageApply, adOp())
	if err != nil {
		t.Fatal(err)
	}
	fp := got.Override.GetAcknowledgedFingerprints()
	if len(fp) != 2 || !bytes.Equal(fp[0], []byte{0x0a, 0x0b}) || got.Override.GetOverrideId() == nil {
		t.Fatalf("override = %v", got.Override)
	}
	r.ov.o.ConnectionID = entraConn // another connection's override is never applied
	if _, err := r.builder(t).Build(context.Background(), StageApply, adOp()); !isReason(err, ReasonInconsistent) {
		t.Fatalf("foreign override: %v", err)
	}
	r.ov.o.ConnectionID = adConn
	r.ov.o.AcknowledgedFingerprints = []string{"zz"}
	if _, err := r.builder(t).Build(context.Background(), StageApply, adOp()); err == nil {
		t.Fatal("a corrupt fingerprint must refuse")
	}
}

func TestEntraTargetGetsADPeerKind(t *testing.T) {
	r := newRig()
	l := link(inventory.StateCandidate, true, "C1")
	l.Self, l.Peer, l.PeerKind = inventory.Ref{Connection: entraConn, Object: objGUID}, inventory.Ref{Connection: adConn, Object: entraObj}, "ad_forest"
	r.corr.links = []inventory.Link{l}
	op := adOp()
	op.Target.Connection = entraConn
	got, err := r.builder(t).Build(context.Background(), StagePlan, op)
	if err != nil {
		t.Fatal(err)
	}
	p := got.Context.Statements[0].GetPeers().Peers[0]
	if p.GetPeerKind() != connectorv1.ProviderKind_PROVIDER_KIND_AD || p.GetPeerDirectory().GetAdForest() == nil {
		t.Fatalf("peer = %v", p)
	}
	// An Entra object with no correlation never claims no_hybrid_link; the absence has no known as-of
	// without a live read.
	r.corr.links = nil
	if _, err = r.builder(t).Build(context.Background(), StagePlan, op); !isReason(err, ReasonStaleFacts) {
		t.Fatalf("got %v", err)
	}
	r.ref = &fakeRefresh{}
	got, err = r.builder(t).Build(context.Background(), StagePlan, op)
	if err != nil || got.Context.Statements[0].GetNoHybridLink() != nil || got.Context.Statements[0].GetPeers() == nil {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestNewTier0BuilderRequiresSources(t *testing.T) {
	if _, err := NewTier0Builder(Tier0Sources{}); err == nil {
		t.Fatal("empty sources accepted")
	}
}

// refusingConnector stands in for the connector's F5 rule: a consistent tier0 peer in any state refuses.
type refusingConnector struct {
	transport
	plans, applies []*connectorv1.Tier0Context
	refuse         *connectorv1.Guid
}

func (c *refusingConnector) check(t0 *connectorv1.Tier0Context) error {
	for _, s := range t0.GetStatements() {
		for _, p := range s.GetPeers().GetPeers() {
			if p.GetPeerTier0() && len(p.GetPeerTier0Basis()) > 0 && p.GetEvidence().GetEvidence() != nil {
				d := &connectorv1.ConnectorError{Code: connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED,
					Details: &connectorv1.ConnectorError_Tier0Refused{Tier0Refused: &connectorv1.Tier0RefusedDetails{Object: s.GetObject()}}}
				st, _ := status.New(codes.FailedPrecondition, "refused: "+string(s.GetObject().GetValue())).WithDetails(d)
				return st.Err()
			}
		}
	}
	return nil
}
func (c *refusingConnector) Plan(_ context.Context, r *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	c.plans = append(c.plans, r.GetTier0())
	if err := c.check(r.GetTier0()); err != nil {
		return nil, err
	}
	return &connectorv1.PlanResponse{}, nil
}
func (c *refusingConnector) Apply(_ context.Context, r *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	c.applies = append(c.applies, r.GetTier0())
	if err := c.check(r.GetTier0()); err != nil {
		return nil, err
	}
	return &connectorv1.ApplyResponse{}, nil
}

func TestWriteCarriesStatementAtPlanAndApplyAndRefusalNeverReachesAudit(t *testing.T) {
	for _, st := range []inventory.State{inventory.StateCandidate, inventory.StateMatched, inventory.StateBroken} {
		t.Run(string(st), func(t *testing.T) {
			r := newRig()
			r.corr.links = []inventory.Link{link(st, true, "E1")}
			ctr := &refusingConnector{}
			c := New(WithTransport(ctr), WithFacts(&facts{}), WithTier0Builder(r.builder(t)))
			tg := authority.TargetRef{Connection: adConn, GUID: objGUID, Class: "user", NC: ncGUID}
			var werr error
			withStepOf(t, tg, authority.Pins{ncGUID: "dc1.corp.example"}, func(ctx context.Context, s step.Step) {
				_, werr = c.Write(ctx, s, WriteOp{DigestKind: "user.set", Target: tg, Attrs: testAttrs})
			})
			if len(ctr.plans) != 1 {
				t.Fatalf("plans %d", len(ctr.plans))
			}
			p := ctr.plans[0].GetStatements()[0].GetPeers().GetPeers()
			if len(p) != 1 || !p[0].GetPeerTier0() || p[0].GetEvidence().GetEvidence() == nil || p[0].GetState() == 0 {
				t.Fatalf("plan statement = %v", p)
			}
			if werr == nil {
				t.Fatal("connector refusal must surface")
			}
			o := MapError(werr)
			if o.Status != StatusRefused || o.Code != connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED {
				t.Fatalf("outcome %+v", o)
			}
			// AC2: nothing a caller may put into an audit event, or an error text, holds the object.
			id, _ := parseUUID(objGUID)
			for _, s := range []string{fmt.Sprint(o.Audit), werr.Error(), fmt.Sprintf("%+v", o.Audit)} {
				if strings.Contains(strings.ToLower(s), objGUID) || strings.Contains(s, string(id)) {
					t.Fatalf("object identifier in %q", s)
				}
			}
		})
	}
}

func TestApplyBuildsAFreshContext(t *testing.T) {
	r := newRig()
	r.corr.links = []inventory.Link{link(inventory.StateMatched, false)}
	ctr := &refusingConnector{}
	c := New(WithTransport(ctr), WithFacts(&facts{}), WithTier0Builder(r.builder(t)))
	tg := authority.TargetRef{Connection: adConn, GUID: objGUID, Class: "user", NC: ncGUID}
	withStepOf(t, tg, authority.Pins{ncGUID: "dc1.corp.example"}, func(ctx context.Context, s step.Step) {
		if _, err := c.Write(ctx, s, WriteOp{DigestKind: "user.set", Target: tg, Attrs: testAttrs}); err != nil {
			t.Fatal(err)
		}
	})
	if r.corr.calls != 2 || len(ctr.applies) != 1 {
		t.Fatalf("correlation reads %d, applies %d: Apply must rebuild", r.corr.calls, len(ctr.applies))
	}
	if proto.Equal(ctr.plans[0], &connectorv1.Tier0Context{}) {
		t.Fatal("empty context")
	}
}

func TestMapErrorTier0ContextRefusal(t *testing.T) {
	o := MapError(fmt.Errorf("x: %w", ctxErr(ReasonStaleFacts, errors.New("cause with "+objGUID))))
	if o.Status != StatusFailed || o.Retryable || o.Audit["reason"] != "stale_facts" || strings.Contains(fmt.Sprint(o.Audit), objGUID) {
		t.Fatalf("%+v", o)
	}
}

func isReason(err error, want Tier0Reason) bool {
	var e *Tier0ContextError
	return errors.As(err, &e) && e.Reason == want
}

// A peer recorded "not tier0" with no facts as-of has no known as-of for that status: it may not be
// stamped with the gate check time (F3).
func TestNonTier0PeerWithoutFactsAsOfIsStale(t *testing.T) {
	r := newRig()
	l := link(inventory.StateMatched, false)
	l.FactsAsOf = time.Time{}
	r.corr.links = []inventory.Link{l}
	if _, err := r.builder(t).Build(context.Background(), StagePlan, adOp()); !isReason(err, ReasonStaleFacts) {
		t.Fatalf("zero FactsAsOf: %v", err)
	}
	l = link(inventory.StateMatched, false)
	l.GateCheckedAt = time.Time{}
	r.corr.links = []inventory.Link{l}
	if _, err := r.builder(t).Build(context.Background(), StagePlan, adOp()); !isReason(err, ReasonStaleFacts) {
		t.Fatalf("zero GateCheckedAt: %v", err)
	}
}
