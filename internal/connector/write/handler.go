package write

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

type (
	basis = connectorv1.Tier0Basis
)

const (
	stMissing       = connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_MISSING
	stStale         = connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_STALE
	stRequest       = connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_REQUEST_CONTEXT
	stConnectorSet  = connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONNECTOR_SET
	stLive          = connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD
	stContradicted  = connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_CONTEXT_CONTRADICTED
	afterWriteLimit = 2 * time.Minute
)

// Handler is the connector's Plan and Apply (contract §8.1). It implements the write half of
// connectorv1.ConnectorServer and directory/client.Transport.
type Handler struct {
	prov  Provider
	gates *GateBook
	rec   Recorder
	now   func() time.Time
	ops   map[connectorv1.WriteKind]WriteOp
}

// Option configures New.
type Option func(*Handler)

// WithRecorder replaces the default slog recorder.
func WithRecorder(r Recorder) Option { return func(h *Handler) { h.rec = r } }

// WithClock replaces the clock the freshness rule reads (tests).
func WithClock(now func() time.Time) Option { return func(h *Handler) { h.now = now } }

// New builds the handler for one provider. The gate book must be the one the connector's
// VerifyConnection feeds.
func New(p Provider, g *GateBook, opts ...Option) (*Handler, error) {
	if p == nil || g == nil {
		return nil, errors.New("write: provider and gate book are required")
	}
	h := &Handler{prov: p, gates: g, rec: SlogRecorder{}, now: time.Now, ops: operations}
	for _, o := range opts {
		o(h)
	}
	if err := validateOps(h.ops); err != nil {
		return nil, err
	}
	return h, nil
}

// call is the common shape of PlanRequest and ApplyRequest.
type call struct {
	name   string
	conn   *connectorv1.ConnectionRef
	step   *connectorv1.StepKey
	target *connectorv1.WriteTarget
	kind   connectorv1.WriteKind
	change *connectorv1.WriteChange
	t0     *connectorv1.Tier0Context
	ov     *connectorv1.WriteGateOverride
	acting *connectorv1.ActingPrincipal

	dc *connectorv1.DcSelection // Plan only

	secret  bool // Apply only: the request carries secret_input
	attempt uint32
	pre     *connectorv1.TargetPrecondition
	digest  []byte
}

// outcome of the guard: the operation to run, or nil when the kind is not wired.
type passed struct {
	op      *WriteOp
	auth    Authorised
	touched []guid.GUID
	// designated is the set step 7 checked; step 9 repeats the same reads.
	designated []guid.GUID
	dec        Decision
	// dc is the bound DC's identity (AD only), verified equal to the pin (Plan) or to precondition.dc (Apply).
	dc *connectorv1.DcIdentity
}

// Plan implements connectorv1.ConnectorServer.
func (h *Handler) Plan(ctx context.Context, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	c := &call{name: "plan", conn: req.GetConnection(), step: req.GetStep(), target: req.GetTarget(), kind: req.GetKind(),
		change: req.GetChange(), t0: req.GetTier0(), ov: req.GetTier0Override(), acting: req.GetActingPrincipal(), dc: req.GetDc()}
	ev := h.event(c)
	p, err := h.guard(ctx, c, &ev)
	if err != nil {
		return nil, h.finish(&ev, err)
	}
	if p.op == nil {
		return nil, h.finish(&ev, unsupported())
	}
	resp, err := p.op.Plan(ctx, p.auth, req)
	if err != nil {
		return nil, h.finish(&ev, err)
	}
	if p.dc != nil { // AD: the precondition names the DC Plan read from, which is the pinned one
		if resp.Precondition == nil {
			resp.Precondition = &connectorv1.TargetPrecondition{}
		}
		if d := resp.Precondition.GetDc(); d != nil && !proto.Equal(d.GetDsaGuid(), p.dc.GetDsaGuid()) {
			return nil, h.finish(&ev, pinRefusal("5"))
		}
		resp.Precondition.Dc = p.dc
	}
	h.fillEvaluation(&resp.Tier0, p)
	resp.Step, resp.Target = req.GetStep(), req.GetTarget()
	h.finish(&ev, nil)
	return resp, nil
}

// Apply implements connectorv1.ConnectorServer.
func (h *Handler) Apply(ctx context.Context, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	c := &call{name: "apply", conn: req.GetConnection(), step: req.GetStep(), target: req.GetTarget(), kind: req.GetKind(),
		change: req.GetChange(), t0: req.GetTier0(), ov: req.GetTier0Override(), acting: req.GetActingPrincipal(),
		attempt: req.GetAttempt(), pre: req.GetPrecondition(), digest: req.GetPlanDigest(), secret: req.GetSecretInput() != nil}
	ev := h.event(c)
	p, err := h.guard(ctx, c, &ev)
	if err != nil {
		return nil, h.finish(&ev, err)
	}
	if p.op == nil {
		return nil, h.finish(&ev, unsupported())
	}
	// Step 5 for Apply: the digest, recomputed from the typed fields.
	want, derr := p.op.Digest(req)
	if derr != nil || !bytes.Equal(want, c.digest) {
		return nil, h.finish(&ev, invalid("5", "PlanDigestMismatch", "plan_digest"))
	}
	resp, err := p.op.Apply(ctx, p.auth, req)
	if err != nil {
		return nil, h.finish(&ev, err)
	}
	h.fillEvaluation(&resp.Tier0, p)
	resp.Step, resp.Attempt, resp.Target = req.GetStep(), req.GetAttempt(), req.GetTarget()
	if resp.GetOutcome() == connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED {
		resp.Tier0AfterWrite = h.afterWrite(ctx, p, &ev)
	}
	h.finish(&ev, nil)
	return resp, nil
}

func (h *Handler) fillEvaluation(dst **connectorv1.Tier0Evaluation, p *passed) {
	ev := &connectorv1.Tier0Evaluation{ServerTier0Revision: 0}
	for _, g := range p.touched {
		ev.Evaluated = append(ev.Evaluated, toWire(g))
	}
	if len(p.dec.VerificationID) > 0 {
		ev.VerificationId = &connectorv1.Guid{Value: p.dec.VerificationID}
	}
	*dst = ev
}

func (h *Handler) event(c *call) Event {
	e := Event{Op: c.name, Attempt: itoa(c.attempt), PlanDigest: hex.EncodeToString(c.digest)}
	if c.step != nil {
		e.Operation, e.Item, e.Step = guidText(c.step.GetOperationId()), itoa(c.step.GetItem()), itoa(c.step.GetStep())
	}
	e.Account, e.Token = guidText(c.acting.GetAccountId()), guidText(c.acting.GetApiTokenId())
	if c.t0 != nil {
		e.Tier0Revision, e.Statements = c.t0.GetTier0Revision(), len(c.t0.GetStatements())
		for _, s := range c.t0.GetStatements() {
			e.Peers += len(s.GetPeers().GetPeers())
		}
	}
	return e
}

// finish records the call and returns err unchanged.
func (h *Handler) finish(ev *Event, err error) error {
	ev.Outcome = "ok"
	if err != nil {
		ev.Outcome, ev.Code = "failed", "unknown"
		var r *Refusal
		if errors.As(err, &r) {
			ev.Outcome, ev.Code = "refused", r.Code().String()
			if ev.Stage == "" {
				ev.Stage = r.stage
			}
			if d := r.Err.GetTier0Refused(); d != nil {
				ev.Object = guidText(d.GetObject())
				for _, b := range d.GetBasis() {
					ev.Bases = append(ev.Bases, b.String())
				}
			}
		}
	}
	h.rec.Record(*ev)
	return err
}

// guard runs steps 1 to 7 of §8.1. A nil error means every check passed; p.op is nil when the kind
// is not wired, in which case the caller answers CAPABILITY_UNSUPPORTED (the refusal that names a
// reason wins over it, so the target's checks run first).
func (h *Handler) guard(ctx context.Context, c *call, ev *Event) (*passed, error) {
	// Step 1: request shape and directory identity. No directory call.
	if c.conn.GetConnectionId() == "" || c.conn.GetDirectoryIdentity() == nil {
		return nil, invalid("1", "ConnectionRequired", "connection")
	}
	if !proto.Equal(c.conn.GetDirectoryIdentity(), h.prov.Identity()) {
		return nil, mismatch()
	}
	target, err := fromWire(c.target.GetObject())
	if err != nil {
		return nil, invalid("1", "TargetRequired", "target.object")
	}
	if c.name == "apply" && (c.pre == nil || len(c.digest) == 0) {
		return nil, invalid("1", "PreconditionRequired", "precondition")
	}

	isAD := h.prov.Kind() == connectorv1.ProviderKind_PROVIDER_KIND_AD
	// ADR-0005 rule 5: an AD Plan names the DC it must run on; nil or unset is refused before any
	// directory call. An AD Apply is held to the DC the precondition names.
	var want *connectorv1.Guid
	if isAD {
		if c.name == "plan" {
			want = c.dc.GetPinnedDsaGuid()
			if _, err := fromWire(want); err != nil {
				return nil, invalid("1", "DcRequired", "dc.pinned_dsa_guid")
			}
		} else {
			want = c.pre.GetDc().GetDsaGuid()
			if _, err := fromWire(want); err != nil {
				return nil, invalid("1", "DcRequired", "precondition.dc.dsa_guid")
			}
		}
	}

	// Step 2: the write gate.
	dec := h.gates.Check(c.conn.GetConnectionId(), isAD, c.ov)
	if dec.ByOverride {
		ev.OverrideID, ev.OverrideAcked, ev.OverrideListed = guidText(c.ov.GetOverrideId()), dec.Acknowledged, dec.Listed
	}
	if !dec.Open {
		return nil, gateRefusal(dec.State, wireOrNil(dec.VerificationID), dec.Unacknowledged)
	}

	// Step 2b: the bound DC is the pinned one. A mismatch or an unreadable identity is an error,
	// never a silent switch (read-your-writes, DM-15.I3).
	var bound *connectorv1.DcIdentity
	if isAD {
		b, ok := h.prov.(DCBinder)
		if !ok {
			return nil, pinRefusal("2")
		}
		id, err := b.BoundDC(ctx)
		if err != nil || id == nil || !proto.Equal(id.GetDsaGuid(), want) {
			return nil, pinRefusal("2")
		}
		bound = id
	}

	// Step 3: Tier0Context present; the target's statement present and fresh.
	idx := h.index(c.t0)
	if c.t0 == nil {
		return nil, tier0Refusal(toWire(target), nil, stMissing, "3")
	}
	if r := h.statementCheck(idx, target, "3"); r != nil {
		return nil, r
	}

	// Step 4: the target against the request's marks and the connector's set.
	if r := h.requestMarks(c, idx, []guid.GUID{target}, isAD, true); r != nil {
		return nil, r
	}
	if r := h.checkRequest(c, idx, target, isAD, "4"); r != nil {
		return nil, r
	}

	// Step 4, last check: the dynamic-group property guard (contract §8.9). It is not an input of
	// the override (D11): c.ov was consulted at step 2 only. A kind that is not wired has no
	// PropertyWrite and writes nothing.
	var op *WriteOp
	var declared []string
	if w, ok := h.ops[c.kind]; ok && c.kind != connectorv1.WriteKind_WRITE_KIND_UNSPECIFIED {
		op = &w
		if w.Arm != nil && !w.Arm(c.change) && !(c.name == "apply" && w.WantsSecret && !c.secret) {
			return nil, invalid("4", "WriteChangeArmMismatch", "change")
		}
		if c.name == "apply" && c.secret != w.WantsSecret {
			return nil, invalid("4", "SecretInputMismatch", "secret_input")
		}
		if r := h.propertyGuard(ctx, w, c, target, ev); r != nil {
			return nil, r
		}
		declared = append(declared, ev.PropertyKeys...)
	}

	// Step 5: the kind. A kind that is not wired is answered after the target's live checks.
	touched := []guid.GUID{target}
	if op != nil {
		w := *op
		ts, err := w.Touched(target, c.change)
		if err != nil {
			return nil, invalid("5", "TouchedSet", "change")
		}
		touched = dedupe(target, ts)
	}

	// Step 6: every other touched object needs its own present, fresh statement and passes the
	// same checks.
	if len(touched) > 1 {
		if r := h.requestMarks(c, idx, touched[1:], isAD, false); r != nil {
			return nil, r
		}
		for _, id := range touched[1:] {
			if r := h.statementCheck(idx, id, "6"); r != nil {
				return nil, r
			}
		}
		for _, id := range touched[1:] {
			if r := h.checkRequest(c, idx, id, isAD, "6"); r != nil {
				return nil, r
			}
		}
	}
	ev.Ignored = h.ignored(c.t0, touched)

	// Step 7: live re-read and classification of every touched object. An error is tier0.
	designated := unionGUIDs(parseGUIDs(c.t0.GetDesignated()), h.gates.Designated(c.conn.GetConnectionId()))
	for _, id := range touched {
		if r := h.live(ctx, idx, id, designated); r != nil {
			return nil, r
		}
	}
	var boundDSA guid.GUID
	if bound != nil {
		boundDSA, _ = fromWire(bound.GetDsaGuid()) // verified equal to the pin at step 2b
	}
	return &passed{op: op, touched: touched, designated: designated, dec: dec, dc: bound, auth: Authorised{p: &pass{evaluated: touched, dc: boundDSA, props: declared, prov: h.prov}}}, nil
}

// Refusal reasons recorded for a property-write refusal that is not a rule verdict.
const (
	reasonGuardUnavailable = "property_guard_unavailable"
	reasonBadDeclaration   = "property_declaration_invalid"
)

// propertyGuard is CheckPropertyWrite at step 4. Every outcome but a clean allow refuses: a kind
// whose PropertyWrite cannot be derived, a guard that cannot be built, a read error (LIVE_REREAD)
// and a refusal verdict. The reason, the declared op and the key names are set on ev (the
// audit-ready refusal record); attribute values and guard error text never are.
func (h *Handler) propertyGuard(ctx context.Context, w WriteOp, c *call, target guid.GUID, ev *Event) *Refusal {
	pw, err := w.PropertyWrite(c.change)
	plane := tier0.PlaneEntra
	if h.prov.Kind() == connectorv1.ProviderKind_PROVIDER_KIND_AD {
		plane = tier0.PlaneAD
	}
	if err != nil || pw.Plane != plane { // a declaration for the other plane is a bug in the kind
		ev.Reason = reasonBadDeclaration
		if err == nil {
			ev.PropertyOp, ev.PropertyKeys = pw.Op.String(), append([]string(nil), pw.Keys...)
		}
		return invalid("4", "PropertyWrite", "change")
	}
	ev.PropertyOp, ev.PropertyKeys = pw.Op.String(), append([]string(nil), pw.Keys...)
	refuse := func(reason string, st connectorv1.Tier0RefusalStage) *Refusal {
		ev.Reason = reason
		return tier0Refusal(toWire(target), []basis{tier0.Designated}, st, "4")
	}
	g, err := h.prov.PropertyGuard(ctx)
	if err != nil || g == nil {
		return refuse(reasonGuardUnavailable, stLive)
	}
	v, err := g.CheckPropertyWrite(ctx, pw)
	if err != nil {
		return refuse(reasonGuardUnavailable, stLive)
	}
	if v.Refused {
		if v.Reason != "" {
			ev.Reason = v.Reason
		}
		if v.Op != 0 {
			ev.PropertyOp = v.Op.String()
		}
		if v.Keys != nil {
			ev.PropertyKeys = append([]string(nil), v.Keys...)
		}
		reason := v.Reason
		if reason == "" {
			reason = tier0.ReasonDesignatedDynamicRule
		}
		if v.Stage == tier0.StageLiveReread {
			return refuse(reason, stLive)
		}
		return refuse(reason, stConnectorSet)
	}
	return nil
}

// stmt is the merge of every complete statement about one object (F1).
type stmt struct {
	peers          []*connectorv1.CorrelatedPeer
	noLink         bool
	hasPeers       bool
	oldest, newest time.Time
	n              int
}

func (h *Handler) index(t0 *connectorv1.Tier0Context) map[string]*stmt {
	idx := map[string]*stmt{}
	for _, s := range t0.GetStatements() {
		id, err := fromWire(s.GetObject())
		if err != nil || s.GetComputedAt() == nil {
			continue // not about a usable object, or computed_at unset: never read as the epoch
		}
		var peers []*connectorv1.CorrelatedPeer
		var noLink, hasPeers bool
		switch c := s.GetCorrelation().(type) {
		case *connectorv1.CorrelationStatement_NoHybridLink:
			noLink = true
		case *connectorv1.CorrelationStatement_Peers:
			hasPeers, peers = true, c.Peers.GetPeers()
		default:
			continue // correlation unset: absence never means "no correlation"
		}
		at := s.GetComputedAt().AsTime()
		m := idx[id.String()]
		if m == nil {
			m = &stmt{oldest: at, newest: at}
			idx[id.String()] = m
		}
		m.n++
		m.noLink = m.noLink || noLink
		m.hasPeers = m.hasPeers || hasPeers
		m.peers = append(m.peers, peers...)
		if at.Before(m.oldest) {
			m.oldest = at
		}
		if at.After(m.newest) {
			m.newest = at
		}
	}
	return idx
}

// statementCheck is F1 (present), F3 (fresh) and the contradiction rule for one touched object.
func (h *Handler) statementCheck(idx map[string]*stmt, id guid.GUID, step string) *Refusal {
	s := idx[id.String()]
	if s == nil {
		return tier0Refusal(toWire(id), nil, stMissing, step)
	}
	now := h.now()
	if now.Sub(s.oldest) > MaxStatementAge || s.newest.Sub(now) > MaxFutureSkew {
		return tier0Refusal(toWire(id), nil, stStale, step)
	}
	if s.noLink && s.hasPeers {
		return tier0Refusal(toWire(id), nil, stContradicted, step)
	}
	return nil
}

func peerConsistent(p *connectorv1.CorrelatedPeer, own connectorv1.ProviderKind) bool {
	switch {
	case p.GetState() == connectorv1.CorrelationState_CORRELATION_STATE_UNSPECIFIED,
		p.GetPeerKind() == connectorv1.ProviderKind_PROVIDER_KIND_UNSPECIFIED,
		p.GetPeerKind() == own,
		p.GetEvidence() == nil || p.GetEvidence().GetEvidence() == nil,
		p.GetPeerTier0() && len(p.GetPeerTier0Basis()) == 0,
		!p.GetPeerTier0() && len(p.GetPeerTier0Basis()) > 0:
		return false
	}
	return true
}

// requestMarks adds the marks of the accepted context to the ratchet (§8.3a) before any decision is
// made on them, whatever the call's outcome. withDesignated adds the context's designations (once,
// at step 4). A failed durable append closes the gate and ends the call.
func (h *Handler) requestMarks(c *call, idx map[string]*stmt, ids []guid.GUID, isAD, withDesignated bool) *Refusal {
	var marks []Mark
	if withDesignated {
		for _, d := range parseGUIDs(c.t0.GetDesignated()) {
			marks = append(marks, Mark{Object: d, Basis: tier0.Designated, Source: "request", Revision: c.t0.GetTier0Revision()})
		}
	}
	own := h.prov.Kind()
	peerBasis := tier0.E5
	if isAD {
		peerBasis = tier0.C16
	}
	for _, id := range ids {
		s := idx[id.String()]
		if s == nil || !fresh(h, s) {
			continue // a missing or stale statement is not accepted, so it adds nothing
		}
		for _, p := range s.peers {
			if p.GetPeerTier0() && peerConsistent(p, own) {
				marks = append(marks, Mark{Object: id, Basis: peerBasis, Source: "request", Revision: c.t0.GetTier0Revision()})
				break
			}
		}
	}
	if err := h.gates.Ratchet(c.conn.GetConnectionId(), marks); err != nil {
		return gateRefusal(connectorv1.WriteGateState_WRITE_GATE_STATE_LOCAL_RECORD_FAILED, nil, 0)
	}
	return nil
}

// fresh is F3 alone (contradiction does not stop a mark from being added).
func fresh(h *Handler, s *stmt) bool {
	now := h.now()
	return now.Sub(s.oldest) <= MaxStatementAge && s.newest.Sub(now) <= MaxFutureSkew
}

// checkRequest is F2 and F5 on the request, then the connector's own set (steps 4 and 6).
func (h *Handler) checkRequest(c *call, idx map[string]*stmt, id guid.GUID, isAD bool, step string) *Refusal {
	s := idx[id.String()]
	if s != nil {
		for _, p := range s.peers {
			if !peerConsistent(p, h.prov.Kind()) { // F5: unknown is tier0
				return tier0Refusal(toWire(id), nil, stRequest, step)
			}
		}
	}
	for _, d := range parseGUIDs(c.t0.GetDesignated()) {
		if d == id {
			return tier0Refusal(toWire(id), []basis{tier0.Designated}, stRequest, step)
		}
	}
	if s != nil {
		for _, p := range s.peers {
			if p.GetPeerTier0() {
				b := tier0.E5
				if isAD {
					b = tier0.C16
				}
				return tier0Refusal(toWire(id), []basis{b}, stRequest, step)
			}
		}
	}
	if b := h.gates.Lookup(c.conn.GetConnectionId(), id); len(b) > 0 {
		return tier0Refusal(toWire(id), b, stConnectorSet, step)
	}
	return nil
}

// live is step 7 for one object: F4 evidence against the re-read anchors, then the classifier.
func (h *Handler) live(ctx context.Context, idx map[string]*stmt, id guid.GUID, designated []guid.GUID) *Refusal {
	if s := idx[id.String()]; s != nil {
		var evidence []*connectorv1.CorrelationEvidence
		for _, p := range s.peers {
			evidence = append(evidence, p.GetEvidence())
		}
		if len(evidence) > 0 {
			a, err := h.prov.Anchors(ctx, id)
			if err != nil {
				return tier0Refusal(toWire(id), nil, stLive, "7")
			}
			for _, ev := range evidence {
				if !a.matches(ev) {
					return tier0Refusal(toWire(id), nil, stContradicted, "7")
				}
			}
		}
	}
	v, err := h.prov.Classify(ctx, id, designated)
	if err != nil || v.Tier0 {
		return tier0Refusal(toWire(id), v.Bases, stLive, "7")
	}
	return nil
}

// afterWrite is step 9 (TM-D23 rule 11): the same live reads on every touched object, after the
// write. A failed re-read lists the object with an empty basis.
func (h *Handler) afterWrite(ctx context.Context, p *passed, ev *Event) []*connectorv1.Tier0Member {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), afterWriteLimit)
	defer cancel()
	designated := p.designated
	var out []*connectorv1.Tier0Member
	for _, id := range p.touched {
		v, err := h.prov.Classify(ctx, id, designated)
		switch {
		case err != nil:
			out = append(out, &connectorv1.Tier0Member{Object: toWire(id)})
		case v.Tier0:
			out = append(out, &connectorv1.Tier0Member{Object: toWire(id), Basis: v.Bases})
		}
	}
	for _, m := range out {
		ev.Tier0AfterWrite = append(ev.Tier0AfterWrite, guidText(m.GetObject()))
	}
	return out
}

func (h *Handler) ignored(t0 *connectorv1.Tier0Context, touched []guid.GUID) int {
	in := map[string]bool{}
	for _, g := range touched {
		in[g.String()] = true
	}
	n := 0
	for _, s := range t0.GetStatements() {
		if g, err := fromWire(s.GetObject()); err != nil || !in[g.String()] {
			n++
		}
	}
	return n
}

func dedupe(target guid.GUID, more []guid.GUID) []guid.GUID {
	seen := map[guid.GUID]bool{target: true}
	out := []guid.GUID{target}
	for _, g := range more {
		if !seen[g] {
			seen[g], out = true, append(out, g)
		}
	}
	return out
}

func parseGUIDs(in []*connectorv1.Guid) []guid.GUID {
	var out []guid.GUID
	for _, g := range in {
		if id, err := fromWire(g); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func guidText(g *connectorv1.Guid) string {
	if id, err := fromWire(g); err == nil {
		return id.String()
	}
	return ""
}

func wireOrNil(b []byte) *connectorv1.Guid {
	if len(b) == 0 {
		return nil
	}
	return &connectorv1.Guid{Value: b}
}

func itoa(n uint32) string { return strconv.FormatUint(uint64(n), 10) }

func unionGUIDs(a, b []guid.GUID) []guid.GUID {
	seen := map[guid.GUID]bool{}
	var out []guid.GUID
	for _, l := range [][]guid.GUID{a, b} {
		for _, id := range l {
			if !seen[id] {
				seen[id], out = true, append(out, id)
			}
		}
	}
	return out
}
