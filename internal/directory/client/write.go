package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Errors of the write path. None carries a plan value, a DN or a directory response.
var (
	ErrNoTier0Builder = errors.New("client: no Tier0Context builder wired; write refused")
	ErrNoTransport    = errors.New("client: no connector transport wired; write refused")
	ErrNoFacts        = errors.New("client: no live facts reader wired; write refused")
	ErrNoTier0        = errors.New("client: Tier0Context builder returned no context; write refused")
	ErrDigest         = errors.New("client: operation does not match the step's plan digest")
	ErrInvalidOp      = errors.New("client: invalid write operation")
	ErrBadResponse    = errors.New("client: connector answered with an unusable response")
	ErrUnknownKind    = errors.New("client: write kind is not registered; write refused")
	ErrNoNC           = errors.New("client: step binds no naming context; write refused")
	ErrNoDCPin        = errors.New("client: step has no DC pin for the naming context; write refused")
	ErrNoDSAPin       = errors.New("client: step pins no DSA GUID for the naming context; write refused")
	ErrTransport      = errors.New("client: connector call failed")
)

// WriteOp is one planned directory write, as the Action's Apply hands it over. The Step authorises
// exactly the write whose digest it carries; Write recomputes the digest from DigestKind, Target and
// Attrs and refuses a mismatch. Everything that goes on the wire is derived from these fields: the
// connection from Target.Connection, the object from Target.GUID (the planned parent for a create),
// the naming context from the Step (Target.NC, digest-covered), the
// WriteKind from DigestKind through kindTable. No wire field is caller-supplied, so none can differ from what the digest covers. WriteChange has no arm until a
// kind ticket adds one with a constructor deriving it from Attrs; until then Change is never sent.
type WriteOp struct {
	// DigestKind names the operation in the plan digest ("user.setAttribute").
	DigestKind string
	Target     authority.TargetRef
	Attrs      []step.Attr
}

// kindTable maps a plan-digest kind to the connector's WriteKind. Each kind ticket adds its row;
// until one does, every write is refused as an unknown kind.
var kindTable = map[string]connectorv1.WriteKind{}

// wire is the request material derived from a validated WriteOp.
type wire struct {
	conn   *connectorv1.ConnectionRef
	target *connectorv1.WriteTarget
	kind   connectorv1.WriteKind
}

// Result is what a completed Write returns.
type Result struct {
	// NoOp: Plan found the target already in the requested state; nothing was sent to Apply.
	NoOp  bool
	Apply *connectorv1.ApplyResponse
}

// Client is the write path. Build it with New; the zero Client refuses every write.
type Client struct {
	transport Transport
	facts     FactsReader
	tier0     Tier0Builder
}

// Option wires one dependency of the Client.
type Option func(*Client)

// WithTransport wires the connector transport.
func WithTransport(t Transport) Option { return func(c *Client) { c.transport = t } }

// WithFacts wires the live facts reader.
func WithFacts(f FactsReader) Option { return func(c *Client) { c.facts = f } }

// WithTier0Builder wires the Tier0Context builder (T-0109).
func WithTier0Builder(b Tier0Builder) Option { return func(c *Client) { c.tier0 = b } }

// New returns a Client.
func New(opts ...Option) *Client {
	c := &Client{}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Facts implements operation.LiveFacts structurally by delegating to the wired FactsReader.
func (c *Client) Facts(ctx context.Context, pins authority.Pins, q authority.FactsQuery) (authority.Facts, error) {
	if c.facts == nil {
		return authority.Facts{}, ErrNoFacts
	}
	return c.facts.Facts(ctx, pins, q)
}

// Write sends one planned write: Plan, then Apply, each carrying a freshly built Tier0Context. It
// refuses, before any transport call, a zero or revoked Step, an operation that is not the one the
// Step's digest covers, and a Client with no builder, facts reader or transport. It reads the live
// facts the Step names, runs the Step's authorisation re-check, and sends only with the Clearance
// that issues.
func (c *Client) Write(ctx context.Context, s step.Step, op WriteOp) (Result, error) {
	if err := s.Valid(); err != nil {
		return Result{}, err
	}
	w, err := op.derive()
	if err != nil {
		return Result{}, err
	}
	if step.Compute(op.DigestKind, op.Target, op.Attrs) != s.Digest() || op.Target.NC != s.NC() {
		return Result{}, ErrDigest
	}
	// The NC comes from the Step, not the caller. Every write needs one until an Entra kind declares
	// itself (no such kind exists); an empty NC never falls back to an unpinned write.
	nc := s.NC()
	if nc == "" {
		return Result{}, ErrNoNC
	}
	ncb, err := parseUUID(string(nc))
	if err != nil {
		return Result{}, fmt.Errorf("%w: naming context", ErrInvalidOp)
	}
	w.target.NcGuid = &connectorv1.Guid{Value: ncb}
	switch {
	case c.tier0 == nil:
		return Result{}, ErrNoTier0Builder
	case c.facts == nil:
		return Result{}, ErrNoFacts
	case c.transport == nil:
		return Result{}, ErrNoTransport
	}
	key, err := stepKey(s.Key())
	if err != nil {
		return Result{}, err
	}
	acting, err := actingPrincipal(s.Actor())
	if err != nil {
		return Result{}, err
	}

	host, ok := s.DC(nc)
	if !ok || host == "" {
		return Result{}, ErrNoDCPin
	}
	dsa, ok := s.DSA(nc)
	if !ok {
		return Result{}, ErrNoDSAPin // rule 5: a host alone is not enforceable by the connector; never fall back to unpinned
	}
	dsaID, err := parseUUID(dsa)
	if err != nil {
		return Result{}, fmt.Errorf("%w: DSA GUID is not a GUID", ErrNoDSAPin)
	}
	pins := authority.Pins{nc: host}
	facts, err := c.facts.Facts(ctx, pins, s.FactsQuery())
	if err != nil {
		return Result{}, fmt.Errorf("client: reading live facts: %w", err)
	}
	clr, err := s.Recheck(ctx, facts)
	if err != nil {
		return Result{}, err
	}

	t0, err := c.buildTier0(ctx, StagePlan, op)
	if err != nil {
		return Result{}, err
	}
	plan, err := c.sendPlan(ctx, clr, s, &connectorv1.PlanRequest{
		Connection: w.conn, Step: key, Target: w.target, Kind: w.kind,
		Tier0: t0.Context, Tier0Override: t0.Override, ActingPrincipal: acting,
		Dc: &connectorv1.DcSelection{PinnedDsaGuid: &connectorv1.Guid{Value: dsaID}},
	})
	if err != nil {
		return Result{}, err
	}
	if plan.GetNoOp() {
		return Result{NoOp: true}, nil
	}

	t0, err = c.buildTier0(ctx, StageApply, op)
	if err != nil {
		return Result{}, err
	}
	d := s.Digest()
	resp, err := c.sendApply(ctx, clr, s, &connectorv1.ApplyRequest{
		Connection: w.conn, Step: key, Attempt: uint32(s.Attempt()), Target: w.target,
		Kind: w.kind, Tier0: t0.Context, Precondition: plan.GetPrecondition(),
		Tier0Override: t0.Override, ActingPrincipal: acting, PlanDigest: d[:],
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Apply: resp}, nil
}

func (op WriteOp) derive() (wire, error) {
	if op.DigestKind == "" || op.Target.Connection == "" {
		return wire{}, ErrInvalidOp
	}
	kind, ok := kindTable[op.DigestKind]
	if !ok || kind == connectorv1.WriteKind_WRITE_KIND_UNSPECIFIED {
		return wire{}, ErrUnknownKind
	}
	obj := op.Target.GUID
	if obj == "" {
		obj = op.Target.Parent // a create targets the planned parent container
	}
	id, err := parseUUID(obj)
	if err != nil {
		return wire{}, fmt.Errorf("%w: target object", ErrInvalidOp)
	}
	wt := &connectorv1.WriteTarget{Object: &connectorv1.Guid{Value: id}}
	return wire{conn: &connectorv1.ConnectionRef{ConnectionId: op.Target.Connection}, target: wt, kind: kind}, nil
}

func (c *Client) buildTier0(ctx context.Context, st Stage, op WriteOp) (Tier0, error) {
	t0, err := c.tier0.Build(ctx, st, op)
	if err != nil {
		return Tier0{}, fmt.Errorf("client: building Tier0Context at %s: %w", st, err)
	}
	if t0.Context == nil {
		return Tier0{}, ErrNoTier0
	}
	return t0, nil
}

// sanitize keeps a connector's message text, which can carry a DN or directory text, out of every
// error callers log: a ConnectorError becomes the code-only RemoteError, anything else a fixed
// error that still unwraps to the cause for MapError.
func sanitize(err error) error {
	if re := new(RemoteError); errors.As(FromStatus(err), &re) && re.Err != nil {
		return re
	}
	return &transportError{cause: err}
}

type transportError struct{ cause error }

func (e *transportError) Error() string   { return ErrTransport.Error() }
func (e *transportError) Unwrap() error   { return e.cause }
func (e *transportError) Is(t error) bool { return t == ErrTransport }

// sendPlan and sendApply are the only functions that call the connector's write RPCs. Each checks
// the Clearance against the step's key and digest on the way to the wire (O2).
func (c *Client) sendPlan(ctx context.Context, clr step.Clearance, s step.Step, req *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	if err := clr.Check(s.Key(), s.Digest()); err != nil {
		return nil, err
	}
	resp, err := c.transport.Plan(ctx, req)
	if err != nil {
		return nil, sanitize(err)
	}
	if resp == nil {
		return nil, ErrBadResponse
	}
	return resp, nil
}

func (c *Client) sendApply(ctx context.Context, clr step.Clearance, s step.Step, req *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	if err := clr.Check(s.Key(), s.Digest()); err != nil {
		return nil, err
	}
	resp, err := c.transport.Apply(ctx, req)
	if err != nil {
		return nil, sanitize(err)
	}
	if resp == nil {
		return nil, ErrBadResponse
	}
	return resp, nil
}

func stepKey(k step.Key) (*connectorv1.StepKey, error) {
	id, err := parseUUID(string(k.Operation))
	if err != nil || k.Item < 0 || k.Step < 0 {
		return nil, fmt.Errorf("%w: step key", ErrInvalidOp)
	}
	return &connectorv1.StepKey{OperationId: &connectorv1.Guid{Value: id}, Item: uint32(k.Item), Step: uint32(k.Step)}, nil
}

// actingPrincipal derives the wire principal from the Step's chain, never from the caller: the
// requester is the account, the innermost API-token principal (if any) is the token.
func actingPrincipal(ch authority.Chain) (*connectorv1.ActingPrincipal, error) {
	acc, err := parseUUID(string(ch.Requester.ID))
	if err != nil {
		return nil, fmt.Errorf("%w: acting principal", ErrInvalidOp)
	}
	ap := &connectorv1.ActingPrincipal{AccountId: &connectorv1.Guid{Value: acc}}
	for _, p := range ch.Via {
		if p.Kind != authority.APIToken {
			continue
		}
		tok, err := parseUUID(string(p.ID))
		if err != nil {
			return nil, fmt.Errorf("%w: acting principal", ErrInvalidOp)
		}
		ap.ApiTokenId = &connectorv1.Guid{Value: tok}
	}
	return ap, nil
}

// parseUUID parses the canonical 8-4-4-4-12 form into 16 RFC 4122-order bytes.
func parseUUID(s string) ([]byte, error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return nil, errors.New("not a uuid")
	}
	out := make([]byte, 0, 16)
	for i := 0; i < len(s); {
		if s[i] == '-' {
			i++
			continue
		}
		hi, ok1 := unhex(s[i])
		lo, ok2 := unhex(s[i+1])
		if !ok1 || !ok2 {
			return nil, errors.New("not a uuid")
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return out, nil
}

func unhex(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}
