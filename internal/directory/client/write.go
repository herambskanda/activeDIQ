package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/accountkind"
	"github.com/skenzeriq/activediq/internal/directory/writechange"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/secret"
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
	ErrDCMismatch     = errors.New("client: plan precondition names a DC other than the pinned one; apply refused")
	ErrNoDSAPin       = errors.New("client: step pins no DSA GUID for the naming context; write refused")
	ErrTransport      = errors.New("client: connector call failed")
	ErrKindAttrs      = errors.New("client: operation attributes are not the kind's; write refused")
	ErrKindClass      = errors.New("client: target class is not one the kind allows; write refused")
	ErrNoSecret       = errors.New("client: the step carries no secret input for this kind; write refused")
	ErrNotCanonical   = errors.New("client: target or naming context is not canonical lower-case UUID text; write refused")
)

// WriteOp is one planned directory write, as the Action's Apply hands it over. The Step authorises
// exactly the write whose digest it carries; Write recomputes the digest from DigestKind, Target and
// Attrs and refuses a mismatch. Everything that goes on the wire is derived from these fields: the
// connection from Target.Connection, the object from Target.GUID (the planned parent for a create),
// the naming context from the Step (Target.NC, digest-covered), the
// WriteKind from DigestKind through kindTable. No wire field is caller-supplied, so none can differ from what the digest covers. The WriteChange is derived from Attrs by one constructor per
// kind (objectchange.go), never filled in by the caller.
type WriteOp struct {
	// DigestKind names the operation in the plan digest ("user.setAttribute").
	DigestKind string
	Target     authority.TargetRef
	Attrs      []step.Attr
	// SecretInput is the password of an OBJECT_CREATE of a USER whose Attrs carry "~secret" (presence
	// only). It must be non-empty exactly then, goes into ApplyRequest.secret_input only, is never in
	// the digest and is zeroed after the send.
	SecretInput secret.Secret
}

// The plan-digest keys of the wired kinds (contract §8.10.1). Compile-time constants; the connector
// holds the same strings (write.DigestObject*) and a test pins the two.
const (
	DigestObjectMove    = "ad.object.move"
	DigestObjectRename  = "ad.object.rename"
	DigestObjectRestore = "ad.object.restore"
)

// The attribute names the object kinds' digests cover (contract §8.10.2 rule 5).
const (
	AttrNewParent   = "newParent"
	AttrNewParentNC = "newParentNC"
	AttrNewRDN      = "newRDN"
	AttrRDN         = "rdn"
)

// ClassMove is the TM-D28 class of the object move, rename and restore kinds.
const ClassMove = "move"

// kindRow is one registered kind: the connector WriteKind and its TM-D28 class ("none" when the kind
// is outside every class). A row without a class is refused by TestKindTableClosed.

// structureKind is true for the object move, rename and restore digest kinds (T-1624): their change comes from
// op.change, not from writechange or accountkind.
func structureKind(k string) bool {
	return k == DigestObjectMove || k == DigestObjectRename || k == DigestObjectRestore
}

type kindRow struct {
	Kind  connectorv1.WriteKind
	Class string
}

// kindTable maps a plan-digest kind to the connector's WriteKind (contract §8.10.2). Each kind ticket
// adds its row together with its writechange codec and its operation-table row; every key not in the
// table is refused as an unknown kind before any transport call.
var kindTable = map[string]kindRow{
	writechange.KeyObjectCreate: {Kind: connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, Class: "none"},
	writechange.KeyObjectUpdate: {Kind: connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE, Class: "attributes"},
	writechange.KeyObjectDelete: {Kind: connectorv1.WriteKind_WRITE_KIND_OBJECT_DELETE, Class: "none"},
	DigestObjectMove:            {Kind: connectorv1.WriteKind_WRITE_KIND_OBJECT_MOVE, Class: ClassMove},
	DigestObjectRename:          {Kind: connectorv1.WriteKind_WRITE_KIND_OBJECT_RENAME, Class: ClassMove},
	DigestObjectRestore:         {Kind: connectorv1.WriteKind_WRITE_KIND_OBJECT_RESTORE, Class: ClassMove},
}

// kindClass is the TM-D28 class of each registered kind ("none" for a tightening, contract §8.10.1).
// A kind in kindTable without a class here is refused at init (TM §6.9 rule 4).
var kindClass = map[string]string{
	accountkind.KeyResetPassword: "reset_password",
	accountkind.KeyUnlock:        "unlock",
	accountkind.KeyEnable:        "enable",
	accountkind.KeyDisable:       "none",
}

func init() {
	for _, sp := range accountkind.Specs() {
		if _, ok := kindClass[sp.Key]; !ok {
			panic("client: kind registered without a TM-D28 class: " + sp.Key)
		}
		kindTable[sp.Key] = kindRow{Kind: sp.Kind, Class: kindClass[sp.Key]}
	}
}

// wire is the request material derived from a validated WriteOp.
type wire struct {
	conn   *connectorv1.ConnectionRef
	target *connectorv1.WriteTarget
	kind   connectorv1.WriteKind
	// change is the typed change derived from the digested Attrs; nil for a kind with no arm yet.
	change *connectorv1.WriteChange
	// secret is set for a kind whose Apply carries secret_input (reset password).
	secret bool
	// hasSecret is set for a create that carries the new account's password in op.SecretInput.
	hasSecret bool
}

// Result is what a completed Write returns.
type Result struct {
	// NoOp: Plan found the target already in the requested state; nothing was sent to Apply.
	NoOp  bool
	Apply *connectorv1.ApplyResponse
}

// Tier0AfterWrite returns the connector's step-9 report as findings: each object by canonical GUID
// text with its bases (C1..C11 and so on), an empty Bases meaning unclassified. An object whose GUID
// is unusable is still reported, by an empty Object, because the report counts whatever it lists.
func (r Result) Tier0AfterWrite() []step.Tier0Finding {
	var out []step.Tier0Finding
	for _, m := range r.Apply.GetTier0AfterWrite() {
		f := step.Tier0Finding{}
		if v := m.GetObject().GetValue(); len(v) == 16 {
			f.Object = formatUUID(v)
		}
		for _, b := range m.GetBasis() {
			f.Bases = append(f.Bases, basisName(b))
		}
		out = append(out, f)
	}
	return out
}

// basisName is "C2" for TIER0_BASIS_C2_PROTECTED_GROUP_MEMBER.
func basisName(b connectorv1.Tier0Basis) string {
	n := strings.TrimPrefix(b.String(), "TIER0_BASIS_")
	if i := strings.IndexByte(n, '_'); i > 0 {
		return n[:i]
	}
	return n
}

// Client is the write path. Build it with New; the zero Client refuses every write.
type Client struct {
	transport Transport
	facts     FactsReader
	tier0     Tier0Builder
	verify    VerifyTransport
	scope     VerifyScopeSource
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
	defer op.SecretInput.Destroy() // on every exit, a refused op included
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
	if err := op.deriveChange(&w); err != nil {
		return Result{}, err
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
	if string(dsaID) == string(make([]byte, len(dsaID))) {
		return Result{}, fmt.Errorf("%w: nil DSA GUID", ErrNoDSAPin)
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
		Connection: w.conn, Step: key, Target: w.target, Kind: w.kind, Change: w.change,
		Tier0: t0.Context, Tier0Override: t0.Override, ActingPrincipal: acting,
		Dc: &connectorv1.DcSelection{PinnedDsaGuid: &connectorv1.Guid{Value: dsaID}},
	})
	if err != nil {
		return Result{}, err
	}
	if plan.GetNoOp() {
		return Result{NoOp: true}, nil
	}

	// Rule 5: Apply goes only to the DC Plan read from, and that is the pinned one. A connector that
	// planned elsewhere is refused here, before anything is sent.
	if !bytes.Equal(plan.GetPrecondition().GetDc().GetDsaGuid().GetValue(), dsaID) {
		return Result{}, ErrDCMismatch
	}

	t0, err = c.buildTier0(ctx, StageApply, op)
	if err != nil {
		return Result{}, err
	}
	d := s.Digest()
	areq := &connectorv1.ApplyRequest{
		Connection: w.conn, Step: key, Attempt: uint32(s.Attempt()), Target: w.target,
		Kind: w.kind, Change: w.change, Tier0: t0.Context, Precondition: plan.GetPrecondition(),
		Tier0Override: t0.Override, ActingPrincipal: acting, PlanDigest: d[:],
	}
	if w.secret {
		sv, err := secretInput(s)
		if err != nil {
			return Result{}, err
		}
		areq.SecretInput = sv
		defer clear(sv.Material) // the copy this call made; the step's own secret is the runner's to destroy
	}
	if w.hasSecret {
		var sec *connectorv1.SecretValue
		op.SecretInput.Expose(func(b []byte) { sec = &connectorv1.SecretValue{Material: append([]byte(nil), b...)} })
		if sec != nil {
			areq.SecretInput = sec
			defer clear(sec.Material) // wipe the wire copy on every exit path
		}
	}
	resp, err := c.sendApply(ctx, clr, s, areq)
	if err != nil {
		return Result{}, err
	}
	return Result{Apply: resp}, nil
}

func (op WriteOp) derive() (wire, error) {
	if op.DigestKind == "" || op.Target.Connection == "" {
		return wire{}, ErrInvalidOp
	}
	row, ok := kindTable[op.DigestKind]
	if !ok || row.Kind == connectorv1.WriteKind_WRITE_KIND_UNSPECIFIED {
		return wire{}, ErrUnknownKind
	}
	kind := row.Kind
	var change *connectorv1.WriteChange
	hasSecret := false
	_, account := accountkind.ByKey(op.DigestKind)
	switch {
	case account:
		// The account kinds (T-1583) have their own change codec, class label and secret rule, applied by
		// deriveChange.
	case structureKind(op.DigestKind):
		// Kinds 4-6 (T-1624): the change comes from op.change; the connector reads the class live.
		var err error
		change, err = op.change(kind)
		if err != nil {
			return wire{}, err
		}
	default:
		// The object create, update and delete kinds (T-1623) are decoded here.
		var err error
		change, err = writechange.Decode(op.DigestKind, op.Attrs)
		if err != nil {
			return wire{}, fmt.Errorf("%w: change", ErrInvalidOp)
		}
		// Canonical (lower-case) identifiers only: the connector recomputes the digest from the wire
		// fields, so a different spelling of the same GUID would never match.
		for _, id := range []string{op.Target.GUID, op.Target.Parent, string(op.Target.NC)} {
			if id != strings.ToLower(id) {
				return wire{}, fmt.Errorf("%w: identifier is not canonical", ErrInvalidOp)
			}
		}
		if kind != connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE && op.Target.Class != "" {
			return wire{}, fmt.Errorf("%w: class is read live", ErrInvalidOp)
		}
		if cc := change.GetObjectCreate(); cc != nil {
			hasSecret = cc.GetHasSecretInput()
		}
		if hasSecret == op.SecretInput.IsEmpty() {
			return wire{}, fmt.Errorf("%w: secret input", ErrInvalidOp)
		}
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
	return wire{conn: &connectorv1.ConnectionRef{ConnectionId: op.Target.Connection}, target: wt, kind: kind, change: change, hasSecret: hasSecret}, nil
}

// deriveChange fills the typed change of a kind that has an arm (the account kinds). The change comes
// from the digested Attrs by accountkind.ChangeFromAttrs, which the connector inverts, and the class
// label and UUID texts must be the forms the connector recomputes the digest with: an op the
// connector could not verify is refused here, before any transport call.
func (op WriteOp) deriveChange(w *wire) error {
	sp, ok := accountkind.ByKey(op.DigestKind)
	if !ok {
		return nil
	}
	if !sp.AllowsClass(op.Target.Class) {
		return ErrKindClass
	}
	if !accountkind.Canonical(op.Target.GUID) || !accountkind.Canonical(string(op.Target.NC)) || op.Target.Parent != "" || op.Target.RDN != "" {
		return ErrNotCanonical
	}
	ch, err := accountkind.ChangeFromAttrs(op.DigestKind, op.Attrs)
	if err != nil {
		return ErrKindAttrs
	}
	w.change = ch
	w.secret = op.DigestKind == accountkind.KeyResetPassword
	return nil
}

// secretInput copies the step's transient secret into the wire message. It is never logged, and the
// caller zeroes the copy once the call returns.
func secretInput(s step.Step) (*connectorv1.SecretValue, error) {
	sec := s.Secret()
	if sec.IsEmpty() {
		return nil, ErrNoSecret
	}
	var b []byte
	sec.Expose(func(x []byte) { b = append([]byte(nil), x...) })
	return &connectorv1.SecretValue{Material: b}, nil
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
