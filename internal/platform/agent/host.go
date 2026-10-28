package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	agentv1 "github.com/skenzeriq/activediq/internal/proto/skenzeriq/agent/v1"
)

// Ceilings are the local limits set at install in a config file the service cannot write
// (agent-host-addc-contract.md §3). A policy can narrow them and never widen them (TM-TB12-T11).
type Ceilings struct {
	OutboxMaxBytes     uint32
	BatchMaxBytes      uint32
	MaxEventsPerSecond uint32
}

// Valid reports whether the ceilings can hold a working agent.
func (c Ceilings) Valid() bool {
	return c.OutboxMaxBytes >= 4*DefaultSegmentBytes && c.BatchMaxBytes >= 4096 && c.BatchMaxBytes <= c.OutboxMaxBytes && c.MaxEventsPerSecond >= 1
}

// EventSink is how a module hands the host an observed event. It is the module's only way out.
type EventSink interface {
	// Append stores the record and returns its sequence. It never blocks on the network and never
	// waits; on a full or failing disk it returns an error and the caller carries on.
	Append(*agentv1.AgentEvent) (uint64, error)
	// Flush makes everything appended so far durable.
	Flush() error
}

// ModuleDeps is the whole of what a module is given: the fixed dependency struct of the contract
// (§1). There is no path, file, process, registry, network or service-control capability in it.
type ModuleDeps struct {
	Events EventSink
	Blobs  *Blobs
	Log    *slog.Logger
	Now    func() time.Time
}

// Module is an agent module (addc today). The host owns its lifecycle and its policy.
type Module interface {
	// Validate checks what only the module knows about a verified policy, such as its compiled-in
	// event catalogue. A policy it rejects is not installed.
	Validate(agentpolicy.AddcPolicy) error
	// Activate puts a policy that passed Validate in force. It must not block.
	Activate(agentpolicy.AddcPolicy) error
	// Start begins work; Stop ends it. Both are bounded by ctx.
	Start(ctx context.Context, d ModuleDeps) error
	Stop(ctx context.Context) error
	// Collection reports what the module is doing, for GetStatus.
	Collection() agentv1.CollectionState
	// Register adds the module's own server-callable service to reg (the tunnel's registrar).
	Register(reg grpc.ServiceRegistrar)
}

// UpdateStager verifies and stages an update. The one TUF verifier (TM-D12) implements it. Until it
// exists the host passes nil, and StageUpdate refuses everything.
type UpdateStager interface {
	Stage(ctx context.Context, metadataBundle, artefactDigest []byte) error
}

// Config configures a Host.
type Config struct {
	Identity fleet.Identity // from the certificate SAN: tenant and kind are never taken from a message
	DataDir  string
	Version  string
	Module   Module
	Ceilings Ceilings
	Logger   *slog.Logger
	// Applied is called after a policy or keyset has been persisted and activated: the local
	// Windows Application-log entry of ADR-0007 decision 8. It must not block.
	Applied func(agentpolicy.Applied)
	// TokenCheckPassed is the result of the start-up privilege check (ADR-0006 decision 3).
	TokenCheckPassed bool
	Updates          UpdateStager
	Now              func() time.Time
}

// Host is the agent host. It implements skenzeriq.agent.v1.Host.
type Host struct {
	agentv1.UnimplementedHostServer
	cfg    Config
	log    *slog.Logger
	now    func() time.Time
	outbox *Outbox
	store  *StateStore
	blobs  *Blobs

	mu       sync.Mutex // serialises policy application; guards v, effective
	v        *agentpolicy.Verifier
	policy   *agentpolicy.AddcPolicy
	stateErr error

	sendMu sync.Mutex
	client agentv1.EventIngestClient
	wake   chan struct{}
}

// Open prepares the data directory, the outbox and the policy store. It starts nothing.
func Open(cfg Config) (*Host, error) {
	if cfg.Module == nil || !cfg.Ceilings.Valid() || cfg.DataDir == "" || cfg.Identity.Tenant.IsZero() || !fleet.ValidKind(cfg.Identity.Kind) {
		return nil, errors.New("agent: incomplete host configuration")
	}
	log, now := cfg.Logger, cfg.Now
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	if err := CheckDataDir(cfg.DataDir); err != nil {
		return nil, fmt.Errorf("agent: data directory is not safe: %w", err)
	}
	ob, err := OpenOutbox(filepath.Join(cfg.DataDir, "outbox"), int64(cfg.Ceilings.OutboxMaxBytes), DefaultSegmentBytes)
	if err != nil {
		return nil, fmt.Errorf("agent: opening outbox: %w", err)
	}
	blobs, err := NewBlobs(filepath.Join(cfg.DataDir, "module"))
	if err != nil {
		_ = ob.Close()
		return nil, err
	}
	store := NewStateStore(cfg.DataDir)
	v, serr := store.Load(cfg.Identity)
	if v == nil {
		_ = ob.Close()
		return nil, serr
	}
	h := &Host{cfg: cfg, log: log, now: now, outbox: ob, store: store, blobs: blobs, v: v, stateErr: serr, wake: make(chan struct{}, 1)}
	if serr != nil {
		log.Error("stored policy state was unreadable and was set aside; waiting for the server to deliver a keyset and a policy")
	}
	if p, ok := v.Installed(); ok {
		h.policy = &p
		h.clampLocked(h.policy)
	}
	return h, nil
}

// Outbox exposes the outbox for tests and the status path.
func (h *Host) Outbox() *Outbox { return h.outbox }

// Register adds Host and the module's service to reg. The tunnel's registrar refuses a method outside
// the bound contract, so registering more than the contract names fails closed.
func (h *Host) Register(reg grpc.ServiceRegistrar) {
	agentv1.RegisterHostServer(reg, h)
	h.cfg.Module.Register(reg)
}

// SetEventClient sets the client the sender uses, or nil while the tunnel is down. Events accumulate
// in the outbox meanwhile.
func (h *Host) SetEventClient(c agentv1.EventIngestClient) {
	h.sendMu.Lock()
	h.client = c
	h.sendMu.Unlock()
	h.poke()
}

func (h *Host) poke() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// Run starts the module with the installed policy (if any) and the sender, and blocks until ctx is
// done. It returns after the module has stopped and the outbox is closed.
func (h *Host) Run(ctx context.Context) error {
	d := ModuleDeps{Events: h.outbox, Blobs: h.blobs, Log: h.log, Now: h.now}
	h.mu.Lock()
	if h.policy != nil {
		if err := h.cfg.Module.Activate(*h.policy); err != nil {
			h.log.Error("installed policy could not be activated", "err", err)
		}
	}
	h.mu.Unlock()
	if err := h.cfg.Module.Start(ctx, d); err != nil {
		_ = h.outbox.Close()
		return fmt.Errorf("agent: starting module: %w", err)
	}
	h.sendLoop(ctx)
	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := h.cfg.Module.Stop(stopCtx)
	if cerr := h.outbox.Close(); err == nil {
		err = cerr
	}
	return err
}

// Fixed answers. They never repeat anything the server sent.
var (
	errRejected    = status.Error(codes.InvalidArgument, "document rejected")
	errNotAnchored = status.Error(codes.FailedPrecondition, "no keyset anchor yet")
	errDenied      = status.Error(codes.PermissionDenied, "document refused")
	errReplay      = status.Error(codes.FailedPrecondition, "sequence is not above the highest accepted")
	errExpired     = status.Error(codes.FailedPrecondition, "document is expired")
	errInternal    = status.Error(codes.Internal, "agent could not persist the document")
	errNoUpdates   = status.Error(codes.FailedPrecondition, "update staging is not available on this agent")
)

func mapVerifyErr(err error) error {
	switch {
	case errors.Is(err, agentpolicy.ErrNotAnchored):
		return errNotAnchored
	case errors.Is(err, agentpolicy.ErrReplay), errors.Is(err, agentpolicy.ErrKeysetReplay):
		return errReplay
	case errors.Is(err, agentpolicy.ErrExpired):
		return errExpired
	case errors.Is(err, agentpolicy.ErrWrongTenant), errors.Is(err, agentpolicy.ErrWrongKind),
		errors.Is(err, agentpolicy.ErrUnknownKey), errors.Is(err, agentpolicy.ErrBadSignature),
		errors.Is(err, agentpolicy.ErrUnknownSigner), errors.Is(err, agentpolicy.ErrAlreadyAnchored):
		return errDenied
	}
	return errRejected
}

const maxDocBytes = agentpolicy.MaxBannedBytes + 256<<10

// clone copies the verifier through its snapshot, so a refused document changes nothing.
func (h *Host) cloneLocked() (*agentpolicy.Verifier, error) {
	snap, err := h.v.Snapshot()
	if err != nil {
		return nil, err
	}
	return agentpolicy.RestoreVerifier(h.cfg.Identity.Tenant, h.cfg.Identity.Kind, snap)
}

// clampLocked narrows a policy to the local ceilings (batch and outbox sizes). Events per second above
// the ceiling are rejected by checkCeilings before this runs on a new policy.
func (h *Host) clampLocked(p *agentpolicy.AddcPolicy) {
	c := h.cfg.Ceilings
	p.Events.BatchMaxBytes = min(p.Events.BatchMaxBytes, c.BatchMaxBytes)
	p.Events.OutboxMaxBytes = min(p.Events.OutboxMaxBytes, c.OutboxMaxBytes)
	p.Events.BatchMaxBytes = min(p.Events.BatchMaxBytes, p.Events.OutboxMaxBytes)
	h.outbox.SetMaxBytes(int64(p.Events.OutboxMaxBytes))
}

func (h *Host) checkCeilings(p agentpolicy.AddcPolicy) error {
	if p.Events.MaxEventsPerSecond > h.cfg.Ceilings.MaxEventsPerSecond {
		return errors.New("events.max_events_per_second above the local ceiling")
	}
	return nil
}

// ApplyPolicy implements Host.
func (h *Host) ApplyPolicy(ctx context.Context, req *agentv1.ApplyPolicyRequest) (*agentv1.ApplyPolicyResponse, error) {
	doc := req.GetSigned().GetDocument()
	if len(doc) == 0 || len(doc) > maxDocBytes {
		return nil, errRejected
	}
	sp, err := agentpolicy.ParseSignedPolicy(doc)
	if err != nil {
		return nil, errRejected
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	next, err := h.cloneLocked()
	if err != nil {
		return nil, errInternal
	}
	var applied agentpolicy.Applied
	next.OnApplied = func(a agentpolicy.Applied) { applied = a }
	pol, err := next.ApplyPolicy(sp, h.now())
	if err != nil {
		return nil, mapVerifyErr(err)
	}
	if err := h.checkCeilings(pol); err != nil {
		return nil, errRejected
	}
	if err := h.cfg.Module.Validate(pol); err != nil {
		return nil, errRejected
	}
	if err := h.store.Save(h.cfg.Identity, next); err != nil {
		h.log.Error("policy not persisted; not activated", "err", err)
		return nil, errInternal
	}
	h.v = next
	h.policy = &pol
	h.clampLocked(h.policy)
	if err := h.cfg.Module.Activate(*h.policy); err != nil {
		h.log.Error("policy persisted but the module could not activate it", "err", err)
	}
	h.recordApplied(applied)
	return &agentv1.ApplyPolicyResponse{PolicySeq: sp.Header.Seq, KeyId: sp.Header.KeyID}, nil
}

// ApplyKeyset implements Host. The first keyset after enrolment is the anchor; later ones must be
// signed by a key already held.
func (h *Host) ApplyKeyset(ctx context.Context, req *agentv1.ApplyKeysetRequest) (*agentv1.ApplyKeysetResponse, error) {
	doc := req.GetSigned().GetDocument()
	if len(doc) == 0 || len(doc) > 64<<10 {
		return nil, errRejected
	}
	sk, err := agentpolicy.ParseSignedKeyset(doc)
	if err != nil {
		return nil, errRejected
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	next, err := h.cloneLocked()
	if err != nil {
		return nil, errInternal
	}
	var applied agentpolicy.Applied
	next.OnApplied = func(a agentpolicy.Applied) { applied = a }
	anchoring := h.v.KeysetSeq() == 0
	if anchoring {
		err = next.Anchor(sk)
	} else {
		err = next.ApplyKeyset(sk)
	}
	if err != nil {
		return nil, mapVerifyErr(err)
	}
	if err := h.store.Save(h.cfg.Identity, next); err != nil {
		h.log.Error("keyset not persisted", "err", err)
		return nil, errInternal
	}
	h.v = next
	h.recordApplied(applied)
	return &agentv1.ApplyKeysetResponse{KeysetSeq: sk.Seq, AnchoredNow: anchoring}, nil
}

// recordApplied writes the local trace of ADR-0007 decision 8: what was applied, never its content.
func (h *Host) recordApplied(a agentpolicy.Applied) {
	h.log.Info("applied", "what", a.What, "seq", a.Seq, "key_id", a.KeyID, "body_digest", fmt.Sprintf("%x", a.BodyHash[:]))
	if h.cfg.Applied != nil {
		h.cfg.Applied(a)
	}
}

// GetStatus implements Host.
func (h *Host) GetStatus(context.Context, *agentv1.GetStatusRequest) (*agentv1.GetStatusResponse, error) {
	h.mu.Lock()
	anchored, pseq, kseq := h.v.KeysetSeq() > 0, h.v.PolicySeq(), h.v.KeysetSeq()
	h.mu.Unlock()
	st := h.outbox.Stats()
	return &agentv1.GetStatusResponse{
		AgentVersion: h.cfg.Version, Anchored: anchored, PolicySeq: pseq, KeysetSeq: kseq,
		Collection: h.cfg.Module.Collection(), TokenCheckPassed: h.cfg.TokenCheckPassed,
		OutboxRecords: st.Records, OutboxBytes: st.Bytes, OutboxDroppedRecords: st.Dropped,
		LastAgentSeq: st.LastSeq, AckedThroughSeq: st.AckedThrough,
	}, nil
}

// AckEvents implements Host.
func (h *Host) AckEvents(_ context.Context, req *agentv1.AckEventsRequest) (*agentv1.AckEventsResponse, error) {
	h.outbox.Ack(req.GetThroughAgentSeq())
	return &agentv1.AckEventsResponse{OutboxRecords: h.outbox.Stats().Records}, nil
}

// StageUpdate implements Host. It stages only what the one TUF verifier accepts (TM-D12); without it
// nothing is staged. There is no path from this RPC to running anything.
func (h *Host) StageUpdate(ctx context.Context, req *agentv1.StageUpdateRequest) (*agentv1.StageUpdateResponse, error) {
	if h.cfg.Updates == nil {
		return nil, errNoUpdates
	}
	if len(req.GetMetadataBundle()) == 0 || len(req.GetMetadataBundle()) > 1<<20 || len(req.GetArtefactDigest()) != 32 {
		return nil, errRejected
	}
	if err := h.cfg.Updates.Stage(ctx, req.GetMetadataBundle(), req.GetArtefactDigest()); err != nil {
		return nil, errDenied
	}
	return &agentv1.StageUpdateResponse{Staged: true}, nil
}
