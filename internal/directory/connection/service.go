package connection

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Audit kinds this service emits, registered by the owner of the lifecycle (EP-7). None carries a
// finding, an object GUID, a SID, a qualifier or a fingerprint (DM-24.I5): they name run IDs, the
// verdict, each check's outcome, a count and a salted digest.
const (
	AuditVerificationCompleted audit.Kind = "connection.verification.completed"
	AuditActivated             audit.Kind = "connection.activated"
	AuditCredentialChanged     audit.Kind = "connection.credential.changed"
	AuditVerdictChanged        audit.Kind = "connection.rights.verdict_changed"
)

// ErrRunInterrupted: the connector did not return a completed result. The run is recorded as failed
// (DM-10.I10) and the connection is where it was.
var ErrRunInterrupted = errors.New("connection: verification run did not complete")

// Service runs verifications against a directory and applies their result to the registry: the
// activation gate (DM-10.I9), the audited scheduled health check and the clearing of an override. It
// is the orchestration the `connections` module's Actions and jobs call; the SQL is the Store's.
//
// Every state change and every recorded run commits together with its audit event, so an
// unaudited change cannot exist.
type Service struct {
	reg    *Registry
	client ConnectorClient
	sink   audit.Sink
	now    func() time.Time
	sched  Scheduler
}

// NewService binds the registry, the connector client and the audit sink. All three are required: a
// service without a sink would change state with no trail.
func NewService(reg *Registry, client ConnectorClient, sink audit.Sink, opts ...Option) (*Service, error) {
	if reg == nil || reg.db == nil || client == nil || sink == nil {
		return nil, fmt.Errorf("%w: service needs a registry, a connector client and an audit sink", ErrInvalid)
	}
	sv := &Service{reg: reg, client: client, sink: sink, now: time.Now}
	for _, o := range opts {
		o(sv)
	}
	return sv, nil
}

// VerifyOutcome is a recorded run. Findings are filled; the caller shows them only to an account that
// may start a verification on the connection (FR-16).
type VerifyOutcome struct {
	Connection   Connection
	Verification Verification
}

// Activate presses Activate (spec L4). If the connection's newest run is fresh and qualifies it
// activates at once; otherwise it runs a verification (draft → verifying), records it, and the
// connection becomes active only if that run qualifies (a pass, or an over-privilege-only refusal
// covered by the override in force) and returns to draft otherwise. The recorded run, with its
// excessive and missing findings, is returned either way; a refusal also returns *ActivationError.
func (s *Service) Activate(ctx context.Context, tid tenant.ID, id ID, actor authority.Chain) (VerifyOutcome, error) {
	if err := actor.Validate(); err != nil {
		return VerifyOutcome{}, err
	}
	var fast VerifyOutcome
	err := s.reg.with(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		c, err := s.reg.s.Activate(ctx, tx, id)
		if err != nil {
			return err
		}
		fast.Connection = c
		if c.LastVerificationID != "" {
			if fast.Verification, err = getVerification(ctx, tx, c.ID, VerificationID(c.LastVerificationID), true); err != nil {
				return err
			}
		}
		if err := s.sink.Append(ctx, tx, s.activatedEvent(actor, c, fast.Verification.ID, audit.Success, "")); err != nil {
			return err
		}
		return s.schedule(ctx, tx, tid)
	})
	if err == nil {
		return fast, nil
	}
	var ae *ActivationError
	if !errors.As(err, &ae) || ae.Code == ReasonWrongState {
		return VerifyOutcome{}, err
	}
	// No qualifying fresh result: Activate starts a run of kind activation.
	return s.run(ctx, tid, id, KindActivation, actor)
}

// Verify runs a verification that does not activate. KindOnboarding starts from a draft and ends
// back in draft (DM-10.I10); KindManual and KindScheduled run on an active or suspended connection
// as a job and leave the lifecycle state alone (spec L11). It records the run and returns it.
func (s *Service) Verify(ctx context.Context, tid tenant.ID, id ID, kind VerificationKind, actor authority.Chain) (VerifyOutcome, error) {
	if err := actor.Validate(); err != nil {
		return VerifyOutcome{}, err
	}
	switch kind {
	case KindOnboarding, KindManual, KindScheduled:
	default:
		return VerifyOutcome{}, fmt.Errorf("%w: run kind %q is not started through Verify", ErrInvalid, kind)
	}
	return s.run(ctx, tid, id, kind, actor)
}

// ClearOverride is the "revoke" of a Tier-0 override: it re-runs the check. DM-25.I5 has no undo, so
// the override ends only when the run finds the over-privilege check at pass, which is when the
// operator has removed the rights. If they are still there, the override stays in force and the
// banner stays (FR-14); nothing is withdrawn by pressing a button.
func (s *Service) ClearOverride(ctx context.Context, tid tenant.ID, id ID, actor authority.Chain) (Health, error) {
	if _, err := s.Verify(ctx, tid, id, KindManual, actor); err != nil {
		return Health{}, err
	}
	return s.reg.Health(ctx, tid, id, false, s.now())
}

// ScheduledResult is the result for one connection of RunScheduled.
type ScheduledResult struct {
	Connection ID
	Outcome    VerifyOutcome
	Err        error
}

// RunScheduled is the scheduled health check of one tenant: it verifies every active connection, one
// at a time so the domain controllers are not hit in parallel, and records the excessive and missing
// findings of each. A connection whose run fails does not stop the others, and is never retried
// here: a permissions error must not become a hang against a DC.
func (s *Service) RunScheduled(ctx context.Context, tid tenant.ID) ([]ScheduledResult, error) {
	cs, err := s.reg.List(ctx, tid, false)
	if err != nil {
		return nil, err
	}
	actor := authority.Chain{Requester: authority.Principal{ID: "system:scheduler", Kind: authority.System}}
	var out []ScheduledResult
	for _, c := range cs {
		if c.State != StateActive {
			continue
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		o, err := s.run(ctx, tid, c.ID, KindScheduled, actor)
		out = append(out, ScheduledResult{Connection: c.ID, Outcome: o, Err: err})
	}
	return out, nil
}

// StrandedGrace is how long a connection may stay verifying before its run is presumed lost. A run is
// one connector call, bounded well below this; the margin means a slow live run is never swept.
const StrandedGrace = 15 * time.Minute

// sweeperID is the system principal a swept run is recorded under.
const sweeperID = "system:sweeper"

// SweepStranded finds connections left in verifying by a crash (no live run can outlast grace; zero
// takes StrandedGrace) and, for each, records a failed run with the over-privilege check not_run and
// returns it to draft (DM-10.I10). It returns the connections it recovered. A connection whose state
// moved meanwhile (the run finished after all) is skipped; a connection that cannot be recorded is
// reported in the error and the others are still swept.
func (s *Service) SweepStranded(ctx context.Context, tid tenant.ID, grace time.Duration) ([]ID, error) {
	if grace <= 0 {
		grace = StrandedGrace
	}
	var cs []Connection
	err := s.reg.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) {
		cs, e = s.reg.s.ListStranded(ctx, tx, s.now().Add(-grace))
		return
	})
	if err != nil {
		return nil, err
	}
	actor := authority.Chain{Requester: authority.Principal{ID: sweeperID, Kind: authority.System}}
	var swept []ID
	var errs []error
	for _, c := range cs {
		if err := ctx.Err(); err != nil {
			return swept, errors.Join(append(errs, err)...)
		}
		// Onboarding is the run kind that ends verifying → draft without an activation attempt; the
		// original kind is not recorded and does not matter, both end in draft on a failed run.
		_, err := s.recordInterrupted(ctx, tid, c, KindOnboarding, newVerificationID(), s.now(), actor)
		switch {
		case err == nil:
			swept = append(swept, c.ID)
		case errors.Is(err, ErrStateConflict):
			// Settled by its own run in the meantime: nothing to recover.
		default:
			errs = append(errs, fmt.Errorf("connection %s: %w", c.ID, err))
		}
	}
	return swept, errors.Join(errs...)
}

// run is one verification: claim, ask the connector, apply. The connector call is outside every
// transaction: it is a network round trip to a DC and must not hold a row lock.
func (s *Service) run(ctx context.Context, tid tenant.ID, id ID, kind VerificationKind, actor authority.Chain) (VerifyOutcome, error) {
	return s.runCandidate(ctx, tid, id, kind, actor, "")
}

// ChangeCredential is "Change credential" (spec FR-21, DM-10.I8): it verifies the candidate credential
// against the connection's own directory identity and swaps it in, atomically with the recorded run,
// only on a pass. On any other outcome the old credential stays in use and the run is kept as evidence.
// The run is recorded and returned either way; the caller learns whether the swap happened from
// Connection.CredentialID. Retiring the old DM-11 row is the credential port's step after a swap.
func (s *Service) ChangeCredential(ctx context.Context, tid tenant.ID, id ID, candidate CredentialID, actor authority.Chain) (VerifyOutcome, error) {
	if err := actor.Validate(); err != nil {
		return VerifyOutcome{}, err
	}
	cand, err := ParseCredentialID(string(candidate))
	if err != nil {
		return VerifyOutcome{}, err
	}
	return s.runCandidate(ctx, tid, id, KindCredentialChange, actor, cand)
}

// runCandidate is run for a kind that may verify a credential other than the connection's current
// one. The connection value carried through the run names the credential being verified, so the
// connector call and the recorded row agree on it.
func (s *Service) runCandidate(ctx context.Context, tid tenant.ID, id ID, kind VerificationKind, actor authority.Chain, cand CredentialID) (VerifyOutcome, error) {
	var conn Connection
	fromDraft := kind == KindActivation || kind == KindOnboarding
	err := s.reg.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) {
		if fromDraft {
			// draft → verifying is the claim: a second concurrent press fails the compare-and-set.
			if conn, e = s.reg.s.Transition(ctx, tx, id, StateDraft, StateVerifying); e != nil {
				return
			}
			// The cadence also carries the sweep of runs stranded here, so it starts with the first claim.
			return s.schedule(ctx, tx, tid)
		}
		if conn, e = s.reg.s.Get(ctx, tx, id); e != nil {
			return
		}
		if conn.State != StateActive && conn.State != StateSuspended {
			return fmt.Errorf("%w: a %s connection is not re-verified", ErrIllegalTransition, conn.State)
		}
		if kind == KindCredentialChange {
			if cand == "" || cand == conn.CredentialID {
				return fmt.Errorf("%w: a credential change names a different credential", ErrInvalid)
			}
			conn.CredentialID = cand
		}
		return nil
	})
	if err != nil {
		return VerifyOutcome{}, err
	}
	vid := newVerificationID()
	started := s.now()
	// TM-D26 rule 10: the run is told the connection's pins, so a renamed pinned group stays tier0.
	// A pin store that cannot be read fails the run closed: an unknown pin set is not an empty one.
	var pins []string
	if conn.Kind == KindADForest {
		if perr := s.reg.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) {
			pins, e = Store{}.PinnedC13(ctx, tx, conn.ID)
			return
		}); perr != nil {
			return s.interrupted(ctx, tid, conn, kind, vid, started, actor, perr)
		}
	}
	res, verr := s.client.VerifyConnection(ctx, VerifyRequest{Connection: conn, Kind: kind, VerificationID: vid, PinnedC13: pins})
	if verr == nil {
		verr = checkResult(conn.Kind, res)
	}
	if verr == nil && kind == KindOnboarding && conn.Kind == KindADForest && len(res.C13Groups) > 0 {
		// First discovery: pin what the run found (TM-D26 rule 10). Add-only and idempotent. A pin that
		// cannot be made durable interrupts the run: the next press starts again from draft.
		verr = s.reg.with(ctx, tid, func(ctx context.Context, tx store.Tx) error {
			return Store{}.PinC13(ctx, tx, conn.ID, res.C13Groups)
		})
	}
	if verr != nil {
		return s.interrupted(ctx, tid, conn, kind, vid, started, actor, verr)
	}
	res, err = s.applyIdentity(ctx, tid, conn, res)
	if err != nil {
		return s.interrupted(ctx, tid, conn, kind, vid, started, actor, err)
	}
	return s.settle(ctx, tid, conn, kind, vid, started, actor, res)
}

// checkResult refuses a result that is not a complete answer.
// A pass that does not answer every required check is an incomplete answer too: it goes through
// interrupted(), which records a failed run, closes the write gate and audits.
func checkResult(k Kind, r VerifyResult) error {
	if r.CheckListVersion < 1 || len(r.Outcomes) == 0 || !r.Verdict.valid() {
		return fmt.Errorf("%w: the result is incomplete", ErrRunInterrupted)
	}
	if r.Verdict == VerdictPass && !passComplete(k, r.Outcomes) {
		return fmt.Errorf("%w: a pass does not answer every required check", ErrRunInterrupted)
	}
	return nil
}

// identityCheck is the check that reads the directory identity: V5 for AD, EV2 for Entra.
func identityCheck(k Kind) Check {
	if k == KindEntraTenant {
		return "EV2"
	}
	return "V5"
}

// applyIdentity records the identity a passing identity check read (DM-10.I1), in its own
// transaction because a duplicate (I2) is a database error that aborts the one it happens in. If the
// identity is not allowed, the result is downgraded to a failed identity check: the run is still
// recorded, and nothing activates on it.
func (s *Service) applyIdentity(ctx context.Context, tid tenant.ID, conn Connection, r VerifyResult) (VerifyResult, error) {
	if r.DirectoryIdentity == "" {
		return r, nil
	}
	if _, err := ParseDirectoryIdentity(string(r.DirectoryIdentity)); err != nil {
		return VerifyResult{}, err
	}
	chk := identityCheck(conn.Kind)
	switch {
	case conn.DirectoryIdentity != "" && conn.DirectoryIdentity != r.DirectoryIdentity:
		return failIdentity(r, chk), nil // I1: a connection is never re-pointed
	case conn.DirectoryIdentity == "" && r.Outcomes[chk] == OutcomePass && conn.State == StateVerifying:
		_, err := s.reg.SetDirectoryIdentity(ctx, tid, conn.ID, r.DirectoryIdentity)
		switch {
		case errors.Is(err, ErrDuplicateIdentity):
			return failIdentity(r, chk), nil // spec L10: V5 fails with duplicate_identity
		case err != nil:
			return VerifyResult{}, err
		}
	}
	return r, nil
}

func failIdentity(r VerifyResult, chk Check) VerifyResult {
	out := r
	out.Outcomes = make(map[Check]Outcome, len(r.Outcomes))
	for c, o := range r.Outcomes {
		out.Outcomes[c] = o
	}
	out.Outcomes[chk] = OutcomeFail
	out.Verdict = VerdictFailed
	return out
}

// settle records the run and applies it, in one transaction with its audit events.
func (s *Service) settle(ctx context.Context, tid tenant.ID, conn Connection, kind VerificationKind, vid VerificationID,
	started time.Time, actor authority.Chain, r VerifyResult) (VerifyOutcome, error) {
	var out VerifyOutcome
	var refused error
	err := s.reg.with(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		refused, out = nil, VerifyOutcome{}
		return s.record(ctx, tx, tid, conn, kind, vid, started, actor, r, &out, &refused)
	})
	if err != nil {
		return VerifyOutcome{}, err
	}
	return out, refused
}

func (s *Service) record(ctx context.Context, tx store.Tx, tid tenant.ID, conn Connection, kind VerificationKind, vid VerificationID,
	started time.Time, actor authority.Chain, r VerifyResult, out *VerifyOutcome, refused *error) error {
	var prev *Verification
	if conn.LastVerificationID != "" {
		p, err := getVerification(ctx, tx, conn.ID, VerificationID(conn.LastVerificationID), false)
		if err != nil {
			return err
		}
		prev = &p
	}
	var was CredentialID
	if kind == KindCredentialChange {
		cur, err := s.reg.s.Get(ctx, tx, conn.ID) // conn already names the candidate; the row names the one in use
		if err != nil {
			return err
		}
		was = cur.CredentialID
	}
	requestedBy := string(actor.Requester.ID)
	if kind == KindScheduled {
		requestedBy = ""
	}
	v, err := s.reg.s.RecordVerification(ctx, tx, NewVerification{
		ID: vid, ConnectionID: conn.ID, CredentialID: conn.CredentialID, Kind: kind, RequestedBy: requestedBy,
		StartedAt: started, ObservedIdentity: r.DirectoryIdentity, CheckListVersion: r.CheckListVersion,
		Outcomes: r.Outcomes, Verdict: r.Verdict, Findings: r.Findings,
	})
	if err != nil {
		return err
	}
	out.Connection, out.Verification = conn, v
	if err := s.sink.Append(ctx, tx, s.verificationEvent(actor, conn, v)); err != nil {
		return err
	}
	if kind == KindCredentialChange {
		// The pointer moved only on a swap. Re-read the row so the caller sees the credential in use.
		c, err := s.reg.s.Get(ctx, tx, conn.ID)
		if err != nil {
			return err
		}
		out.Connection = c
		if c.CredentialID == v.CredentialID {
			if err := s.sink.Append(ctx, tx, s.credentialChangedEvent(actor, c, was, v.ID)); err != nil {
				return err
			}
		}
		return nil // the previous run judged another credential: no verdict-changed event
	}
	if prev != nil && prev.Verdict != v.Verdict {
		if err := s.sink.Append(ctx, tx, s.verdictChangedEvent(actor, conn, v, prev.Verdict)); err != nil {
			return err
		}
	}
	switch kind {
	case KindActivation:
		c, aerr := s.reg.s.Activate(ctx, tx, conn.ID)
		var ae *ActivationError
		switch {
		case aerr == nil:
			out.Connection = c
			if err := s.sink.Append(ctx, tx, s.activatedEvent(actor, c, v.ID, audit.Success, "")); err != nil {
				return err
			}
			return s.schedule(ctx, tx, tid)
		case errors.As(aerr, &ae):
			// The run is kept; the connection goes back to draft (DM-10.I10) and the refusal is audited.
			if err := s.sink.Append(ctx, tx, s.activatedEvent(actor, conn, v.ID, audit.Denied, ae.Code)); err != nil {
				return err
			}
			if out.Connection, err = s.reg.s.Transition(ctx, tx, conn.ID, StateVerifying, StateDraft); err != nil {
				return err
			}
			*refused = ae
		default:
			return aerr
		}
	case KindOnboarding:
		c, err := s.reg.s.Transition(ctx, tx, conn.ID, StateVerifying, StateDraft)
		if err != nil {
			return err
		}
		out.Connection = c
	}
	return nil
}

// schedule starts the tenant's scheduled check with the activation, in its transaction.
func (s *Service) schedule(ctx context.Context, tx store.Tx, tid tenant.ID) error {
	if s.sched == nil {
		return nil
	}
	return s.sched.ScheduleCheck(ctx, tx, tid)
}

// interrupted records a run that did not complete as failed with the over-privilege check not_run,
// which closes the write gate until a later run answers (DM-10.I10, I11), and returns a verifying
// connection to draft. It runs in a context that outlives the caller's cancellation, so a cancelled
// request never strands the connection in verifying.
func (s *Service) interrupted(ctx context.Context, tid tenant.ID, conn Connection, kind VerificationKind, vid VerificationID,
	started time.Time, actor authority.Chain, cause error) (VerifyOutcome, error) {
	o, err := s.recordInterrupted(ctx, tid, conn, kind, vid, started, actor)
	if err != nil {
		return VerifyOutcome{}, errors.Join(fmt.Errorf("%w: and it could not be recorded", ErrRunInterrupted), err)
	}
	if errors.Is(cause, ErrRunInterrupted) {
		return o, cause
	}
	return o, fmt.Errorf("%w: %w", ErrRunInterrupted, cause)
}

// recordInterrupted writes the failed run and the verifying → draft step, in a context that outlives
// the caller's cancellation. It returns only a recording failure.
func (s *Service) recordInterrupted(ctx context.Context, tid tenant.ID, conn Connection, kind VerificationKind, vid VerificationID,
	started time.Time, actor authority.Chain) (VerifyOutcome, error) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	r := VerifyResult{CheckListVersion: 1, Verdict: VerdictFailed,
		Outcomes: map[Check]Outcome{overPrivilegeCheck(conn.Kind): OutcomeNotRun}}
	o, err := s.settle(rctx, tid, conn, kind, vid, started, actor, r)
	if err != nil && !errors.Is(err, ErrActivationRefused) { // an activation run's own refusal is expected here
		return VerifyOutcome{}, err
	}
	return o, nil
}

func (s *Service) base(kind audit.Kind, actor authority.Chain, c Connection, o audit.Outcome, reason string) audit.Event {
	return audit.Event{
		ID: newEventID(), Kind: kind, At: s.now(), Actor: actor,
		Target:    authority.TargetRef{Connection: string(c.ID), GUID: string(c.ID), Class: "connection"},
		Component: "connection", Outcome: o, Reason: reason,
	}
}

func (s *Service) activatedEvent(actor authority.Chain, c Connection, vid VerificationID, o audit.Outcome, reason string) audit.Event {
	ev := s.base(AuditActivated, actor, c, o, reason)
	ev.Changes = []audit.Change{{Attribute: "verification_id", After: []string{string(vid)}}}
	if o == audit.Success {
		ev.Changes = append(ev.Changes, audit.Change{Attribute: "state", After: []string{string(StateActive)}})
	}
	return ev
}

// credentialChangedEvent records a swap. Only the credential's reference ID appears, never material.
func (s *Service) credentialChangedEvent(actor authority.Chain, c Connection, was CredentialID, vid VerificationID) audit.Event {
	ev := s.base(AuditCredentialChanged, actor, c, audit.Success, "")
	ev.Changes = []audit.Change{
		{Attribute: "credential_id", Before: []string{string(was)}, After: []string{string(c.CredentialID)}},
		{Attribute: "verification_id", After: []string{string(vid)}},
	}
	return ev
}

func (s *Service) verificationEvent(actor authority.Chain, c Connection, v Verification) audit.Event {
	ev := s.base(AuditVerificationCompleted, actor, c, audit.Success, "")
	ev.Changes = []audit.Change{
		{Attribute: "verification_id", After: []string{string(v.ID)}},
		{Attribute: "kind", After: []string{string(v.Kind)}},
		{Attribute: "verdict", After: []string{string(v.Verdict)}},
		{Attribute: "findings_count", After: []string{fmt.Sprint(len(v.Findings))}},
		{Attribute: "findings_digest", After: []string{fmt.Sprintf("%x", v.FindingsDigest)}},
	}
	for _, chk := range sortedChecks(v.Outcomes) {
		ev.Changes = append(ev.Changes, audit.Change{Attribute: "outcome." + string(chk), After: []string{string(v.Outcomes[chk])}})
	}
	return ev
}

func (s *Service) verdictChangedEvent(actor authority.Chain, c Connection, v Verification, was Verdict) audit.Event {
	ev := s.base(AuditVerdictChanged, actor, c, audit.Success, "")
	ev.Changes = []audit.Change{
		{Attribute: "verdict", Before: []string{string(was)}, After: []string{string(v.Verdict)}},
		{Attribute: "verification_id", After: []string{string(v.ID)}},
		{Attribute: "findings_digest", After: []string{fmt.Sprintf("%x", v.FindingsDigest)}},
	}
	return ev
}

func sortedChecks(m map[Check]Outcome) []Check {
	out := make([]Check, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

func newEventID() string { return string(newVerificationID()) }

// newVerificationID draws a random (version 4) UUID.
func newVerificationID() VerificationID {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("connection: no entropy: " + err.Error())
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return VerificationID(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]))
}
