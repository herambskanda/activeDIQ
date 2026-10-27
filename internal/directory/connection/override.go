package connection

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Tier0OverrideID identifies a DM-25 row.
type Tier0OverrideID string

// Tier0Override is DM-25: the installation operator's acknowledgement that activeDIQ may run as
// Tier 0 in this forest despite specific over-privilege findings (TM-D1). It is insert-only; whether
// it is in force is derived (InForce), never stored.
type Tier0Override struct {
	ID                       Tier0OverrideID
	ConnectionID             ID
	CredentialID             CredentialID
	VerificationID           VerificationID
	AcknowledgedBy           string    // the real human's pseudonymous principal ID
	AcknowledgedAt           time.Time // the connection's ordering stamp (DM-10.I13)
	AcknowledgedFingerprints []string  // the run's whole over-privilege set, sorted (DM-25.I1)
}

const overrideColumns = `id, connection_id, credential_id, verification_id, acknowledged_by, acknowledged_at, acknowledged_fingerprints`

func scanOverride(r scanner) (Tier0Override, error) {
	var o Tier0Override
	var id, conn, cred, ver string
	if err := r.Scan(&id, &conn, &cred, &ver, &o.AcknowledgedBy, &o.AcknowledgedAt, &o.AcknowledgedFingerprints); err != nil {
		return Tier0Override{}, err
	}
	o.ID, o.ConnectionID, o.CredentialID, o.VerificationID = Tier0OverrideID(id), ID(conn), CredentialID(cred), VerificationID(ver)
	return o, nil
}

// AcknowledgeInput is what AcknowledgeTier0Override needs. The permission, the step-up and the typed
// text are checked by the Action before it calls; this layer re-checks the facts that are the data's.
type AcknowledgeInput struct {
	ConnectionID   ID
	VerificationID VerificationID
	By             string // pseudonymous principal ID of the human behind the request
}

// AcknowledgeTier0Override records DM-25. It is accepted only when the referenced run is the
// connection's last_verification_id, belongs to its current credential, completed no more than
// FreshnessWindow earlier, and meets every DM-10.I9 (b) condition except the acknowledged set: the
// refusal is over-privilege alone, nothing is unanswered, and nothing else failed. The set stored is
// the run's whole over-privilege fingerprint set; an operator acknowledges everything shown, never a
// subset. A newer acknowledgement of the same credential supersedes an older one.
//
// It does not activate the connection: the caller runs Activate in the same transaction.
func (s Store) AcknowledgeTier0Override(ctx context.Context, tx store.Tx, in AcknowledgeInput) (Tier0Override, error) {
	if in.By == "" {
		return Tier0Override{}, fmt.Errorf("%w: an override names the human who acknowledged it", ErrInvalid)
	}
	if _, err := ParseVerificationID(string(in.VerificationID)); err != nil {
		return Tier0Override{}, err
	}
	cur, stamp, err := lock(ctx, tx, in.ConnectionID)
	if err != nil {
		return Tier0Override{}, err
	}
	switch cur.State {
	case StateDraft, StateActive, StateSuspended:
	default:
		return Tier0Override{}, &OverrideError{Code: ReasonWrongState}
	}
	if cur.LastVerificationID == "" || cur.LastVerificationID != string(in.VerificationID) {
		return Tier0Override{}, &OverrideError{Code: ReasonNotLatestRun}
	}
	v, err := getVerification(ctx, tx, cur.ID, in.VerificationID, true)
	if err != nil {
		return Tier0Override{}, err
	}
	if v.CredentialID != cur.CredentialID {
		return Tier0Override{}, &OverrideError{Code: ReasonCredentialChanged}
	}
	if stamp.Sub(v.CompletedAt) > FreshnessWindow {
		return Tier0Override{}, &OverrideError{Code: ReasonStaleVerification}
	}
	if ok, why := onlyOverPrivilege(cur.Kind, v); !ok {
		return Tier0Override{}, &OverrideError{Code: why}
	}
	fps := overPrivilegeFingerprints(cur.Kind, v)
	if len(fps) == 0 {
		return Tier0Override{}, &OverrideError{Code: ReasonNoFindings}
	}
	o, err := scanOverride(tx.QueryRow(ctx, `INSERT INTO public.connection_tier0_overrides
		(tenant_id, connection_id, credential_id, verification_id, acknowledged_by, acknowledged_at, acknowledged_fingerprints)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2::uuid, $3::uuid, $4, $5, $6)
		RETURNING `+overrideColumns, string(cur.ID), string(cur.CredentialID), string(v.ID), in.By, stamp, fps))
	if err != nil {
		return Tier0Override{}, fmt.Errorf("connection: tier0 override: %w", err)
	}
	if tag, err := tx.Exec(ctx, `UPDATE public.connections SET last_stamp_at = $2, updated_at = now() WHERE id = $1::uuid`,
		string(cur.ID), stamp); err != nil || tag.RowsAffected() != 1 {
		return Tier0Override{}, fmt.Errorf("connection: tier0 override: stamp: %w", errOrNoRow(err))
	}
	return o, nil
}

// Tier0OverrideInForce returns the override in force for the connection's current credential, or nil.
// DM-25.I3: an override is in force until the earliest of being cleared (a later run of the same
// credential with the over-privilege check at pass), superseded (a newer override of the same
// credential: only the newest is considered) or ended (the credential was replaced: a different
// credential never matches; or the connection was retired). The banner of spec FR-14 shows exactly
// while this is non-nil.
func (Store) Tier0OverrideInForce(ctx context.Context, tx store.Tx, id ID) (*Tier0Override, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return nil, err
	}
	c, err := Store{}.Get(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	return overrideInForce(ctx, tx, c)
}

// Tier0OverrideInForce is the tenant-explicit read for the connector client (client.OverrideSource,
// TM-R15): the override in force for the connection's current credential, or nil. A connection of
// another tenant is not visible under tid's row-level security and reads as not found.
func (r *Registry) Tier0OverrideInForce(ctx context.Context, tid tenant.ID, id ID) (o *Tier0Override, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) (e error) { o, e = r.s.Tier0OverrideInForce(ctx, tx, id); return })
	if err != nil {
		return nil, err
	}
	return o, nil
}

func overrideInForce(ctx context.Context, tx store.Tx, c Connection) (*Tier0Override, error) {
	if c.RetiredAt != nil {
		return nil, nil // ended: DM-10.I13 retired_at
	}
	o, err := scanOverride(tx.QueryRow(ctx, `SELECT `+overrideColumns+` FROM public.connection_tier0_overrides
		WHERE connection_id = $1::uuid AND credential_id = $2::uuid ORDER BY acknowledged_at DESC LIMIT 1`,
		string(c.ID), string(c.CredentialID)))
	if store.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("connection: tier0 override: %w", err)
	}
	var cleared bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.connection_verifications v
		WHERE v.connection_id = $1::uuid AND v.credential_id = $2::uuid AND v.completed_at > $3
		  AND v.outcomes ->> $4 = 'pass')`,
		string(c.ID), string(c.CredentialID), o.AcknowledgedAt, string(overPrivilegeCheck(c.Kind))).Scan(&cleared); err != nil {
		return nil, fmt.Errorf("connection: tier0 override: %w", err)
	}
	if cleared {
		return nil, nil // clearing is final (DM-25.I4)
	}
	return &o, nil
}

// Activate is the activation gate (DM-10.I9) as the single door into `active` from a draft or a
// verifying connection. Under the connection's row lock it requires the connection's newest run to
// belong to its current credential, to have completed no more than FreshnessWindow earlier, and to
// qualify (a pass, or an over-privilege-only refusal wholly covered by the override in force); then
// it takes the declared edge. Otherwise it changes nothing and returns *ActivationError with a
// stable reason. It runs no verification: a stale or missing run is the caller's cue to start one
// (the Service does).
//
// The embedded connector binding (DM-13, DM-10.I3) is created in this same transaction, just before
// the transition; the database refuses an activation with no live binding.
func (s Store) Activate(ctx context.Context, tx store.Tx, id ID) (Connection, error) {
	cur, stamp, err := lock(ctx, tx, id)
	if err != nil {
		return Connection{}, err
	}
	if cur.State != StateDraft && cur.State != StateVerifying {
		return Connection{}, &ActivationError{Code: ReasonWrongState}
	}
	if cur.LastVerificationID == "" {
		return Connection{}, &ActivationError{Code: ReasonNoVerification}
	}
	v, err := getVerification(ctx, tx, cur.ID, VerificationID(cur.LastVerificationID), true)
	if err != nil {
		return Connection{}, err
	}
	if v.CredentialID != cur.CredentialID {
		return Connection{}, &ActivationError{Code: ReasonCredentialChanged}
	}
	if stamp.Sub(v.CompletedAt) > FreshnessWindow {
		return Connection{}, &ActivationError{Code: ReasonStaleVerification}
	}
	ov, err := overrideInForce(ctx, tx, cur)
	if err != nil {
		return Connection{}, err
	}
	if ok, why := Qualifies(cur.Kind, v, ov); !ok {
		return Connection{}, &ActivationError{Code: why}
	}
	if err := ensureEmbeddedBinding(ctx, tx, id); err != nil {
		return Connection{}, err
	}
	return s.Transition(ctx, tx, id, cur.State, StateActive)
}

// OverrideEvidence is what the override's audit event commits to (DM-25.I7): how many fingerprints
// the override acknowledges and their salted digest. It carries no fingerprint.
type OverrideEvidence struct {
	Count  int
	Digest []byte
}

// OverrideEvidenceFor computes the evidence for acknowledging the run: the run's whole over-privilege
// fingerprint set, digested under adq-override-digest/1 with the run's digest_salt. A run is
// immutable, so this agrees with what AcknowledgeTier0Override stores for the same run.
func (s Store) OverrideEvidenceFor(ctx context.Context, tx store.Tx, conn ID, vid VerificationID) (OverrideEvidence, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return OverrideEvidence{}, err
	}
	cur, err := s.Get(ctx, tx, conn)
	if err != nil {
		return OverrideEvidence{}, err
	}
	v, err := getVerification(ctx, tx, conn, vid, true)
	if err != nil {
		return OverrideEvidence{}, err
	}
	var salt []byte
	if err := tx.QueryRow(ctx, `SELECT digest_salt FROM public.connection_verifications WHERE connection_id = $1::uuid AND id = $2::uuid`,
		string(conn), string(vid)).Scan(&salt); err != nil {
		return OverrideEvidence{}, fmt.Errorf("connection: override evidence: %w", errOrNoRow(err))
	}
	fps := overPrivilegeFingerprints(cur.Kind, v)
	if len(fps) == 0 {
		return OverrideEvidence{}, &OverrideError{Code: ReasonNoFindings}
	}
	return OverrideEvidence{Count: len(fps), Digest: OverrideDigest(salt, fps)}, nil
}

// VerifyOverrideEvidence reports whether the stored override acknowledges exactly the set the plan
// committed to. Apply calls it so the event never states a digest the row does not back.
func (Store) VerifyOverrideEvidence(ctx context.Context, tx store.Tx, o Tier0Override, want OverrideEvidence) error {
	var salt []byte
	if err := tx.QueryRow(ctx, `SELECT digest_salt FROM public.connection_verifications WHERE connection_id = $1::uuid AND id = $2::uuid`,
		string(o.ConnectionID), string(o.VerificationID)).Scan(&salt); err != nil {
		return fmt.Errorf("connection: override evidence: %w", errOrNoRow(err))
	}
	if len(o.AcknowledgedFingerprints) != want.Count || !bytes.Equal(OverrideDigest(salt, o.AcknowledgedFingerprints), want.Digest) {
		return fmt.Errorf("%w: the acknowledged set changed since the plan", ErrInvalid)
	}
	return nil
}
