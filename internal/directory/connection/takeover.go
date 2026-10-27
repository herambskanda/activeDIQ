package connection

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// TakeoverProtection is the Entra connection's derived takeover state (DM-10.I7, threat model §6.8).
// It is computed from the stored attestation at every evaluation and never stored.
type TakeoverProtection string

// The four states. Only TakeoverAttested lets a correlation become matched (DM-20.I4(f)); every
// other state makes the tenant's correlations candidate with reason tenant_takeover_open.
const (
	TakeoverUnattested TakeoverProtection = "unattested" // never attested
	TakeoverAttested   TakeoverProtection = "attested"
	TakeoverOpen       TakeoverProtection = "open"  // the last attestation read a flag as false
	TakeoverStale      TakeoverProtection = "stale" // aged out, or a demotion signal arrived
)

// MaxAttestationAge is both the default and the cap of attestation_max_age (TM-D17 rule 2, DM-10.I7(c)).
const MaxAttestationAge = 90 * 24 * time.Hour

// ErrAttestationMaxAge: a tenant may shorten attestation_max_age but never lengthen it.
var ErrAttestationMaxAge = errors.New("connection: attestation_max_age must be positive and at most 90 days")

// ErrAttemptInvalid is the one answer for an unknown, expired, replayed or foreign attestation
// attempt. It does not say which.
var ErrAttemptInvalid = errors.New("connection: attestation attempt is unknown, expired or already used")

// ValidateAttestationMaxAge refuses an age above the 90-day cap, zero or negative, or one that is
// not a whole number of seconds (the column is seconds).
func ValidateAttestationMaxAge(d time.Duration) error {
	if d <= 0 || d > MaxAttestationAge || d%time.Second != 0 {
		return ErrAttestationMaxAge
	}
	return nil
}

// Attestation is the latest attestation as the connection keeps it (I7(b)). It holds no token.
type Attestation struct {
	By             string // the Global Administrator's Entra object ID, canonical lower-case UUID
	At             time.Time
	BlockHardMatch bool // blockCloudObjectTakeoverThroughHardMatchEnabled
	BlockSoftMatch bool // blockSoftMatchEnabled
}

// TakeoverRecord is the stored input of the derived state.
type TakeoverRecord struct {
	Attestation     *Attestation // nil: never attested
	MaxAge          time.Duration
	FirstAttestedAt *time.Time
	DemotedAt       *time.Time
}

// ExpiresAt is when the current attestation ages out; zero if none.
func (r TakeoverRecord) ExpiresAt() time.Time {
	if r.Attestation == nil {
		return time.Time{}
	}
	return r.Attestation.At.Add(r.MaxAge)
}

// EvaluateTakeover is the I7(c) state machine as one pure function. It reads no clock but now.
// attested needs all three: both values true, age below the cap, and no demotion signal after the
// attestation. An unreadable record (zero or over-cap max age, an attestation from the future) is
// stale, never attested: any doubt fails closed.
func EvaluateTakeover(r TakeoverRecord, now time.Time) TakeoverProtection {
	a := r.Attestation
	if a == nil {
		return TakeoverUnattested
	}
	if !a.BlockHardMatch || !a.BlockSoftMatch {
		return TakeoverOpen
	}
	if r.MaxAge <= 0 || r.MaxAge > MaxAttestationAge || a.At.After(now) || !now.Before(a.At.Add(r.MaxAge)) {
		return TakeoverStale
	}
	if r.DemotedAt != nil && !r.DemotedAt.Before(a.At) {
		return TakeoverStale
	}
	return TakeoverAttested
}

// Takeover returns the derived state with the stored inputs.
type Takeover struct {
	Record TakeoverRecord
	State  TakeoverProtection
}

// Attempt is a started attestation awaiting its callback.
type Attempt struct {
	ConnectionID ID
	CodeVerifier string
	StartedBy    string
}

// HashState is the stored form of an attempt's state value: the raw value is never stored.
func HashState(state string) [32]byte { return sha256.Sum256([]byte(state)) }

const takeoverColumns = `attested_by, attested_at, attested_block_hard_match, attested_block_soft_match,
	attestation_max_age_seconds, first_attested_at, demoted_at`

func scanTakeover(r scanner) (TakeoverRecord, error) {
	var by *string
	var at *time.Time
	var hard, soft *bool
	var secs int
	var rec TakeoverRecord
	if err := r.Scan(&by, &at, &hard, &soft, &secs, &rec.FirstAttestedAt, &rec.DemotedAt); err != nil {
		return TakeoverRecord{}, err
	}
	rec.MaxAge = time.Duration(secs) * time.Second
	if by != nil && at != nil && hard != nil && soft != nil {
		rec.Attestation = &Attestation{By: *by, At: *at, BlockHardMatch: *hard, BlockSoftMatch: *soft}
	}
	return rec, nil
}

func (s Store) entraRecord(ctx context.Context, tx store.Tx, id ID, lock bool) (TakeoverRecord, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return TakeoverRecord{}, err
	}
	if _, err := ParseID(string(id)); err != nil {
		return TakeoverRecord{}, err
	}
	q := `SELECT ` + takeoverColumns + ` FROM public.connections WHERE id = $1::uuid AND kind = 'entra_tenant'`
	if lock {
		q += ` FOR UPDATE`
	}
	rec, err := scanTakeover(tx.QueryRow(ctx, q, string(id)))
	if store.IsNoRows(err) {
		return TakeoverRecord{}, ErrNotFound
	}
	return rec, err
}

// GetTakeover returns the stored inputs of an Entra connection (ErrNotFound for any other kind).
func (s Store) GetTakeover(ctx context.Context, tx store.Tx, id ID) (TakeoverRecord, error) {
	return s.entraRecord(ctx, tx, id, false)
}

// RecordAttestation stores the latest attestation, clears any earlier demotion signal (a new
// attestation supersedes it, I7(d)), and sets first_attested_at on the first move to attested
// (I7(f)). It returns the resulting record and state. The row is locked, so two callbacks serialise.
func (s Store) RecordAttestation(ctx context.Context, tx store.Tx, id ID, a Attestation, now time.Time) (Takeover, error) {
	by, ok := canonUUID(a.By)
	if !ok {
		return Takeover{}, fmt.Errorf("%w: attester object id", ErrInvalid)
	}
	a.By = by
	rec, err := s.entraRecord(ctx, tx, id, true)
	if err != nil {
		return Takeover{}, err
	}
	a.At = now
	next := TakeoverRecord{Attestation: &a, MaxAge: rec.MaxAge, FirstAttestedAt: rec.FirstAttestedAt}
	state := EvaluateTakeover(next, now)
	if state == TakeoverAttested && next.FirstAttestedAt == nil {
		t := now
		next.FirstAttestedAt = &t
	}
	if _, err := tx.Exec(ctx, `UPDATE public.connections SET attested_by = $2, attested_at = $3,
		attested_block_hard_match = $4, attested_block_soft_match = $5, first_attested_at = $6, demoted_at = NULL,
		updated_at = now() WHERE id = $1::uuid`,
		string(id), a.By, now, a.BlockHardMatch, a.BlockSoftMatch, next.FirstAttestedAt); err != nil {
		return Takeover{}, fmt.Errorf("connection: record attestation: %w", err)
	}
	return Takeover{Record: next, State: state}, nil
}

// RecordDemotion stores a demotion signal (I7(d)); the state is stale until a new attestation.
func (s Store) RecordDemotion(ctx context.Context, tx store.Tx, id ID, at time.Time) error {
	if _, err := s.entraRecord(ctx, tx, id, true); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE public.connections SET demoted_at = GREATEST(COALESCE(demoted_at, $2), $2),
		updated_at = now() WHERE id = $1::uuid`, string(id), at)
	if err != nil {
		return fmt.Errorf("connection: record demotion: %w", err)
	}
	return nil
}

// SetAttestationMaxAge shortens (or restores to the default) the tenant's attestation age. It refuses
// anything above the 90-day cap before it reaches the database, which also checks it.
func (s Store) SetAttestationMaxAge(ctx context.Context, tx store.Tx, id ID, d time.Duration) error {
	if err := ValidateAttestationMaxAge(d); err != nil {
		return err
	}
	if _, err := s.entraRecord(ctx, tx, id, true); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE public.connections SET attestation_max_age_seconds = $2, updated_at = now()
		WHERE id = $1::uuid`, string(id), int(d/time.Second)); err != nil {
		return fmt.Errorf("connection: set attestation max age: %w", err)
	}
	return nil
}

// CreateAttempt stores a started attempt under the hash of its state value.
func (s Store) CreateAttempt(ctx context.Context, tx store.Tx, a Attempt, stateHash [32]byte, now time.Time, ttl time.Duration) error {
	if err := requireTenant(ctx, tx); err != nil {
		return err
	}
	if _, err := s.entraRecord(ctx, tx, a.ConnectionID, false); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO public.connection_attestation_attempts
		(tenant_id, connection_id, state_hash, code_verifier, started_by, created_at, expires_at)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3, $4, $5, $6)`,
		string(a.ConnectionID), stateHash[:], a.CodeVerifier, a.StartedBy, now, now.Add(ttl))
	if err != nil {
		return fmt.Errorf("connection: create attestation attempt: %w", err)
	}
	return nil
}

// ConsumeAttempt deletes and returns the attempt for a state hash. It is single use: a second call
// returns ErrAttemptInvalid, as does an expired or unknown state. Expired rows are removed too.
func (s Store) ConsumeAttempt(ctx context.Context, tx store.Tx, stateHash [32]byte, now time.Time) (Attempt, error) {
	if err := requireTenant(ctx, tx); err != nil {
		return Attempt{}, err
	}
	var a Attempt
	var exp time.Time
	err := tx.QueryRow(ctx, `DELETE FROM public.connection_attestation_attempts WHERE state_hash = $1
		RETURNING connection_id::text, code_verifier, started_by, expires_at`, stateHash[:]).
		Scan(&a.ConnectionID, &a.CodeVerifier, &a.StartedBy, &exp)
	if store.IsNoRows(err) {
		return Attempt{}, ErrAttemptInvalid
	}
	if err != nil {
		return Attempt{}, fmt.Errorf("connection: consume attestation attempt: %w", err)
	}
	if !now.Before(exp) {
		return Attempt{}, ErrAttemptInvalid
	}
	return a, nil
}

// Registry wrappers: one tenant transaction per call.

// GetTakeover returns the stored inputs and the derived state at now.
func (r *Registry) GetTakeover(ctx context.Context, tid tenant.ID, id ID, now time.Time) (t Takeover, err error) {
	err = r.with(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		rec, e := r.s.GetTakeover(ctx, tx, id)
		t = Takeover{Record: rec, State: EvaluateTakeover(rec, now)}
		return e
	})
	return t, err
}

// SetAttestationMaxAge shortens the tenant's attestation age.
func (r *Registry) SetAttestationMaxAge(ctx context.Context, tid tenant.ID, id ID, d time.Duration) error {
	return r.with(ctx, tid, func(ctx context.Context, tx store.Tx) error { return r.s.SetAttestationMaxAge(ctx, tx, id, d) })
}

// RecordDemotion stores a demotion signal.
func (r *Registry) RecordDemotion(ctx context.Context, tid tenant.ID, id ID, at time.Time) error {
	return r.with(ctx, tid, func(ctx context.Context, tx store.Tx) error { return r.s.RecordDemotion(ctx, tx, id, at) })
}
