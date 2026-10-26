package authn

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.authn_authenticator_enrollments", Entity: "DM-37", Kind: tablekind.Tenant})

// Where the sealed seed lives, in the AEAD associated data (TM-D7).
const (
	enrollTable  = "authn_authenticator_enrollments"
	sealedColumn = "sealed_secret"
	methodTOTP   = "totp"
)

// Errors. None carries a seed, a code, a blob or SQL.
var (
	// ErrCodeRejected: the code is malformed, outside the window, wrong, or the enrollment is not in a
	// state that can verify it (missing, revoked, not yet active). Callers answer all of these alike.
	ErrCodeRejected = errors.New("authn: code rejected")
	// ErrCodeReplayed: the code was valid but its step was already used (or a later one was). For the
	// audit trail; the user-facing answer is the same as ErrCodeRejected.
	ErrCodeReplayed = errors.New("authn: code already used")
	// ErrInvalidInput: a subject, label or identifier is malformed.
	ErrInvalidInput = errors.New("authn: invalid input")
	// ErrNotFound: no such enrollment in the tenant.
	ErrNotFound = errors.New("authn: enrollment not found")
)

// KeySource gives the tenant's data-encryption key (TM-D7) under which the seed is sealed. version 0
// asks for the current version. The package destroys the key when done.
type KeySource interface {
	DEK(ctx context.Context, tx store.Tx, id tenant.ID, version uint32) (keys.DEK, error)
}

// Subject is who an enrollment belongs to: a console account, or a directory user as connection plus
// objectGUID (never a DN). Exactly one form is set. IDs are canonical UUID text.
type Subject struct {
	AccountID    string
	ConnectionID string
	ObjectGUID   string
}

func (s Subject) validate() error {
	ok := func(v string) bool { _, err := tenant.Parse(v); return err == nil }
	switch {
	case s.AccountID != "" && s.ConnectionID == "" && s.ObjectGUID == "":
		if ok(s.AccountID) {
			return nil
		}
	case s.AccountID == "" && s.ConnectionID != "" && s.ObjectGUID != "":
		if ok(s.ConnectionID) && ok(s.ObjectGUID) {
			return nil
		}
	}
	return ErrInvalidInput
}

// State is the lifecycle of DM-37: pending → active → revoked.
type State string

// States.
const (
	StatePending State = "pending"
	StateActive  State = "active"
	StateRevoked State = "revoked"
)

// Info is what the package returns about an enrollment. It has no field for the seed, the sealed
// blob or the key version: nothing readable carries them (DM-37.I1).
type Info struct {
	ID        string
	Subject   Subject
	Method    string
	Label     string
	State     State
	LastUsed  *time.Time
	CreatedAt time.Time
}

// Provisioned is the result of Enroll: the only time a seed leaves the package. Seed holds the
// base32 text (no padding) an authenticator app takes; it prints as [REDACTED] and cannot be
// serialised. The caller shows it once and calls Seed.Destroy.
type Provisioned struct {
	ID   string
	Seed secret.Secret
}

// Service is the TOTP factor primitive. The caller brings the tenant transaction (store.DB.WithTenant)
// so the factor check, the audit record and the session change commit together.
type Service struct {
	Keys KeySource
	// Now is the clock; nil means time.Now. Tests inject one.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func rowContext(tid tenant.ID, rowID string, version uint32) keys.Context {
	return keys.Context{Tenant: tid, Table: enrollTable, Row: rowID, Column: sealedColumn, Version: version}
}

// Enroll creates a pending TOTP enrollment for subject with a fresh random seed, sealed under the
// tenant's current key. It does not activate it: Activate does, on the first valid code.
func (s *Service) Enroll(ctx context.Context, tx store.Tx, tid tenant.ID, subject Subject, label string) (Provisioned, error) {
	if tid.IsZero() || subject.validate() != nil || label == "" || len(label) > 128 {
		return Provisioned{}, ErrInvalidInput
	}
	seed := make([]byte, SeedBytes)
	defer zero(seed)
	if _, err := rand.Read(seed); err != nil {
		return Provisioned{}, fmt.Errorf("authn: seed: %w", err)
	}
	var rowID string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&rowID); err != nil {
		return Provisioned{}, fmt.Errorf("authn: enroll: %w", err)
	}
	dek, err := s.Keys.DEK(ctx, tx, tid, 0)
	if err != nil {
		return Provisioned{}, fmt.Errorf("authn: tenant key: %w", err)
	}
	defer dek.Destroy()
	blob, err := keys.Seal(dek, rowContext(tid, rowID, dek.Version), seed)
	if err != nil {
		return Provisioned{}, fmt.Errorf("authn: seal: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.authn_authenticator_enrollments
		(tenant_id, id, account_id, connection_id, object_guid, method, sealed_secret, key_version, label)
		VALUES ($1::uuid, $2::uuid, NULLIF($3, '')::uuid, NULLIF($4, '')::uuid, NULLIF($5, '')::uuid, $6, $7, $8, $9)`,
		tid.String(), rowID, subject.AccountID, subject.ConnectionID, subject.ObjectGUID, methodTOTP, blob, int32(dek.Version), label); err != nil {
		return Provisioned{}, fmt.Errorf("authn: enroll: %w", err)
	}
	text := []byte(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed))
	return Provisioned{ID: rowID, Seed: secret.FromBytes(text)}, nil
}

// Get returns an enrollment without its seed.
func (s *Service) Get(ctx context.Context, tx store.Tx, id string) (Info, error) {
	if _, err := tenant.Parse(id); err != nil {
		return Info{}, ErrInvalidInput
	}
	var (
		in             Info
		acc, conn, gid *string
		state          string
	)
	err := tx.QueryRow(ctx, `SELECT id::text, account_id::text, connection_id::text, object_guid::text,
		method, label, state, last_used, created_at
		FROM public.authn_authenticator_enrollments WHERE id = $1::uuid`, id).
		Scan(&in.ID, &acc, &conn, &gid, &in.Method, &in.Label, &state, &in.LastUsed, &in.CreatedAt)
	if store.IsNoRows(err) {
		return Info{}, ErrNotFound
	}
	if err != nil {
		return Info{}, fmt.Errorf("authn: read enrollment: %w", err)
	}
	in.State = State(state)
	in.Subject = Subject{AccountID: deref(acc), ConnectionID: deref(conn), ObjectGUID: deref(gid)}
	return in, nil
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Activate verifies the first code of a pending enrollment (proof the app holds the seed) and makes
// it active. The code's step is spent like any other.
func (s *Service) Activate(ctx context.Context, tx store.Tx, tid tenant.ID, id, code string) error {
	return s.check(ctx, tx, tid, id, code, StatePending)
}

// Verify checks a code against an active enrollment. A code verifies at most once: a second
// submission of it, in its window or after, gets ErrCodeReplayed.
func (s *Service) Verify(ctx context.Context, tx store.Tx, tid tenant.ID, id, code string) error {
	return s.check(ctx, tx, tid, id, code, StateActive)
}

func (s *Service) check(ctx context.Context, tx store.Tx, tid tenant.ID, id, code string, want State) error {
	if tid.IsZero() {
		return ErrInvalidInput
	}
	if _, err := tenant.Parse(id); err != nil || !validCodeText(code) {
		return ErrCodeRejected
	}
	var (
		blob    []byte
		version int32
		state   string
		last    *int64
	)
	err := tx.QueryRow(ctx, `SELECT sealed_secret, key_version, state, last_used_step
		FROM public.authn_authenticator_enrollments WHERE id = $1::uuid AND method = 'totp' FOR UPDATE`, id).
		Scan(&blob, &version, &state, &last)
	if store.IsNoRows(err) {
		return ErrCodeRejected
	}
	if err != nil {
		return fmt.Errorf("authn: read enrollment: %w", err)
	}
	if State(state) != want || version <= 0 {
		return ErrCodeRejected
	}
	dek, err := s.Keys.DEK(ctx, tx, tid, uint32(version))
	if err != nil {
		return fmt.Errorf("authn: tenant key: %w", err)
	}
	defer dek.Destroy()
	seed, err := keys.Open(dek, rowContext(tid, id, uint32(version)), blob)
	if err != nil {
		return fmt.Errorf("authn: open seed: %w", err) // a tampered or moved blob: an integrity fault, not a wrong code
	}
	defer zero(seed)

	after := int64(-1)
	if last != nil {
		after = *last
	}
	now := s.now()
	step, ok, replayed := matchStep(seed, code, now, after)
	switch {
	case replayed:
		return ErrCodeReplayed
	case !ok:
		return ErrCodeRejected
	}
	// Spend the step. Conditional, so two submissions of one code racing past the read above cannot
	// both win even without the row lock; the trigger also refuses a decreasing step.
	tag, err := tx.Exec(ctx, `UPDATE public.authn_authenticator_enrollments
		SET last_used_step = $2, last_used = $3, state = CASE WHEN state = 'pending' THEN 'active' ELSE state END
		WHERE id = $1::uuid AND state = $4 AND (last_used_step IS NULL OR last_used_step < $2)`,
		id, step, now, string(want))
	if err != nil {
		return fmt.Errorf("authn: spend step: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrCodeReplayed
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
