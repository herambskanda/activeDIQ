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

var (
	_ = tablekind.Declare(tablekind.Table{Name: "public.authn_authenticator_enrollments", Entity: "DM-37", Kind: tablekind.Tenant})
	// Refused codes: the app role inserts and, to prune, deletes only rows older than two hours (trigger).
	_ = tablekind.Declare(tablekind.Table{Name: "public.authn_totp_failures", Entity: "DM-37", Kind: tablekind.Tenant})
)

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
	// ErrFactorPaused: ten wrong codes within an hour paused this enrollment (ENH-09 §5); even a correct
	// code is refused until PausedUntil. The user-facing answer is the same as ErrCodeRejected; the
	// caller may use this to steer a technician to another factor. The code is not evaluated.
	ErrFactorPaused = errors.New("authn: factor paused")
	// ErrActiveCap: the account already has MaxActiveTOTPPerAccount active console TOTP enrolments, so
	// another cannot be activated until one is revoked. The database enforces it (migration 0036).
	ErrActiveCap = errors.New("authn: account is at its active TOTP enrolment limit")
)

// The failure budget (ENH-09 §5, DM-37).
const (
	// MaxFailuresPerHour wrong codes within FailureWindow pause the enrollment for PauseDuration.
	MaxFailuresPerHour = 10
	FailureWindow      = time.Hour
	PauseDuration      = time.Hour
	// PendingTTL is how long a pending enrollment can be confirmed; MaxConfirmAttempts wrong codes
	// expire it sooner.
	PendingTTL         = 10 * time.Minute
	MaxConfirmAttempts = 5
	// MaxActiveTOTPPerAccount bounds sign-in guess rate: every active enrolment of an account is tried
	// per attempt. Mirrors the constant in migrations/0036; a test pins the two together.
	MaxActiveTOTPPerAccount = 3
	// recordLockWait bounds the charging transaction's wait for the enrollment row, so a caller
	// holding that row never hangs an attempt.
	recordLockWait = 3 * time.Second
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

// State is the lifecycle of DM-37: pending → active → revoked, or pending → expired.
type State string

// States.
const (
	StatePending State = "pending"
	StateActive  State = "active"
	StateRevoked State = "revoked"
	StateExpired State = "expired"
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
	// ExpiresAt is set while pending; PausedUntil only while the failure budget has paused the factor.
	ExpiresAt   *time.Time
	PausedUntil *time.Time
}

// Provisioned is the result of Enroll: the only time a seed leaves the package. Seed holds the
// base32 text (no padding) an authenticator app takes; it prints as [REDACTED] and cannot be
// serialised. The caller shows it once and calls Seed.Destroy.
type Provisioned struct {
	ID   string
	Seed secret.Secret
}

// FailureStore opens the short, separate tenant transaction that records a refused code. *store.DB
// satisfies it.
type FailureStore interface {
	WithTenantSeparate(ctx context.Context, id tenant.ID, lockWait time.Duration, fn func(ctx context.Context, tx store.Tx) error) error
}

// Service is the TOTP factor primitive. The caller brings the tenant transaction (store.DB.WithTenant)
// so the factor check, the audit record and the session change commit together.
//
// An attempt is the exception: it is charged through Failures in its own transaction, committed
// before the code is evaluated, so a caller that rolls back cannot erase it and parallel requests
// cannot out-guess the budget. The enrolment must therefore be committed already, and the caller's
// transaction must not hold a lock on its row (check itself reads without locking); the charge waits
// at most 3 s for the row and then fails closed with an error.
type Service struct {
	Keys KeySource
	// Failures records refusals. Required: without it a refusal cannot be counted, so check fails
	// closed instead of verifying with no budget.
	Failures FailureStore
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
		(tenant_id, id, account_id, connection_id, object_guid, method, sealed_secret, key_version, label, expires_at)
		VALUES ($1::uuid, $2::uuid, NULLIF($3, '')::uuid, NULLIF($4, '')::uuid, NULLIF($5, '')::uuid, $6, $7, $8, $9, $10)`,
		tid.String(), rowID, subject.AccountID, subject.ConnectionID, subject.ObjectGUID, methodTOTP, blob, int32(dek.Version), label, s.now().Add(PendingTTL)); err != nil {
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
		method, label, state, last_used, created_at, expires_at, paused_until
		FROM public.authn_authenticator_enrollments WHERE id = $1::uuid`, id).
		Scan(&in.ID, &acc, &conn, &gid, &in.Method, &in.Label, &state, &in.LastUsed, &in.CreatedAt, &in.ExpiresAt, &in.PausedUntil)
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
	if s.Failures == nil {
		return errors.New("authn: no failure store configured")
	}
	if _, err := tenant.Parse(id); err != nil || !validCodeText(code) {
		return ErrCodeRejected // not an attempt at any enrollment: there is no row to charge
	}
	now := s.now()
	// Charge first, evaluate second: the attempt is committed under the enrolment row lock before the
	// code is looked at, so however many requests race, at most the budget's worth are ever evaluated.
	attempt, err := s.charge(ctx, tid, id, want, now)
	if err != nil {
		return err
	}
	var (
		blob    []byte
		version int32
		state   string
		last    *int64
	)
	// No row lock here: a lock held by this transaction would block the charging transaction of the
	// next attempt.
	err = tx.QueryRow(ctx, `SELECT sealed_secret, key_version, state, last_used_step
		FROM public.authn_authenticator_enrollments WHERE id = $1::uuid AND method = 'totp'`, id).
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
	step, ok, replayed := matchStep(seed, code, now, after)
	if replayed || !ok {
		if err := s.settleFailure(ctx, tid, id, want, now); err != nil {
			return err
		}
		if replayed {
			return ErrCodeReplayed
		}
		return ErrCodeRejected
	}
	// Spend the step. Conditional, so two submissions of one code racing past the read above cannot
	// both win; the pause and expiry are re-asserted in the same statement; the trigger also refuses a
	// decreasing step.
	tag, err := tx.Exec(ctx, `UPDATE public.authn_authenticator_enrollments
		SET last_used_step = $2, last_used = $3, state = CASE WHEN state = 'pending' THEN 'active' ELSE state END,
		    refund_attempt = NULLIF($6, '')::uuid
		WHERE id = $1::uuid AND state = $4 AND (last_used_step IS NULL OR last_used_step < $2)
		  AND (paused_until IS NULL OR paused_until <= $3)
		  AND (state <> 'pending' OR (expires_at > $3 AND confirm_attempts <= $5))`,
		id, step, now, string(want), MaxConfirmAttempts, attempt)
	if store.SQLState(err) == "AD409" {
		return ErrActiveCap
	}
	if err != nil {
		return fmt.Errorf("authn: spend step: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrCodeReplayed
	}
	if attempt != "" {
		// Refund the attempt, in the transaction that spent the step: if the caller rolls back, the
		// attempt stays charged (the safe direction). The trigger accepts this update only when the spend named this attempt in refund_attempt.
		if _, err := tx.Exec(ctx, `UPDATE public.authn_totp_failures SET succeeded = true WHERE id = $1::uuid`, attempt); err != nil {
			return fmt.Errorf("authn: refund attempt: %w", err)
		}
	}
	return nil
}

// charge books one attempt against the enrolment in its own committed transaction, under the row lock,
// and refuses (paused, expired, over budget) before the code is evaluated. For an active enrolment it
// returns the id of the attempt row, which a success refunds; a pending one counts confirm_attempts.
// Attempts still in flight count, so the evaluations per enrolment in a window never exceed the budget.
func (s *Service) charge(ctx context.Context, tid tenant.ID, id string, want State, now time.Time) (attempt string, err error) {
	var refusal error
	err = s.Failures.WithTenantSeparate(ctx, tid, recordLockWait, func(ctx context.Context, tx store.Tx) error {
		var (
			state    string
			paused   *time.Time
			expires  *time.Time
			attempts int32
		)
		e := tx.QueryRow(ctx, `SELECT state, paused_until, expires_at, confirm_attempts
			FROM public.authn_authenticator_enrollments WHERE id = $1::uuid AND method = 'totp' FOR UPDATE`, id).
			Scan(&state, &paused, &expires, &attempts)
		if store.IsNoRows(e) {
			refusal = ErrCodeRejected
			return nil
		}
		if e != nil {
			return e
		}
		if State(state) != want {
			refusal = ErrCodeRejected
			return nil
		}
		if want == StatePending {
			if expires == nil || !now.Before(*expires) || attempts >= MaxConfirmAttempts {
				refusal = ErrCodeRejected
				_, e = tx.Exec(ctx, `UPDATE public.authn_authenticator_enrollments SET state = 'expired' WHERE id = $1::uuid AND state = 'pending'`, id)
				return e
			}
			_, e = tx.Exec(ctx, `UPDATE public.authn_authenticator_enrollments SET confirm_attempts = confirm_attempts + 1 WHERE id = $1::uuid`, id)
			return e
		}
		if paused != nil && now.Before(*paused) {
			refusal = ErrFactorPaused // the code is not evaluated: a correct one gets no answer while paused
			return nil
		}
		var n int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_totp_failures
			WHERE enrollment_id = $1::uuid AND at > $2 AND NOT succeeded`, id, now.Add(-FailureWindow)).Scan(&n); e != nil {
			return e
		}
		if n >= MaxFailuresPerHour {
			refusal = ErrFactorPaused
			return pause(ctx, tx, id, now)
		}
		if _, e := tx.Exec(ctx, `DELETE FROM public.authn_totp_failures WHERE enrollment_id = $1::uuid AND at < $2`,
			id, now.Add(-2*FailureWindow)); e != nil {
			return e
		}
		return tx.QueryRow(ctx, `INSERT INTO public.authn_totp_failures (tenant_id, enrollment_id, at)
			VALUES ($1::uuid, $2::uuid, $3) RETURNING id::text`, tid.String(), id, now).Scan(&attempt)
	})
	if err != nil {
		return "", fmt.Errorf("authn: charge attempt: %w", err) // fail closed: an uncounted attempt is an unbounded guess
	}
	if refusal != nil {
		return "", refusal
	}
	return attempt, nil
}

func pause(ctx context.Context, tx store.Tx, id string, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE public.authn_authenticator_enrollments SET paused_until = $2
		WHERE id = $1::uuid AND (paused_until IS NULL OR paused_until <= $3)`, id, now.Add(PauseDuration), now)
	return err
}

// settleFailure runs after a refused code: it sets the pause when this attempt spent the tenth (the
// charge only pauses on the eleventh), or expires a pending enrolment that has used its fifth confirm.
// Committed on its own, like the charge.
func (s *Service) settleFailure(ctx context.Context, tid tenant.ID, id string, want State, now time.Time) error {
	err := s.Failures.WithTenantSeparate(ctx, tid, recordLockWait, func(ctx context.Context, tx store.Tx) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM public.authn_authenticator_enrollments WHERE id = $1::uuid FOR UPDATE`, id).Scan(&state); err != nil {
			return err
		}
		if State(state) != want {
			return nil // changed under us (activated, revoked, expired): nothing left to settle
		}
		if want == StatePending {
			_, err := tx.Exec(ctx, `UPDATE public.authn_authenticator_enrollments SET state = 'expired'
				WHERE id = $1::uuid AND state = 'pending' AND confirm_attempts >= $2`, id, MaxConfirmAttempts)
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_totp_failures
			WHERE enrollment_id = $1::uuid AND at > $2 AND NOT succeeded`, id, now.Add(-FailureWindow)).Scan(&n); err != nil {
			return err
		}
		if n >= MaxFailuresPerHour {
			return pause(ctx, tx, id, now)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("authn: settle failed code: %w", err)
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
