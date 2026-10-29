// Package personal stores personal values by reference (ADR-0005 rule 12, domain model X11).
//
// A record that must stay tamper-evident forever (an audit event, a change record, a comment) holds a Ref
// instead of the value. The Ref names the subject the value is about, a value ID, the field and a
// commitment: HMAC-SHA-256 keyed with the subject's secret salt over the adq-canon/1 encoding of
// ("adq-personal/1", value_id, field, value). The clear value lives in personal_value; the salt in
// personal_subject. Erasing a subject deletes both, so the Ref (and any hash taken over it) is unchanged
// while the value can no longer be read or guessed from the commitment.
//
// personal sits below audit (blueprint §2.3): it imports no audit code beyond the canon leaf.
package personal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"

	"github.com/skenzeriq/activediq/internal/platform/audit/canon"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Redacted is what Resolve returns for a value whose subject has been erased (the UI shows it as is).
const Redacted = "[erased]"

const (
	commitmentDomain = "adq-personal/1"
	maxValueLen      = 65536
)

// Errors are typed and carry no value.
var (
	ErrInvalid  = errors.New("personal: invalid argument")
	ErrHeld     = errors.New("personal: subject is under legal hold")
	ErrTampered = errors.New("personal: stored value does not match its commitment")
)

// Declared for fitness-domain-keys. Both tables sit beside the append-only audit entity (DM-80) and are
// deleted from by erasure and the retention purge, so they are bookkeeping, not append-only.
var (
	_ = tablekind.Declare(tablekind.Table{Name: "public.personal_subject", Entity: "DM-80", Kind: tablekind.Tenant, Bookkeeping: true})
	_ = tablekind.Declare(tablekind.Table{Name: "public.personal_value", Entity: "DM-80", Kind: tablekind.Tenant, Bookkeeping: true})
	_ = tablekind.Declare(tablekind.Table{Name: "public.personal_hold", Entity: "DM-80", Kind: tablekind.Tenant, Bookkeeping: true})
)

var (
	subjectRe = regexp.MustCompile(`^(dir:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|acct:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	labelRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
)

// AcctSubject returns the subject string for an account (the ID of a human principal in an actor chain), and
// false when the ID is not a UUID. An admin's own events reference them as Requester or Via, so a hold on the
// admin must match them.
func AcctSubject(accountID string) (string, bool) {
	s := "acct:" + accountID
	if accountID == "" || !subjectRe.MatchString(s) {
		return "", false
	}
	return s, true
}

// DirSubject returns the subject string for a directory object, and false when the connection or objectGUID
// is not a UUID (the object cannot be a personal subject).
func DirSubject(connection, objectGUID string) (string, bool) {
	s := "dir:" + connection + ":" + objectGUID
	if connection == "" || objectGUID == "" || !subjectRe.MatchString(s) {
		return "", false
	}
	return s, true
}

// Ref is the form a chained record carries in place of a personal value. It holds no clear value.
type Ref struct {
	Subject    string // dir:<connection>:<objectGUID> or acct:<account_id>
	ValueID    [16]byte
	Field      string
	Commitment [sha256.Size]byte
}

// Canonical returns the adq-canon/1 encoding of the Ref, which is what a record's hash covers. It
// depends on the commitment and never on the value or the salt, so erasure does not change it.
func (r Ref) Canonical() ([]byte, error) {
	var e canon.Encoder
	e.String(1, r.Subject)
	e.UUID(2, r.ValueID)
	e.String(3, r.Field)
	e.Bytes(4, r.Commitment[:])
	return e.Result()
}

// Commit computes the commitment for a value under a subject salt.
func Commit(salt []byte, valueID [16]byte, field, value string) ([sha256.Size]byte, error) {
	var e canon.Encoder
	e.String(1, commitmentDomain)
	e.UUID(2, valueID)
	e.String(3, field)
	e.String(4, value)
	msg, err := e.Result()
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	m := hmac.New(sha256.New, salt)
	m.Write(msg)
	var out [sha256.Size]byte
	copy(out[:], m.Sum(nil))
	return out, nil
}

// Store reads and writes personal values. It has no state; every call runs in the caller's transaction.
type Store struct{}

// New returns a Store.
func New() *Store { return &Store{} }

// Put holds value outside the caller's record and returns the Ref the record stores. The subject's salt is
// created on first use. It runs in tx, the caller's own transaction (an audit commit hook, for example),
// so the value and the record that refers to it commit or roll back together.
func (*Store) Put(ctx context.Context, tx store.Tx, tid tenant.ID, subject, recordKind, field, value string) (Ref, error) {
	if tid.IsZero() || !subjectRe.MatchString(subject) || !labelRe.MatchString(recordKind) || !labelRe.MatchString(field) ||
		len(value) > maxValueLen {
		return Ref{}, ErrInvalid
	}
	var vid [16]byte
	if _, err := rand.Read(vid[:]); err != nil {
		return Ref{}, fmt.Errorf("personal: random: %w", err)
	}
	vid[6], vid[8] = vid[6]&0x0f|0x40, vid[8]&0x3f|0x80
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return Ref{}, fmt.Errorf("personal: random: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.personal_subject (tenant_id, subject_ref, salt) VALUES ($1::uuid, $2, $3)
		ON CONFLICT (tenant_id, subject_ref) DO NOTHING`, tid.String(), subject, salt); err != nil {
		return Ref{}, fmt.Errorf("personal: subject: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT salt FROM public.personal_subject WHERE tenant_id = $1::uuid AND subject_ref = $2`,
		tid.String(), subject).Scan(&salt); err != nil {
		return Ref{}, fmt.Errorf("personal: subject salt: %w", err)
	}
	c, err := Commit(salt, vid, field, value)
	if err != nil {
		return Ref{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.personal_value (tenant_id, value_id, subject_ref, record_kind, field, value)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)`, tid.String(), uuidString(vid), subject, recordKind, field, value); err != nil {
		return Ref{}, fmt.Errorf("personal: value: %w", err)
	}
	return Ref{Subject: subject, ValueID: vid, Field: field, Commitment: c}, nil
}

// Resolve returns the clear value of ref, or Redacted with erased true when the subject has been erased.
// While the value exists it is checked against the commitment; a mismatch is ErrTampered.
func (*Store) Resolve(ctx context.Context, tx store.Tx, tid tenant.ID, ref Ref) (value string, erased bool, err error) {
	if tid.IsZero() {
		return "", false, ErrInvalid
	}
	var salt []byte
	err = tx.QueryRow(ctx, `SELECT v.value, s.salt FROM public.personal_value v
		JOIN public.personal_subject s ON s.tenant_id = v.tenant_id AND s.subject_ref = v.subject_ref
		WHERE v.tenant_id = $1::uuid AND v.value_id = $2::uuid AND v.subject_ref = $3 AND v.field = $4`,
		tid.String(), uuidString(ref.ValueID), ref.Subject, ref.Field).Scan(&value, &salt)
	if store.IsNoRows(err) {
		return Redacted, true, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("personal: resolve: %w", err)
	}
	c, err := Commit(salt, ref.ValueID, ref.Field, value)
	if err != nil {
		return "", false, err
	}
	if !hmac.Equal(c[:], ref.Commitment[:]) {
		return "", false, ErrTampered
	}
	return value, false, nil
}

// Erase deletes a subject's values and salt and returns how many values it removed. It takes the step of
// the Action that authorises it (personal.subject.erase) and runs in that step's transaction. A subject
// under legal hold is refused with ErrHeld and nothing is deleted. Erasing an unknown or already erased
// subject removes nothing and succeeds.
func (*Store) Erase(ctx context.Context, s step.Step, tid tenant.ID, subject string) (int, error) {
	if err := s.Valid(); err != nil {
		return 0, err
	}
	return erase(ctx, s.Tx(), tid, subject)
}

// erase is Erase's body, split out so tests can drive it without a runner-minted step.
func erase(ctx context.Context, tx store.Tx, tid tenant.ID, subject string) (int, error) {
	if tid.IsZero() || !subjectRe.MatchString(subject) {
		return 0, ErrInvalid
	}
	// Serialise with a hold being set on this subject: a hold that commits first is seen here; one that
	// starts afterwards waits for this transaction.
	if err := lockSubject(ctx, tx, tid, subject); err != nil {
		return 0, err
	}
	var hold bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.personal_hold WHERE tenant_id = $1::uuid AND subject_ref = $2)`,
		tid.String(), subject).Scan(&hold); err != nil {
		return 0, fmt.Errorf("personal: erase: %w", err)
	}
	if hold {
		return 0, ErrHeld
	}
	tag, err := tx.Exec(ctx, `DELETE FROM public.personal_value WHERE tenant_id = $1::uuid AND subject_ref = $2`, tid.String(), subject)
	if err != nil {
		return 0, fmt.Errorf("personal: erase values: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM public.personal_subject WHERE tenant_id = $1::uuid AND subject_ref = $2`, tid.String(), subject); err != nil {
		return 0, fmt.Errorf("personal: erase subject: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// Purged counts what PurgeValues removed.
type Purged struct {
	Values   int // personal_value rows deleted
	Subjects int // personal_subject rows (salts) deleted
}

// PurgeValues deletes the values with the given IDs and then the salt of every subject those values
// belonged to that is left with no value and no legal hold (ADR-0005 rule 11, A9). The retention purge
// calls it, in its own maintenance transaction, with the value IDs referenced by the events it deletes;
// each value_id belongs to exactly one record, so no retained record loses a value. tx must run as a role
// that may DELETE (the maintenance owner): the runtime role's deletes are erasure's alone. Unknown IDs are
// ignored, so the call is idempotent. A subject under hold keeps its salt, and keeps any value other
// records still reference.
func (*Store) PurgeValues(ctx context.Context, tx store.Tx, tid tenant.ID, ids [][16]byte) (Purged, error) {
	var out Purged
	if tid.IsZero() {
		return out, ErrInvalid
	}
	const batch = 1000
	subjects := map[string]struct{}{}
	for start := 0; start < len(ids); start += batch {
		end := min(start+batch, len(ids))
		strs := make([]string, 0, end-start)
		for _, id := range ids[start:end] {
			strs = append(strs, uuidString(id))
		}
		rows, err := tx.Query(ctx, `DELETE FROM public.personal_value WHERE tenant_id = $1::uuid AND value_id = ANY($2::uuid[]) RETURNING subject_ref`,
			tid.String(), strs)
		if err != nil {
			return out, fmt.Errorf("personal: purge values: %w", err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				rows.Close()
				return out, fmt.Errorf("personal: purge values: %w", err)
			}
			subjects[s] = struct{}{}
			out.Values++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, fmt.Errorf("personal: purge values: %w", err)
		}
	}
	if len(subjects) == 0 {
		return out, nil
	}
	refs := make([]string, 0, len(subjects))
	for s := range subjects {
		refs = append(refs, s)
	}
	tag, err := tx.Exec(ctx, `DELETE FROM public.personal_subject s WHERE s.tenant_id = $1::uuid AND s.subject_ref = ANY($2::text[])
		AND NOT EXISTS (SELECT 1 FROM public.personal_hold h WHERE h.tenant_id = s.tenant_id AND h.subject_ref = s.subject_ref)
		AND NOT EXISTS (SELECT 1 FROM public.personal_value v WHERE v.tenant_id = s.tenant_id AND v.subject_ref = s.subject_ref)`,
		tid.String(), refs)
	if err != nil {
		return out, fmt.Errorf("personal: purge subjects: %w", err)
	}
	out.Subjects = int(tag.RowsAffected())
	return out, nil
}

func uuidString(u [16]byte) string {
	const hex = "0123456789abcdef"
	b := make([]byte, 0, 36)
	for i, x := range u {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			b = append(b, '-')
		}
		b = append(b, hex[x>>4], hex[x&15])
	}
	return string(b)
}

// lockTenantHolds and lockSubject take transaction-scoped advisory locks keyed by a hash of a fixed label
// and the tenant (and subject). A hash collision only makes two unrelated callers wait for each other.
// The hold registry has no row to lock for a subject not yet held, so these are the lock both sides take:
// SetHold takes the tenant lock shared (holds do not block each other) and LockHolds, the retention
// purge's read, takes it exclusive, so a hold is either committed before the purge reads or waits for it.
func lockTenantHolds(ctx context.Context, tx store.Tx, tid tenant.ID, exclusive bool) error {
	q := `SELECT pg_advisory_xact_lock_shared(hashtextextended('personal_hold:' || $1, 0))`
	if exclusive {
		q = `SELECT pg_advisory_xact_lock(hashtextextended('personal_hold:' || $1, 0))`
	}
	if _, err := tx.Exec(ctx, q, tid.String()); err != nil {
		return fmt.Errorf("personal: lock holds: %w", err)
	}
	return nil
}

func lockSubject(ctx context.Context, tx store.Tx, tid tenant.ID, subject string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('personal_subject:' || $1 || ':' || $2, 0))`, tid.String(), subject); err != nil {
		return fmt.Errorf("personal: lock subject: %w", err)
	}
	return nil
}

// SetHold places a legal hold on a subject (dir:... or acct:...) whether or not it has a salt row. It runs
// in the transaction of the compliance Action that authorises it (step.Tx()). Holding a held subject
// succeeds. It serialises with the retention purge: it waits for a running purge, and a purge that starts
// while this transaction is uncommitted waits for it.
func (*Store) SetHold(ctx context.Context, s step.Step, tid tenant.ID, subject string) error {
	if err := s.Valid(); err != nil {
		return err
	}
	return setHold(ctx, s.Tx(), tid, subject)
}

// setHold is SetHold's body, split out so tests can drive it without a runner-minted step. The database
// also takes both locks on every INSERT into personal_hold (migration 0049), so a writer that bypasses
// this function is serialised with the purge all the same.
func setHold(ctx context.Context, tx store.Tx, tid tenant.ID, subject string) error {
	if tid.IsZero() || !subjectRe.MatchString(subject) {
		return ErrInvalid
	}
	if err := lockTenantHolds(ctx, tx, tid, false); err != nil {
		return err
	}
	if err := lockSubject(ctx, tx, tid, subject); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.personal_hold (tenant_id, subject_ref) VALUES ($1::uuid, $2) ON CONFLICT DO NOTHING`, tid.String(), subject); err != nil {
		return fmt.Errorf("personal: set hold: %w", err)
	}
	return nil
}

// ReleaseHold lifts a legal hold; releasing a subject that is not held succeeds.
// It takes the step of the authorising compliance Action, like SetHold: lifting a hold is what lets the next
// purge destroy evidence, so it never runs outside an authorised, audited Action.
func (*Store) ReleaseHold(ctx context.Context, s step.Step, tid tenant.ID, subject string) error {
	if err := s.Valid(); err != nil {
		return err
	}
	return releaseHold(ctx, s.Tx(), tid, subject)
}

func releaseHold(ctx context.Context, tx store.Tx, tid tenant.ID, subject string) error {
	if tid.IsZero() || !subjectRe.MatchString(subject) {
		return ErrInvalid
	}
	if err := lockTenantHolds(ctx, tx, tid, false); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM public.personal_hold WHERE tenant_id = $1::uuid AND subject_ref = $2`, tid.String(), subject); err != nil {
		return fmt.Errorf("personal: release hold: %w", err)
	}
	return nil
}

// Held reports whether the subject is under legal hold. The compliance Actions read it at Plan to show the
// before state and to refuse a no-op; it takes no lock, so it decides nothing about erasure or the purge.
func (*Store) Held(ctx context.Context, tx store.Tx, tid tenant.ID, subject string) (bool, error) {
	if tid.IsZero() || !subjectRe.MatchString(subject) {
		return false, ErrInvalid
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.personal_hold WHERE tenant_id = $1::uuid AND subject_ref = $2`, tid.String(), subject).Scan(&n); err != nil {
		return false, fmt.Errorf("personal: read hold: %w", err)
	}
	return n > 0, nil
}

// LockHolds returns the tenant's held subjects after taking the hold lock exclusively until tx ends: a
// SetHold whose transaction is still open is waited for and then seen, and one that starts later waits for
// tx. The retention purge calls it in its maintenance transaction before deciding what it may delete.
func (*Store) LockHolds(ctx context.Context, tx store.Tx, tid tenant.ID) (map[string]struct{}, error) {
	if tid.IsZero() {
		return nil, ErrInvalid
	}
	if err := lockTenantHolds(ctx, tx, tid, true); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT subject_ref FROM public.personal_hold WHERE tenant_id = $1::uuid`, tid.String())
	if err != nil {
		return nil, fmt.Errorf("personal: read holds: %w", err)
	}
	defer rows.Close()
	held := map[string]struct{}{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("personal: read hold: %w", err)
		}
		held[s] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("personal: read holds: %w", err)
	}
	return held, nil
}
