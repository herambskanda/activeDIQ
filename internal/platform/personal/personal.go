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

	"github.com/jackc/pgx/v5"

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
)

var (
	subjectRe = regexp.MustCompile(`^(dir:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|acct:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	labelRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
)

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
	if errors.Is(err, pgx.ErrNoRows) {
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
	var hold bool
	err := tx.QueryRow(ctx, `SELECT hold FROM public.personal_subject WHERE tenant_id = $1::uuid AND subject_ref = $2`,
		tid.String(), subject).Scan(&hold)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
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
