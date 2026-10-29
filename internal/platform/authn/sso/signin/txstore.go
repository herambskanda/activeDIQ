package signin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.authn_sso_transactions", Entity: "DM-39", Kind: tablekind.Tenant})

// TransactionTTL is the life of an SSO Transaction (DM-39.I4, SSO-1).
const TransactionTTL = 5 * time.Minute

// CookieName carries the handle from Start to the callback (console-sso.md section 3). The __Host- prefix
// makes browsers accept it only Secure, with Path=/ and no Domain. The handle is never read from a URL
// or a body.
const CookieName = "__Host-adq-sso"

// Errors of the transaction store. The callback answers every one of them with the one generic refusal.
var (
	// ErrNoTransaction: the handle is malformed, unknown, already consumed or from another tenant.
	ErrNoTransaction = errors.New("signin: no such transaction")
	// ErrTransactionExpired: the handle was live but older than TransactionTTL. It is consumed all the same.
	ErrTransactionExpired = errors.New("signin: transaction expired")
)

// Handle is the secret behind the browser-binding cookie: 256 random bits. String redacts.
type Handle struct{ text string }

// Reveal returns the cookie value, for the one response that sets the cookie.
func (h Handle) Reveal() string { return h.text }

// String redacts.
func (Handle) String() string { return "signin.Handle(redacted)" }

// GoString redacts for %#v.
func (Handle) GoString() string { return "signin.Handle(redacted)" }

func (h Handle) hash() []byte {
	sum := sha256.Sum256([]byte("activediq sso transaction v1\x00" + h.text))
	return sum[:]
}

const handleLen = 43 // base64.RawURLEncoding of 32 bytes

// ParseHandle reads cookie text from a client; shape only.
func ParseHandle(s string) (Handle, error) {
	if len(s) != handleLen {
		return Handle{}, ErrNoTransaction
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != s {
		return Handle{}, ErrNoTransaction
	}
	return Handle{text: s}, nil
}

func newHandle() (Handle, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Handle{}, fmt.Errorf("signin: handle: %w", err)
	}
	return Handle{text: base64.RawURLEncoding.EncodeToString(b[:])}, nil
}

// TxStore keeps SSO Transactions in PostgreSQL, so any node completes a sign-in another started.
type TxStore struct {
	db    *store.DB
	clock func() time.Time // nil: the database clock
}

// NewTxStore returns a TxStore over db (the runtime-role store). clock is nil in production.
func NewTxStore(db *store.DB, clock func() time.Time) (*TxStore, error) {
	if db == nil {
		return nil, errors.New("signin: TxStore needs a database")
	}
	return &TxStore{db: db, clock: clock}, nil
}

func (s *TxStore) now(ctx context.Context, tx store.Tx) (time.Time, error) {
	if s.clock != nil {
		return s.clock().UTC(), nil
	}
	var t time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&t); err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

const (
	// Trims this tenant's expired rows so the table stays small without a scheduled job. The expiry
	// index makes it a range delete; a row already consumed is simply not there.
	sqlTrim = `DELETE FROM public.authn_sso_transactions WHERE tenant_id = $1::uuid AND expires_at <= $2`

	sqlInsert = `INSERT INTO public.authn_sso_transactions
  (tenant_id, handle_hash, idp_id, intent, state, nonce, verifier, request_id, return_path, created_at, expires_at)
VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	// Consume-first (SSO-1): one statement reads and removes the row, so two callbacks cannot both win.
	sqlConsume = `DELETE FROM public.authn_sso_transactions WHERE tenant_id = $1::uuid AND handle_hash = $2
RETURNING idp_id, intent, state, nonce, verifier, request_id, return_path, created_at, expires_at`
)

// Put stores the Transaction a verifier's Start produced and returns the handle for the cookie. The
// Transaction's CreatedAt is the store's own clock, not the verifier's.
func (s *TxStore) Put(ctx context.Context, t tenant.ID, tx sso.Transaction) (Handle, error) {
	if t.IsZero() || tx.IdPID == "" || tx.Intent != sso.IntentSignin || tx.ReturnPath == "" {
		return Handle{}, errors.New("signin: invalid transaction")
	}
	h, err := newHandle()
	if err != nil {
		return Handle{}, err
	}
	err = s.db.WithTenant(ctx, t, func(ctx context.Context, dbtx store.Tx) error {
		now, err := s.now(ctx, dbtx)
		if err != nil {
			return err
		}
		if _, err := dbtx.Exec(ctx, sqlTrim, t.String(), now); err != nil {
			return err
		}
		_, err = dbtx.Exec(ctx, sqlInsert, t.String(), h.hash(), tx.IdPID, string(tx.Intent), tx.State, tx.Nonce,
			tx.Verifier, tx.RequestID, tx.ReturnPath, now, now.Add(TransactionTTL))
		return err
	})
	if err != nil {
		return Handle{}, fmt.Errorf("signin: store transaction: %w", err)
	}
	return h, nil
}

// Consume removes the Transaction the handle names and returns it, in its own committed transaction, so
// the removal stands whatever the caller does next (SSO-1). An unknown or already consumed handle is
// ErrNoTransaction; one older than TransactionTTL is removed and ErrTransactionExpired.
func (s *TxStore) Consume(ctx context.Context, t tenant.ID, h Handle) (sso.Transaction, error) {
	if t.IsZero() || h.text == "" {
		return sso.Transaction{}, ErrNoTransaction
	}
	var out sso.Transaction
	var expires time.Time
	var now time.Time
	err := s.db.WithTenant(ctx, t, func(ctx context.Context, dbtx store.Tx) error {
		var err error
		if now, err = s.now(ctx, dbtx); err != nil {
			return err
		}
		var intent string
		row := dbtx.QueryRow(ctx, sqlConsume, t.String(), h.hash())
		if err := row.Scan(&out.IdPID, &intent, &out.State, &out.Nonce, &out.Verifier, &out.RequestID,
			&out.ReturnPath, &out.CreatedAt, &expires); err != nil {
			return err
		}
		out.Intent = sso.Intent(intent)
		return nil
	})
	if store.IsNoRows(err) {
		return sso.Transaction{}, ErrNoTransaction
	}
	if err != nil {
		return sso.Transaction{}, fmt.Errorf("signin: consume transaction: %w", err)
	}
	out.CreatedAt = out.CreatedAt.UTC()
	if !now.Before(expires) || now.Sub(out.CreatedAt) > TransactionTTL {
		return sso.Transaction{}, ErrTransactionExpired
	}
	return out, nil
}
