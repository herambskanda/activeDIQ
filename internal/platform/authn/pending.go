package authn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.authn_pending_signins", Entity: "DM-31", Kind: tablekind.Tenant})

// The pending sign-in of threat model §7.6 rule 1: what a first factor (AN-3, AN-8, AN-9) yields
// instead of a session. It is bound to one account and to the first factor, lives at most PendingSignInTTL,
// allows at most MaxSignInAttempts second-factor submissions, and is consumed by the AN-10 success
// that creates the session. It authorises nothing else.
const (
	PendingSignInTTL  = 5 * time.Minute
	MaxSignInAttempts = 5

	// PendingCookieName carries the handle. The __Host- prefix makes browsers accept it only Secure,
	// with Path=/ and no Domain. The handle is never read from a URL or a body.
	PendingCookieName = "__Host-adiq_pending"
)

// Errors. Callers answer all of them with the same 401 as any sign-in failure; they differ only for
// the audit trail.
var (
	// ErrPendingInvalid: no usable pending sign-in (missing, malformed, unknown, expired, out of
	// attempts, consumed, or its account is no longer active).
	ErrPendingInvalid = errors.New("authn: no valid pending sign-in")
	// ErrSecondFactorRefused: the pending sign-in is live but the second factor did not pass (wrong,
	// replayed or paused code, or no TOTP enrolment).
	ErrSecondFactorRefused = errors.New("authn: second factor refused")
)

// FirstFactor is what created a pending sign-in.
type FirstFactor string

// First factors. The value is also the method name recorded on the session.
const (
	FirstPassword FirstFactor = "password" // AN-8
	FirstSSO      FirstFactor = "sso"      // AN-3, IdP not MFA-asserting
	FirstKerberos FirstFactor = "kerberos" // AN-9
)

func (f FirstFactor) valid() bool {
	return f == FirstPassword || f == FirstSSO || f == FirstKerberos
}

// PendingHandle is the secret behind the pending cookie: 256 random bits, "<tenant>.<secret>" like a
// session token but a distinct type, so it cannot be presented as a session. It reaches the client
// once, in the cookie. String redacts.
type PendingHandle struct{ tok Token }

// Reveal returns the handle text, for the one response that sets the cookie.
func (h PendingHandle) Reveal() string { return h.tok.Reveal() }

// String redacts.
func (PendingHandle) String() string { return "authn.PendingHandle(redacted)" }

// GoString redacts for %#v.
func (PendingHandle) GoString() string { return "authn.PendingHandle(redacted)" }

// hash is what the table stores; the prefix keeps it apart from session-token hashes.
func (h PendingHandle) hash() []byte {
	sum := sha256.Sum256([]byte("activediq pending v1\x00" + h.tok.text))
	return sum[:]
}

// ParsePendingHandle reads handle text from a client; shape only.
func ParsePendingHandle(s string) (PendingHandle, error) {
	t, err := ParseToken(s)
	if err != nil {
		return PendingHandle{}, ErrPendingInvalid
	}
	return PendingHandle{tok: t}, nil
}

// PendingStore holds pending sign-ins in PostgreSQL, so any node completes a sign-in another started.
type PendingStore struct {
	db    *store.DB
	clock func() time.Time // nil: the database clock
}

// NewPendingStore returns a PendingStore. clock is nil in production; tests set it.
func NewPendingStore(db *store.DB, clock func() time.Time) (*PendingStore, error) {
	if db == nil {
		return nil, errors.New("authn: PendingStore needs a database")
	}
	return &PendingStore{db: db, clock: clock}, nil
}

func (p *PendingStore) now(ctx context.Context, tx store.Tx) (time.Time, error) {
	if p.clock != nil {
		return p.clock().UTC(), nil
	}
	var t time.Time
	if err := tx.QueryRow(ctx, sqlClock).Scan(&t); err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// BeginInput is what a first factor knows.
type BeginInput struct {
	Tenant      tenant.ID
	Account     string // the console account's ID, a canonical UUID
	FirstFactor FirstFactor
	ClientIP    netip.Addr // zero when unknown
}

// Begin records a passed first factor and returns the handle for the pending cookie. It never creates
// a session.
func (p *PendingStore) Begin(ctx context.Context, in BeginInput) (PendingHandle, error) {
	if in.Tenant.IsZero() || !validAccount(in.Account) || !in.FirstFactor.valid() {
		return PendingHandle{}, ErrInvalid
	}
	tok, err := newToken(in.Tenant)
	if err != nil {
		return PendingHandle{}, err
	}
	h := PendingHandle{tok: tok}
	var ip *netip.Addr
	if in.ClientIP.IsValid() {
		a := in.ClientIP.Unmap()
		ip = &a
	}
	err = p.db.WithTenant(ctx, in.Tenant, func(ctx context.Context, tx store.Tx) error {
		now, err := p.now(ctx, tx)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO public.authn_pending_signins
  (tenant_id, handle_hash, account_id, first_factor, client_ip, created_at, expires_at)
VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7)`,
			in.Tenant.String(), h.hash(), in.Account, string(in.FirstFactor), ip, now, now.Add(PendingSignInTTL))
		return err
	})
	if err != nil {
		return PendingHandle{}, fmt.Errorf("authn: begin pending sign-in: %w", err)
	}
	return h, nil
}

// pendingRef is a pending sign-in that has been charged one attempt.
type pendingRef struct {
	Tenant   tenant.ID
	ID       string
	Account  string
	First    FirstFactor
	ClientIP netip.Addr
}

// charge spends one attempt of the pending sign-in h names, in its own committed transaction and before
// the code is looked at, so neither a rollback nor racing requests can give a caller more than
// MaxSignInAttempts evaluations. A pending sign-in that is expired or out of attempts is marked dead.
func (p *PendingStore) charge(ctx context.Context, h PendingHandle) (pendingRef, error) {
	t, err := h.tok.Tenant()
	if err != nil {
		return pendingRef{}, ErrPendingInvalid
	}
	var (
		ref     pendingRef
		outcome error
	)
	err = p.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := p.now(ctx, tx)
		if err != nil {
			return err
		}
		var (
			attempts int
			state    string
			expires  time.Time
			first    string
			ip       *netip.Addr
		)
		err = tx.QueryRow(ctx, `SELECT id::text, account_id::text, first_factor, client_ip, attempts, state, expires_at
FROM public.authn_pending_signins WHERE tenant_id = $1::uuid AND handle_hash = $2 FOR UPDATE`, t.String(), h.hash()).
			Scan(&ref.ID, &ref.Account, &first, &ip, &attempts, &state, &expires)
		if store.IsNoRows(err) {
			outcome = ErrPendingInvalid
			return nil
		}
		if err != nil {
			return err
		}
		if state != "active" {
			outcome = ErrPendingInvalid
			return nil
		}
		if !now.Before(expires) || attempts >= MaxSignInAttempts {
			if _, err := tx.Exec(ctx, `UPDATE public.authn_pending_signins SET state = 'dead', ended_at = $3
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'active'`, t.String(), ref.ID, now); err != nil {
				return err
			}
			outcome = ErrPendingInvalid
			return nil // commit the marking
		}
		if _, err := tx.Exec(ctx, `UPDATE public.authn_pending_signins SET attempts = attempts + 1
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'active'`, t.String(), ref.ID); err != nil {
			return err
		}
		ref.Tenant, ref.First = t, FirstFactor(first)
		if ip != nil {
			ref.ClientIP = *ip
		}
		return nil
	})
	if err != nil {
		return pendingRef{}, fmt.Errorf("authn: charge pending sign-in: %w", err)
	}
	if outcome != nil {
		return pendingRef{}, outcome
	}
	return ref, nil
}

// consume ends the pending sign-in in the caller's transaction, so it commits with the session it
// pays for. It reports false when the record is no longer active or has expired, which is how a
// concurrent winner or a late request loses.
func (p *PendingStore) consume(ctx context.Context, tx store.Tx, ref pendingRef) (bool, error) {
	now, err := p.now(ctx, tx)
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.authn_pending_signins SET state = 'consumed', ended_at = $3
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'active' AND expires_at > $3`, ref.Tenant.String(), ref.ID, now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// SecondFactor is AN-10: it turns a pending sign-in and a correct second factor into a session.
type SecondFactor struct {
	DB       *store.DB
	Pending  *PendingStore
	Sessions *Store
	TOTP     *Service
}

// VerifyTOTP checks a TOTP code for the pending sign-in h names. One attempt is charged first. On
// success, in one transaction, the pending sign-in is consumed and a session with a new ID is created
// (methods: the first factor and "totp"); a rollback leaves neither. Every refusal is ErrPendingInvalid
// or ErrSecondFactorRefused and creates nothing.
func (f *SecondFactor) VerifyTOTP(ctx context.Context, h PendingHandle, code string) (CreateResult, error) {
	if f.DB == nil || f.Pending == nil || f.Sessions == nil || f.TOTP == nil {
		return CreateResult{}, errors.New("authn: SecondFactor is not fully configured")
	}
	ref, err := f.Pending.charge(ctx, h)
	if err != nil {
		return CreateResult{}, err
	}
	var res CreateResult
	err = f.DB.WithTenant(ctx, ref.Tenant, func(ctx context.Context, tx store.Tx) error {
		ids, err := activeTOTPIDs(ctx, tx, ref.Tenant, ref.Account)
		if err != nil {
			return err
		}
		if ids == nil {
			return ErrSecondFactorRefused // no active account, or no TOTP enrolled
		}
		matched := false
		for _, id := range ids {
			switch err := f.TOTP.Verify(ctx, tx, ref.Tenant, id, code); {
			case err == nil:
				matched = true
			case errors.Is(err, ErrCodeRejected), errors.Is(err, ErrCodeReplayed), errors.Is(err, ErrFactorPaused):
				continue
			default:
				return err // an infrastructure or integrity fault: fail closed
			}
			break
		}
		if !matched {
			return ErrSecondFactorRefused
		}
		won, err := f.Pending.consume(ctx, tx, ref)
		if err != nil {
			return err
		}
		if !won {
			return ErrPendingInvalid
		}
		now, err := f.Pending.now(ctx, tx)
		if err != nil {
			return err
		}
		res, err = f.Sessions.CreateTx(ctx, tx, CreateInput{Tenant: ref.Tenant, Account: ref.Account,
			Methods: []string{string(ref.First), methodTOTP}, MFAAt: &now, ClientIP: ref.ClientIP})
		return err
	})
	if err != nil {
		if errors.Is(err, ErrSecondFactorRefused) || errors.Is(err, ErrPendingInvalid) {
			return CreateResult{}, err
		}
		return CreateResult{}, fmt.Errorf("authn: second factor: %w", err)
	}
	return res, nil
}

// activeTOTPIDs lists the active console-MFA TOTP enrolments of an active account, oldest first. Only
// enrolments keyed by the account itself count: an end-user (AN-5) enrolment is keyed by directory
// object and is gated by the AD password alone, so accepting it here would make both factors one
// password (TM §7.6 rule 1; DM-04.I2). nil when the account is not active or has none.
func activeTOTPIDs(ctx context.Context, tx store.Tx, t tenant.ID, account string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT e.id::text FROM public.authn_authenticator_enrollments e
JOIN public.authn_accounts a ON a.tenant_id = e.tenant_id AND e.account_id = a.id
WHERE a.tenant_id = $1::uuid AND a.id = $2::uuid AND a.state = 'active' AND e.method = 'totp' AND e.state = 'active'
ORDER BY e.created_at, e.id`, t.String(), account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
