package authn

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
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
	audit audit.Sink
	clock func() time.Time // nil: the database clock
}

// NewPendingStore returns a PendingStore. sink records authn.pending.begun and is required; it must be
// bound to db (audit.NewChainer) so the event is chained in the transaction that creates the pending
// sign-in. clock is nil in production; tests set it.
func NewPendingStore(db *store.DB, sink audit.Sink, clock func() time.Time) (*PendingStore, error) {
	if db == nil {
		return nil, errors.New("authn: PendingStore needs a database")
	}
	if sink == nil {
		return nil, errors.New("authn: PendingStore needs an audit sink")
	}
	return &PendingStore{db: db, audit: sink, clock: clock}, nil
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
	// Epoch is the account's epoch (Store.Epoch) read before the first factor was verified. Required: a
	// second factor completed after a password/MFA reset or role change is refused (T-0429).
	Epoch Epoch
}

// Begin records a passed first factor and returns the handle for the pending cookie. It never creates
// a session. The row and its authn.pending.begun event commit together: if the event cannot be
// appended, no pending sign-in exists (fail closed), so a first factor that is never followed by a
// second one stays visible after PurgePending removes the row.
func (p *PendingStore) Begin(ctx context.Context, in BeginInput) (PendingHandle, error) {
	if in.Tenant.IsZero() || !validAccount(in.Account) || !in.FirstFactor.valid() || !in.Epoch.ok {
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
		var id string
		if err := tx.QueryRow(ctx, `INSERT INTO public.authn_pending_signins
  (tenant_id, handle_hash, account_id, first_factor, client_ip, created_at, expires_at, account_epoch)
VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8) RETURNING id::text`,
			in.Tenant.String(), h.hash(), in.Account, string(in.FirstFactor), ip, now, now.Add(PendingSignInTTL), in.Epoch.n).Scan(&id); err != nil {
			return err
		}
		return p.begun(ctx, tx, id, in, now)
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
	Epoch    Epoch
	Attempt  int // 1-based number of the attempt just charged
}

// charge spends one attempt of the pending sign-in h names, in its own committed transaction and before
// the code is looked at, so neither a rollback nor racing requests can give a caller more than
// MaxSignInAttempts evaluations. A pending sign-in that is expired or out of attempts is marked dead.
//
// onDead is called in the same transaction as the marking, once, when this call is the one that ended
// the pending sign-in (reason "expired" or "attempts_exhausted"), so the audit event commits with it.
func (p *PendingStore) charge(ctx context.Context, h PendingHandle, onDead func(ctx context.Context, tx store.Tx, ref pendingRef, now time.Time, reason string) error) (pendingRef, error) {
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
		err = tx.QueryRow(ctx, `SELECT id::text, account_id::text, first_factor, client_ip, attempts, state, expires_at, account_epoch
FROM public.authn_pending_signins WHERE tenant_id = $1::uuid AND handle_hash = $2 FOR UPDATE`, t.String(), h.hash()).
			Scan(&ref.ID, &ref.Account, &first, &ip, &attempts, &state, &expires, &ref.Epoch.n)
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
			reason := RefusedPendingExpired
			if now.Before(expires) {
				reason = RefusedAttemptsExhausted
			}
			ref.Tenant, ref.First, ref.Attempt = t, FirstFactor(first), attempts
			if ip != nil {
				ref.ClientIP = *ip
			}
			return onDead(ctx, tx, ref, now, reason) // commit the marking and its event
		}
		if _, err := tx.Exec(ctx, `UPDATE public.authn_pending_signins SET attempts = attempts + 1
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'active'`, t.String(), ref.ID); err != nil {
			return err
		}
		ref.Tenant, ref.First, ref.Epoch.ok, ref.Attempt = t, FirstFactor(first), true, attempts+1
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
	// Audit records the refused attempts (authn.secondfactor.refused). Required; it must be bound to DB
	// (audit.NewChainer) so an event is chained in the transaction that writes it.
	Audit audit.Sink
}

// VerifyTOTP checks a TOTP code for the pending sign-in h names. One attempt is charged first. On
// success, in one transaction, the pending sign-in is consumed and a session with a new ID is created
// (methods: the first factor and "totp"); a rollback leaves neither. Every refusal is ErrPendingInvalid
// or ErrSecondFactorRefused and creates nothing. from is the address the attempt arrived from (zero when
// unknown); a refusal of a known pending sign-in is audited with it (see refuse). A handle that names no
// pending sign-in, or one already ended, is not audited: there is no account to name and a flood of
// them must not flood the trail.
func (f *SecondFactor) VerifyTOTP(ctx context.Context, h PendingHandle, code string, from netip.Addr) (CreateResult, error) {
	if f.DB == nil || f.Pending == nil || f.Sessions == nil || f.TOTP == nil || f.Audit == nil {
		return CreateResult{}, errors.New("authn: SecondFactor is not fully configured")
	}
	ref, err := f.Pending.charge(ctx, h, func(ctx context.Context, tx store.Tx, ref pendingRef, now time.Time, reason string) error {
		return f.refuse(ctx, tx, ref, now, reason, from)
	})
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
			reason := RefusedAccountDisabled
			if active, err := accountActive(ctx, tx, ref.Tenant, ref.Account); err != nil {
				return err
			} else if active {
				reason = RefusedNoEnrolment
			}
			return &refusal{reason: reason}
		}
		reason := RefusedWrongCode
		matched := false
		for _, id := range ids {
			switch err := f.TOTP.Verify(ctx, tx, ref.Tenant, id, code); {
			case err == nil:
				matched = true
			case errors.Is(err, ErrCodeRejected):
				continue
			case errors.Is(err, ErrCodeReplayed):
				reason = RefusedCodeReplayed
				continue
			case errors.Is(err, ErrFactorPaused):
				reason = RefusedFactorPaused
				continue
			default:
				return err // an infrastructure or integrity fault: fail closed
			}
			break
		}
		if !matched {
			return &refusal{reason: reason}
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
			Methods: []string{string(ref.First), methodTOTP}, MFAAt: &now, ClientIP: ref.ClientIP, Epoch: ref.Epoch})
		return err
	})
	if err != nil {
		var r *refusal
		switch {
		case errors.As(err, &r):
			// The transaction above rolled back, so the refusal is recorded in its own.
			if aerr := f.refuseOwn(ctx, ref, r.reason, from); aerr != nil {
				return CreateResult{}, aerr
			}
			return CreateResult{}, ErrSecondFactorRefused
		case errors.Is(err, ErrPendingInvalid):
			return CreateResult{}, err
		case errors.Is(err, ErrCredentialsChanged):
			// the first factor predates a reset; start over
			if aerr := f.refuseOwn(ctx, ref, RefusedCredentialsChanged, from); aerr != nil {
				return CreateResult{}, aerr
			}
			return CreateResult{}, ErrPendingInvalid
		}
		return CreateResult{}, fmt.Errorf("authn: second factor: %w", err)
	}
	return res, nil
}

// accountActive reports whether the console account exists and is active.
func accountActive(ctx context.Context, tx store.Tx, t tenant.ID, account string) (bool, error) {
	var state string
	err := tx.QueryRow(ctx, `SELECT state FROM public.authn_accounts WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), account).Scan(&state)
	if store.IsNoRows(err) {
		return false, nil
	}
	return state == "active", err
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
