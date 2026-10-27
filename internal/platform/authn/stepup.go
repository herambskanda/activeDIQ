package authn

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Step-up re-authentication (threat model §7.4, TM-D16 part 1). An operation the catalogue flags
// StepUp (operation.Descriptor.StepUp) needs a second-factor verification inside a short window,
// whatever the session's age. The session records mfa_at (sign-in sets it; Reverify moves it forward).
// The flag is never decided here: apihost reads the permission list generated from the catalogue and
// asks Fresh; the operation runner reads Descriptor.StepUp and Request.FreshStepUp.

// StepUpBounds are the platform limits of a tenant's step-up window.
type StepUpBounds struct{ Min, Max time.Duration }

// DefaultStepUpBounds allow a window of 1 to 15 minutes. A window is never unbounded.
var DefaultStepUpBounds = StepUpBounds{Min: time.Minute, Max: 15 * time.Minute}

// DefaultStepUpWindow is used for a tenant that has configured nothing.
const DefaultStepUpWindow = 5 * time.Minute

// StepUpWindows gives a tenant's window. A nil source means DefaultStepUpWindow for every tenant.
type StepUpWindows interface {
	StepUpWindow(ctx context.Context, t tenant.ID) (time.Duration, error)
}

// StaticStepUpWindow is one window for every tenant.
type StaticStepUpWindow time.Duration

// StepUpWindow implements StepUpWindows.
func (w StaticStepUpWindow) StepUpWindow(context.Context, tenant.ID) (time.Duration, error) {
	return time.Duration(w), nil
}

var (
	// ErrStepUpRefused is every failed re-verification: wrong, replayed or paused code, no enrolled
	// factor, an account that is no longer active. One answer, so a caller learns nothing more.
	ErrStepUpRefused = errors.New("authn: step-up verification refused")
	// ErrStepUpWindow is a window outside the bounds. Nothing is clamped.
	ErrStepUpWindow = errors.New("authn: step-up window outside the platform bounds")
)

// Audit kinds of step-up. Neither carries a code or a token.
const (
	KindStepUpVerified audit.Kind = "authn.stepup.verified"
	KindStepUpFailed   audit.Kind = "authn.stepup.failed"
)

// StepUp implements apihost.StepUpChecker and the re-verification that refreshes mfa_at.
type StepUp struct {
	Sessions *Store
	TOTP     *Service
	Windows  StepUpWindows // nil: DefaultStepUpWindow
	Bounds   StepUpBounds  // zero: DefaultStepUpBounds
}

var _ apihost.StepUpChecker = (*StepUp)(nil)

// readyCheck is what the freshness check needs: the session store only. It reads mfa_at and verifies
// nothing, so a composition without a TOTP key source can still answer Fresh (and refuse Reverify).
func (u *StepUp) readyCheck() error {
	if u == nil || u.Sessions == nil {
		return errors.New("authn: StepUp is not fully configured")
	}
	return nil
}

// ready is what Reverify needs: the session store and the TOTP factor.
func (u *StepUp) ready() error {
	if err := u.readyCheck(); err != nil {
		return err
	}
	if u.TOTP == nil {
		return errors.New("authn: StepUp is not fully configured")
	}
	return nil
}

func (u *StepUp) window(ctx context.Context, t tenant.ID) (time.Duration, error) {
	w := DefaultStepUpWindow
	if u.Windows != nil {
		var err error
		if w, err = u.Windows.StepUpWindow(ctx, t); err != nil {
			return 0, fmt.Errorf("authn: read step-up window: %w", err)
		}
	}
	b := u.Bounds
	if b == (StepUpBounds{}) {
		b = DefaultStepUpBounds
	}
	if w < b.Min || w > b.Max {
		return 0, fmt.Errorf("%w: must be between %s and %s", ErrStepUpWindow, b.Min, b.Max)
	}
	return w, nil
}

// Fresh reports whether the principal's session passed MFA inside its tenant's window. Only a console
// session can: an API token has no interactive second factor, so it is never fresh. Any doubt (no
// session, ended, no mfa_at, a timestamp in the future) is false. An error is an infrastructure fault
// and the caller refuses the request.
func (u *StepUp) Fresh(ctx context.Context, p apihost.Principal) (bool, error) {
	if p.Kind != apihost.KindSession || p.SessionID == "" || p.ID == "" {
		return false, nil
	}
	t, err := tenant.Parse(p.Tenant)
	if err != nil {
		return false, nil
	}
	return u.fresh(ctx, t, p.SessionID, p.ID)
}

// FreshSession answers the same question for a caller that holds only the tenant and the session handle
// of an already authenticated request (the connections attestation, which has authorised the requester
// itself). The session must be active and its MFA inside the window; any doubt is false.
func (u *StepUp) FreshSession(ctx context.Context, t tenant.ID, sessionID string) (bool, error) {
	return u.fresh(ctx, t, sessionID, "")
}

// fresh is the shared check. account, when not empty, must own the session.
func (u *StepUp) fresh(ctx context.Context, t tenant.ID, sessionID, account string) (bool, error) {
	if err := u.readyCheck(); err != nil {
		return false, err
	}
	if t.IsZero() || !validAccount(sessionID) {
		return false, nil
	}
	w, err := u.window(ctx, t)
	if err != nil {
		return false, err
	}
	var fresh bool
	err = u.Sessions.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := u.Sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		var mfa *time.Time
		var acct string
		err = tx.QueryRow(ctx, `SELECT mfa_at, account_id::text FROM public.authn_sessions
WHERE tenant_id = $1 AND id = $2::uuid AND state = 'active' AND idle_expiry > $3 AND absolute_expiry > $3`,
			t.String(), sessionID, now).Scan(&mfa, &acct)
		if store.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		fresh = (account == "" || acct == account) && mfa != nil && !mfa.After(now) && now.Sub(*mfa) < w
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("authn: step-up check: %w", err)
	}
	return fresh, nil
}

// Reverify checks a TOTP code of the session's own account and, on success, sets the session's mfa_at
// to now. On a refusal it clears authority_factor_at (DM-31.I3: a failed second-factor check must not
// leave AD-side authority standing) and keeps mfa_at as it was. The refusal and its audit record
// COMMIT; the per-enrolment failure budget (T-0361) is charged separately and also survives. The
// token must be live: a session that is revoked or expired is ErrSessionNotFound/ErrExpired/ErrRevoked.
func (u *StepUp) Reverify(ctx context.Context, tok Token, code string) (Session, error) {
	if err := u.ready(); err != nil {
		return Session{}, err
	}
	sess, err := u.Sessions.Lookup(ctx, tok)
	if err != nil {
		return Session{}, err
	}
	var (
		out     Session
		refused bool
	)
	err = u.Sessions.db.WithTenant(ctx, sess.Tenant, func(ctx context.Context, tx store.Tx) error {
		now, err := u.Sessions.now(ctx, tx)
		if err != nil {
			return err
		}
		// Serialise concurrent re-verifications of one session and re-check it is still active.
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM public.authn_sessions WHERE tenant_id = $1 AND id = $2::uuid FOR UPDATE`,
			sess.Tenant.String(), sess.ID).Scan(&state); err != nil {
			if store.IsNoRows(err) {
				return ErrSessionNotFound
			}
			return err
		}
		if state != string(SessionActive) {
			return ErrRevoked
		}
		matched, err := u.matchTOTP(ctx, tx, sess, code)
		if err != nil {
			return err
		}
		if matched {
			if _, err := tx.Exec(ctx, `UPDATE public.authn_sessions SET mfa_at = $3
WHERE tenant_id = $1 AND id = $2::uuid AND state = 'active'`, sess.Tenant.String(), sess.ID, now); err != nil {
				return err
			}
			sess.MFAAt = &now
			out = sess
			return u.emit(ctx, tx, now, KindStepUpVerified, audit.Success, sess)
		}
		refused = true
		if _, err := tx.Exec(ctx, `UPDATE public.authn_sessions SET authority_factor_at = NULL
WHERE tenant_id = $1 AND id = $2::uuid AND state = 'active'`, sess.Tenant.String(), sess.ID); err != nil {
			return err
		}
		return u.emit(ctx, tx, now, KindStepUpFailed, audit.Failure, sess)
	})
	if err != nil {
		return Session{}, fmt.Errorf("authn: step-up: %w", err)
	}
	if refused {
		return Session{}, ErrStepUpRefused
	}
	return out, nil
}

// matchTOTP tries the account's console-MFA enrolments (never an end-user one; see activeTOTPIDs).
func (u *StepUp) matchTOTP(ctx context.Context, tx store.Tx, sess Session, code string) (bool, error) {
	ids, err := activeTOTPIDs(ctx, tx, sess.Tenant, sess.Account)
	if err != nil {
		return false, err
	}
	for _, id := range ids {
		switch err := u.TOTP.Verify(ctx, tx, sess.Tenant, id, code); {
		case err == nil:
			return true, nil
		case errors.Is(err, ErrCodeRejected), errors.Is(err, ErrCodeReplayed), errors.Is(err, ErrFactorPaused):
			continue
		default:
			return false, err // fail closed on a fault
		}
	}
	return false, nil
}

func (u *StepUp) emit(ctx context.Context, tx store.Tx, now time.Time, kind audit.Kind, out audit.Outcome, s Session) error {
	ev := audit.Event{
		// One event per attempt: the nanosecond makes the ID unique, a retried tx rewrites the same one.
		ID: "authn.session." + s.ID + ".stepup." + strconv.FormatInt(now.UnixNano(), 10), Kind: kind, At: now,
		Actor: accountChain(s.Account), Target: authority.TargetRef{GUID: s.ID, Class: "session"},
		Component: "authn", Outcome: out, Details: []chain.Detail{{Key: "account", Value: s.Account}},
	}
	if err := u.Sessions.audit.Append(ctx, tx, ev); err != nil {
		return fmt.Errorf("authn: audit step-up: %w", err)
	}
	return nil
}
