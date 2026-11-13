package authn

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.authn_ad_attempts", Entity: "DM-30", Kind: tablekind.Tenant})

// ErrADAttemptsRefused is the one refusal of ADAttempts.Take: the budget is spent, or the domain's
// lockout threshold is 0, 1, unknown or could not be read. The caller answers its ordinary generic
// failure and does not contact the directory.
var ErrADAttemptsRefused = errors.New("authn: AD password attempt refused")

// LockoutThresholds is the port that supplies a domain's lockout policy (the connector wires it with
// the consumers): the lockout threshold and the lockout observation window, the time with no bad
// password after which AD resets its own count. known is false when either could not be determined.
type LockoutThresholds interface {
	LockoutThreshold(ctx context.Context, t tenant.ID, domain string) (threshold int, observation time.Duration, known bool, err error)
}

// ADAttempts is the per-account counter of TM-TB1-T9, shared by every node through PostgreSQL. Take is
// called before each AD password check; Succeeded after a good one.
//
// It reserves the attempt before the directory is contacted, so concurrent attempts cannot all pass a
// check made at the same count: at most threshold-1 attempts reach the directory per window. With
// threshold 5, four attempts go through and the fifth is refused.
//
// The window slides: AD measures its observation window from the last bad password, so every take,
// admitted or refused, restarts ours. The count only restarts after a full window with no attempt at
// all, so it never resets while AD's count can still be live. The window is the larger of Window and
// the domain's observation window. A refused take also restarts the window, so continued attempts keep
// the account refused (bounded by the per-IP limits, see TM-TB1-T9).
//
// Residuals: bad passwords AD counts from other sources (workstation logons, other applications) are
// invisible here, so threshold-1 is not an absolute guarantee; and an attacker can spend a victim's
// budget to deny their enrolment, so the enrolment page (AN-5) must show only its generic error.
type ADAttempts struct {
	DB         *store.DB
	Thresholds LockoutThresholds
	// Window is a minimum counting window, raising the domain's observation window if larger; zero
	// means use the observation window alone.
	Window time.Duration
}

// sqlTakeADAttempt takes one attempt and returns the count after it, in one statement on the database
// clock. The upsert locks the row, so concurrent takes on a key run one after the other. A row with no
// take for a full window restarts at 1; every take moves window_start (the last attempt) to now. The count is capped at $4 (the threshold) so refused attempts cannot grow it.
// The clock is read once, in the innermost subselect.
const sqlTakeADAttempt = `INSERT INTO public.authn_ad_attempts AS a (tenant_id, key_hash, attempts, window_start)
VALUES ($1::uuid, $2, 1, clock_timestamp())
ON CONFLICT (tenant_id, key_hash) DO UPDATE SET (attempts, window_start) = (
  SELECT CASE WHEN c.at - a.window_start >= make_interval(secs => $3::float8) THEN 1 ELSE least(a.attempts + 1, $4::int) END,
         c.at
  FROM (SELECT clock_timestamp() AS at) c)
RETURNING a.attempts`

const sqlResetADAttempts = `DELETE FROM public.authn_ad_attempts WHERE tenant_id = $1::uuid AND key_hash = $2`

// Take reserves one attempt for the account named by key (a 32-byte HMAC computed by the caller over
// tenant, domain and account). It returns nil if the attempt may go to the directory and
// ErrADAttemptsRefused if not. Fail closed: an unknown, zero or one threshold, a threshold error, a bad
// key or any database error refuses.
func (c *ADAttempts) Take(ctx context.Context, t tenant.ID, domain string, key []byte) error {
	if c == nil || c.DB == nil || c.Thresholds == nil || t.IsZero() || domain == "" || len(key) != 32 {
		return ErrADAttemptsRefused
	}
	threshold, observation, known, err := c.Thresholds.LockoutThreshold(ctx, t, domain)
	if err != nil || !known || threshold <= 1 || observation <= 0 {
		return ErrADAttemptsRefused
	}
	window := max(c.Window, observation)
	var n int
	err = c.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, sqlTakeADAttempt, t.String(), key, window.Seconds(), threshold).Scan(&n)
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrADAttemptsRefused, err)
	}
	if n >= threshold {
		return ErrADAttemptsRefused
	}
	return nil
}

// Succeeded clears the account's count after the directory accepted its password.
func (c *ADAttempts) Succeeded(ctx context.Context, t tenant.ID, key []byte) error {
	if c == nil || c.DB == nil || t.IsZero() || len(key) != 32 {
		return ErrInvalid
	}
	return c.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		if _, err := tx.Exec(ctx, sqlResetADAttempts, t.String(), key); err != nil {
			return fmt.Errorf("authn: reset AD attempts: %w", err)
		}
		return nil
	})
}
