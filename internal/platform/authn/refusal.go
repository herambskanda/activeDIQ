package authn

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// KindSecondFactorRefused records an AN-10 attempt that did not become a session (T-0418). Outcome is
// denied; Reason is one of the Reason* codes; Target is the pending sign-in; the details are the account,
// the attempt number, the first factor, the address that first factor came from and the address of this
// attempt. It never carries the code, the handle or its hash.
const KindSecondFactorRefused audit.Kind = "authn.secondfactor.refused"

// KindPendingPurged is what the pending sign-in retention purge records about itself.
const KindPendingPurged audit.Kind = "authn.pending.purged"

// Refused* are the reason codes of KindSecondFactorRefused.
const (
	RefusedPendingExpired     = "pending_expired"     // the five minutes ran out; this attempt ended it
	RefusedAttemptsExhausted  = "attempts_exhausted"  // the fifth wrong code was already spent; this attempt ended it
	RefusedWrongCode          = "wrong_code"          // live pending sign-in, code did not match
	RefusedCodeReplayed       = "code_replayed"       // a code already used in its step
	RefusedFactorPaused       = "factor_paused"       // the TOTP failure budget paused the factor
	RefusedAccountDisabled    = "account_disabled"    // the account is no longer active
	RefusedNoEnrolment        = "no_totp_enrolment"   // active account without a console TOTP enrolment
	RefusedCredentialsChanged = "credentials_changed" // password, MFA or role changed after the first factor
)

// refusal is the in-transaction signal that a live attempt must be answered with ErrSecondFactorRefused
// and audited under reason once the (rolled back) transaction is over.
type refusal struct{ reason string }

func (r *refusal) Error() string        { return ErrSecondFactorRefused.Error() }
func (r *refusal) Is(target error) bool { return target == ErrSecondFactorRefused }

// refuse appends the refusal event to tx.
func (f *SecondFactor) refuse(ctx context.Context, tx store.Tx, ref pendingRef, now time.Time, reason string, from netip.Addr) error {
	details := []chain.Detail{
		{Key: "account", Value: ref.Account},
		{Key: "attempt", Value: strconv.Itoa(ref.Attempt)},
		{Key: "first_factor", Value: string(ref.First)},
	}
	if ref.ClientIP.IsValid() {
		details = append(details, chain.Detail{Key: "first_factor_ip", Value: ref.ClientIP.Unmap().String()})
	}
	if from.IsValid() {
		details = append(details, chain.Detail{Key: "source_ip", Value: from.Unmap().String()})
	}
	phase := "refused." + strconv.Itoa(ref.Attempt)
	if reason == RefusedPendingExpired || reason == RefusedAttemptsExhausted {
		phase = "ended" // once per pending sign-in
	}
	ev := audit.Event{
		ID: "authn.pending." + ref.ID + "." + phase, Kind: KindSecondFactorRefused, At: now, Actor: accountChain(ref.Account),
		Target:    authority.TargetRef{GUID: ref.ID, Class: "pending_signin"},
		Component: "authn", Outcome: audit.Denied, Reason: reason, Details: details,
	}
	if err := f.Audit.Append(ctx, tx, ev); err != nil {
		return fmt.Errorf("authn: audit second-factor refusal: %w", err)
	}
	return nil
}

// refuseOwn records a refusal in its own transaction, after the attempt's transaction rolled back.
func (f *SecondFactor) refuseOwn(ctx context.Context, ref pendingRef, reason string, from netip.Addr) error {
	return f.DB.WithTenant(ctx, ref.Tenant, func(ctx context.Context, tx store.Tx) error {
		now, err := f.Pending.now(ctx, tx)
		if err != nil {
			return err
		}
		return f.refuse(ctx, tx, ref, now, reason, from)
	})
}
