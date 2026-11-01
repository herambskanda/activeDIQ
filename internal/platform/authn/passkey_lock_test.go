package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// The passkey lock (P1 of factor-policy-phishing-resistant-mfa.md, T-0852): an account with an active
// second-factor WebAuthn credential does not finish sign-in with a TOTP code.

func (e *pendEnv) addKey(t *testing.T, purpose string) *softKey {
	t.Helper()
	k := newSoftKey(t)
	if err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
		_, err := insertCredential(ctx, tx, e.ten, e.account, purpose, k.credential())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return k
}

func (e *pendEnv) revokeKeys(t *testing.T) {
	t.Helper()
	if err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE public.authn_webauthn_credentials SET state = 'revoked'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *pendEnv) totpFailures(t *testing.T) int {
	t.Helper()
	return mustInt(e.query(t, `SELECT count(*)::text FROM public.authn_totp_failures`)[0])
}

// problemJSON is the whole uniform answer as the host would serialise it.
func problemJSON(t *testing.T, err error) string {
	t.Helper()
	wantSignInFailed(t, err)
	b, jerr := json.Marshal(err)
	if jerr != nil {
		t.Fatal(jerr)
	}
	return string(b)
}

func TestVerifyTOTPRefusedWhenPasskeyActive(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		hd := Handlers{SecondFactor: cookieAdapter{e.sf}}

		// The wrong-code answer, before the account has a key, is the reference.
		_, wrong := hd.VerifyTOTPSignIn(ctx, totpInput(e.begin(t).Reveal(), e.bad()))
		want := problemJSON(t, wrong)

		e.addKey(t, purposeSecondFactor)
		h := e.begin(t)
		if _, err := e.sf.VerifyTOTP(ctx, h, e.good(), netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("valid code under the passkey lock: %v, want ErrSecondFactorRefused", err)
		}
		out, err := hd.VerifyTOTPSignIn(ctx, totpInput(e.begin(t).Reveal(), e.good()))
		if out != nil {
			t.Fatalf("output %#v for a refused code", out)
		}
		if got := problemJSON(t, err); got != want {
			t.Fatalf("policy refusal differs from wrong code:\n got %s\nwant %s", got, want)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions, want none", n)
		}
	})
}

func TestPasskeyLockDoesNotSpendTOTP(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		e.addKey(t, purposeSecondFactor)
		h := e.begin(t)
		if _, err := e.sf.VerifyTOTP(ctx, h, e.good(), attackerIP); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("under the lock: %v", err)
		}
		evs := e.sink.of(KindSecondFactorRefused)
		if len(evs) != 1 {
			t.Fatalf("%d refusal events, want 1", len(evs))
		}
		ev, d := evs[0], detailsOf(evs[0])
		if ev.Reason != "factor_refused_policy" || ev.Outcome != audit.Denied ||
			d["account"] != e.account || d["attempt"] != "1" || ev.Target.GUID != e.row(t, "id") || d["source_ip"] != attackerIP.String() {
			t.Fatalf("event = %+v %v", ev, d)
		}
		if n := e.totpFailures(t); n != 0 {
			t.Fatalf("%d TOTP failure rows: the lock charged the enrolment budget", n)
		}
		if got := e.row(t, "attempts"); got != "1" {
			t.Fatalf("pending attempts = %s, want 1", got)
		}
		// The same code, same step, same pending sign-in: works once the key is gone.
		e.revokeKeys(t)
		if _, err := e.sf.VerifyTOTP(ctx, h, e.good(), attackerIP); err != nil {
			t.Fatalf("code after revoke: %v (the lock spent the step)", err)
		}
		if n := e.sessions(t); n != 1 {
			t.Fatalf("%d sessions, want 1", n)
		}
	})
}

func TestPasskeyLockChargesPendingBudget(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		e.addKey(t, purposeSecondFactor)
		h := e.begin(t)
		for i := 1; i <= MaxSignInAttempts; i++ {
			if _, err := e.sf.VerifyTOTP(ctx, h, e.good(), netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
				t.Fatalf("attempt %d: %v", i, err)
			}
			if got := e.row(t, "attempts"); got != string(rune('0'+i)) {
				t.Fatalf("after attempt %d attempts = %s", i, got)
			}
		}
		// The budget is spent: the pending sign-in ends, even though the key is now gone and the code good.
		e.revokeKeys(t)
		if _, err := e.sf.VerifyTOTP(ctx, h, e.good(), netip.Addr{}); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("after five attempts: %v, want ErrPendingInvalid", err)
		}
		if got := e.row(t, "state"); got != "dead" {
			t.Fatalf("pending state = %s, want dead", got)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions", n)
		}
		var policy int
		for _, ev := range e.sink.of(KindSecondFactorRefused) {
			if ev.Reason == RefusedFactorPolicy {
				policy++
			}
		}
		if policy != MaxSignInAttempts {
			t.Fatalf("%d policy refusals audited, want %d", policy, MaxSignInAttempts)
		}
	})
}

func TestPasskeyLockIgnoresRevokedAndAuthorityCredentials(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		// A credential of purpose authority is not a second factor.
		e.addKey(t, purposeAuthority)
		// A revoked second-factor credential no longer locks.
		e.addKey(t, purposeSecondFactor)
		e.revokeKeys(t)
		e.addKey(t, purposeAuthority)
		if _, err := e.sf.VerifyTOTP(ctx, e.begin(t), e.good(), netip.Addr{}); err != nil {
			t.Fatalf("code with only revoked/authority credentials: %v", err)
		}
		if n := e.sessions(t); n != 1 {
			t.Fatalf("%d sessions, want 1", n)
		}
	})
}

// Activation first: the credential commits while the TOTP verification of the same pending sign-in is
// already waiting on the account row. The verification must then see it.
func TestPasskeyLockRaceActivationVsTOTP(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		h := e.begin(t)
		code := e.good()
		locked, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			done <- e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
				if _, err := insertCredential(ctx, tx, e.ten, e.account, purposeSecondFactor, newSoftKey(t).credential()); err != nil {
					return err
				}
				close(locked)
				<-release
				return nil
			})
		}()
		<-locked
		res := make(chan error, 1)
		go func() {
			_, err := e.sf.VerifyTOTP(ctx, h, code, netip.Addr{})
			res <- err
		}()
		select {
		case err := <-res:
			t.Fatalf("VerifyTOTP finished (%v) while an activation held the account row", err)
		case <-time.After(500 * time.Millisecond):
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := <-res; !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("VerifyTOTP after the activation committed: %v", err)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions, want none", n)
		}
	})
}

// TOTP first: a verification in flight holds the account row, so an activation waits for the session to
// commit instead of slipping between the policy read and the session insert.
func TestPasskeyLockRaceTOTPInFlightBlocksActivation(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		locked, release, held := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() {
			held <- e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
				if err := lockAccountShared(ctx, tx, e.ten, e.account); err != nil {
					return err
				}
				close(locked)
				<-release
				return nil
			})
		}()
		<-locked
		wf := &WebAuthnFactor{DB: e.db}
		added := make(chan error, 1)
		go func() {
			_, err := wf.AddCredential(ctx, e.ten, e.account, newSoftKey(t).credential())
			added <- err
		}()
		select {
		case err := <-added:
			t.Fatalf("activation finished (%v) while a verification held the account row", err)
		case <-time.After(500 * time.Millisecond):
		}
		close(release)
		if err := <-held; err != nil {
			t.Fatal(err)
		}
		if err := <-added; err != nil {
			t.Fatal(err)
		}
	})
}
