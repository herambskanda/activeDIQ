package signin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/signin"
	"github.com/skenzeriq/activediq/internal/platform/authn/sso/signin/signintest"
)

func started(t *testing.T, r *signintest.Rig) string {
	t.Helper()
	c, err := r.StartCookie(context.Background(), "")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return c
}

func wantRefused(t *testing.T, err error, r *signintest.Rig, reason string) {
	t.Helper()
	if !errors.Is(err, signin.ErrSignInFailed) {
		t.Fatalf("err = %v, want ErrSignInFailed", err)
	}
	if got := r.Rec.Last().Reason; got != reason {
		t.Fatalf("recorded reason = %q, want %q", got, reason)
	}
	if len(r.Sessions.Created) != 0 || len(r.Pending.Begun) != 0 {
		t.Fatalf("a refusal produced a session or pending sign-in")
	}
}

// Acceptance 1: a valid response from an IdP that is not MFA-asserting leaves only a pending sign-in.
func Test_sso_non_mfa_pending_only(t *testing.T) {
	r := signintest.NewRig()
	r.Verifier.Out.MFAAsserted = true // even a claim of MFA counts for nothing when the IdP is not marked
	res, err := r.Callback(context.Background(), started(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != signin.ResultPending || len(r.Pending.Begun) != 1 || len(r.Sessions.Created) != 0 {
		t.Fatalf("kind=%s pending=%d sessions=%d, want one pending and no session", res.Kind, len(r.Pending.Begun), len(r.Sessions.Created))
	}
}

func Test_sso_mfa_asserting_yields_session(t *testing.T) {
	r := signintest.NewRig()
	r.SetMFA()
	r.Verifier.Out.MFAAsserted = true
	res, err := r.Callback(context.Background(), started(t, r))
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != signin.ResultSession || len(r.Sessions.Created) != 1 || len(r.Pending.Begun) != 0 {
		t.Fatalf("kind=%s, want a session", res.Kind)
	}
}

func Test_sso_mfa_idp_without_proof_is_pending_with_warning(t *testing.T) {
	r := signintest.NewRig()
	r.SetMFA()
	res, err := r.Callback(context.Background(), started(t, r))
	if err != nil || res.Kind != signin.ResultPending {
		t.Fatalf("res=%v err=%v, want pending", res.Kind, err)
	}
	if o := r.Rec.Last(); len(o.Warnings) == 0 || o.Warnings[0] != signin.WarnMFAEvidenceAbsent {
		t.Fatalf("warnings = %v", o.Warnings)
	}
}

// MFA-5: an account holding tenant-owner or control_plane never gets a direct session.
func Test_sso_mfa_asserted_privileged_is_pending(t *testing.T) {
	for name, p := range map[string]*signintest.Priv{"holds": {Holds: true}, "check fails": {Err: errors.New("db down")}} {
		t.Run(name, func(t *testing.T) {
			r := signintest.NewRig()
			r.SetMFA()
			r.Verifier.Out.MFAAsserted = true
			r.Priv.Holds, r.Priv.Err = p.Holds, p.Err
			res, err := r.Callback(context.Background(), started(t, r))
			if err != nil || res.Kind != signin.ResultPending || len(r.Sessions.Created) != 0 {
				t.Fatalf("res=%v err=%v sessions=%d, want pending only", res.Kind, err, len(r.Sessions.Created))
			}
		})
	}
}

// Acceptance 2: a UPN-only claim means no binding.
func Test_sso_anchor_binding_rules(t *testing.T) {
	sid := authn.DirectoryRef{}
	t.Run("upn claim binds nothing", func(t *testing.T) {
		for _, claim := range []string{"upn", "email", "preferred_username", "sub"} {
			r := signintest.NewRig()
			r.Verifier.Out.Anchor = &sso.Anchor{Claim: claim, Value: "alice@example.com"}
			if _, err := r.Callback(context.Background(), started(t, r)); err != nil {
				t.Fatalf("%s: %v", claim, err)
			}
			if len(r.Anchors.Resolved) != 0 || len(r.Accounts.Binds) != 0 {
				t.Fatalf("%s: resolved=%d binds=%d, want none", claim, len(r.Anchors.Resolved), len(r.Accounts.Binds))
			}
		}
	})
	t.Run("oid binds once", func(t *testing.T) {
		r := signintest.NewRig()
		r.Anchors.Ref = sid
		r.Verifier.Out.Anchor = &sso.Anchor{Claim: "oid", Value: "0b1f", TID: "tid-1"}
		if _, err := r.Callback(context.Background(), started(t, r)); err != nil {
			t.Fatal(err)
		}
		if len(r.Accounts.Binds) != 1 || r.Accounts.Binds[0].Kind != authn.AnchorOID {
			t.Fatalf("binds = %v", r.Accounts.Binds)
		}
	})
	t.Run("onprem_sid binds", func(t *testing.T) {
		r := signintest.NewRig()
		r.Verifier.Out.Anchor = &sso.Anchor{Claim: "onprem_sid", Value: "S-1-5-21-1"}
		if _, err := r.Callback(context.Background(), started(t, r)); err != nil {
			t.Fatal(err)
		}
		if len(r.Accounts.Binds) != 1 || r.Accounts.Binds[0].Kind != authn.AnchorOnpremSID {
			t.Fatalf("binds = %v", r.Accounts.Binds)
		}
	})
	t.Run("unresolvable anchor leaves the account unbound and signs in", func(t *testing.T) {
		r := signintest.NewRig()
		r.Anchors.Err = authn.ErrAnchorNoMatch
		r.Verifier.Out.Anchor = &sso.Anchor{Claim: "oid", Value: "x", TID: "t"}
		if _, err := r.Callback(context.Background(), started(t, r)); err != nil {
			t.Fatal(err)
		}
		if len(r.Accounts.Binds) != 0 || r.Rec.Last().Warnings[0] != signin.WarnBindingUnresolved {
			t.Fatalf("binds=%d warnings=%v", len(r.Accounts.Binds), r.Rec.Last().Warnings)
		}
	})
	t.Run("a bound account whose anchor now names another object is refused", func(t *testing.T) {
		r := signintest.NewRig()
		bound := authn.DirectoryRef{}
		bound.ObjectGUID = "other-guid"
		an := authn.Anchor{Kind: authn.AnchorOID, Value: "old"}
		r.Accounts.A.Anchor, r.Accounts.A.Ref = &an, &bound
		r.Verifier.Out.Anchor = &sso.Anchor{Claim: "oid", Value: "new", TID: "t"}
		_, err := r.Callback(context.Background(), started(t, r))
		wantRefused(t, err, r, signin.ReasonAnchorChanged)
	})
	t.Run("a bound account with no anchor claim is refused", func(t *testing.T) {
		r := signintest.NewRig()
		an := authn.Anchor{Kind: authn.AnchorOID, Value: "old"}
		ref := authn.DirectoryRef{}
		r.Accounts.A.Anchor, r.Accounts.A.Ref = &an, &ref
		_, err := r.Callback(context.Background(), started(t, r))
		wantRefused(t, err, r, signin.ReasonAnchorMissing)
	})
}

// SSO-1: the same callback twice is refused (O-R02).
func Test_sso_same_callback_twice_refused(t *testing.T) {
	r := signintest.NewRig()
	c := started(t, r)
	if _, err := r.Callback(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	r.Rec.O = nil
	_, err := r.Callback(context.Background(), c)
	wantRefusedAfterFirst(t, err, r, signin.ReasonNoTransaction)
}

func wantRefusedAfterFirst(t *testing.T, err error, r *signintest.Rig, reason string) {
	t.Helper()
	if !errors.Is(err, signin.ErrSignInFailed) || r.Rec.Last().Reason != reason {
		t.Fatalf("err=%v reason=%q, want refusal %q", err, r.Rec.Last().Reason, reason)
	}
	if len(r.Verifier.Completed) != 1 {
		t.Fatalf("verifier ran %d times, want 1", len(r.Verifier.Completed))
	}
}

// SSO-1: a Transaction older than five minutes is refused, before the verifier sees it.
func Test_sso_transaction_older_than_5_minutes_refused(t *testing.T) {
	r := signintest.NewRig()
	c := started(t, r)
	r.Now = r.Now.Add(signin.TransactionTTL + time.Second)
	_, err := r.Callback(context.Background(), c)
	wantRefused(t, err, r, signin.ReasonTransactionAge)
	if len(r.Verifier.Completed) != 0 {
		t.Fatal("verifier ran on an expired Transaction")
	}
}

// SSO-1: a callback without the browser's cookie (another browser) is refused, and the Transaction it
// would have used stays unusable by that browser.
func Test_sso_transaction_from_another_browser_refused(t *testing.T) {
	r := signintest.NewRig()
	_ = started(t, r)
	for _, cookie := range []string{"", "not-a-handle", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		_, err := r.Callback(context.Background(), cookie)
		wantRefused(t, err, r, signin.ReasonNoTransaction)
	}
	if len(r.Verifier.Completed) != 0 {
		t.Fatal("verifier ran without a Transaction")
	}
}

func Test_sso_unknown_subject_not_admitted(t *testing.T) {
	r := signintest.NewRig()
	r.Accounts.Absent = true
	_, err := r.Callback(context.Background(), started(t, r))
	wantRefused(t, err, r, signin.ReasonNotAdmitted)
}

func Test_sso_verifier_refusal_is_generic_and_audited(t *testing.T) {
	r := signintest.NewRig()
	r.Verifier.Err = errors.New("replay store down")
	_, err := r.Callback(context.Background(), started(t, r))
	wantRefused(t, err, r, "sso.verifier_error")
	if r.Rec.Last().Subject != "" {
		t.Fatal("subject recorded for an unverified response")
	}
}

func Test_ValidReturnPath(t *testing.T) {
	for p, ok := range map[string]bool{"/users": true, "/a/b": true, "/a/b?c=d": false, "/a/../b": false, "/a%2f": false, "//evil.example": false, "https://evil.example": false,
		"/\\evil": false, "": false, "users": false, "/a\r\nSet-Cookie: x": false} {
		if got := signin.ValidReturnPath(p); got != ok {
			t.Errorf("ValidReturnPath(%q) = %v, want %v", p, got, ok)
		}
	}
}
