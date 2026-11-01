package signin_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
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

// DM-30.I5 never rebinds, even when a concurrent sign-in wins the race to bind the account.
func Test_sso_bind_race_never_rebinds(t *testing.T) {
	for name, bindErr := range map[string]error{"already bound": authn.ErrAlreadyBound, "object held by another account": authn.ErrAccountExists} {
		t.Run(name, func(t *testing.T) {
			r := signintest.NewRig()
			r.SetMFA()
			r.Verifier.Out.MFAAsserted = true
			r.Verifier.Out.Anchor = &sso.Anchor{Claim: "oid", Value: "0b1f", TID: "tid-1"}
			r.Accounts.BindErr = bindErr
			_, err := r.Callback(context.Background(), started(t, r))
			wantRefused(t, err, r, signin.ReasonAnchorChanged)
		})
	}
}

// OIDC-4 mix-up: a Transaction started at one IdP is refused at another, before any verifier runs.
func Test_sso_callback_idp_mismatch_refused(t *testing.T) {
	r := signintest.NewRig()
	cookie := started(t, r) // started at idp1
	_, err := r.Service.Callback(context.Background(), signin.CallbackRequest{Tenant: signintest.Tenant, IdPID: "idp2", Cookie: cookie,
		Callback: sso.Callback{IdPID: "idp2"}})
	wantRefused(t, err, r, signin.ReasonTransactionIdP)
	if len(r.Verifier.Completed) != 0 {
		t.Fatalf("verifier ran for a mismatched IdP: %d", len(r.Verifier.Completed))
	}
}

// Residual risk (console-sso.md 7.3): a failed success-audit write does not revoke the session; it is
// logged. This pins that behaviour so changing it is a decision, not an accident.
func Test_sso_success_audit_failure_keeps_session(t *testing.T) {
	r := signintest.NewRig()
	r.SetMFA()
	r.Verifier.Out.MFAAsserted = true
	r.Rec.Err = errors.New("audit store down")
	res, err := r.Callback(context.Background(), started(t, r))
	if err != nil || res.Kind != signin.ResultSession || len(r.Sessions.Created) != 1 {
		t.Fatalf("res=%v err=%v sessions=%d, want the session kept", res.Kind, err, len(r.Sessions.Created))
	}
}

// captureLog is a slog.Handler that keeps every record's attributes.
type captureLog struct {
	mu   sync.Mutex
	recs []map[string]string
	with []slog.Attr
}

func (c *captureLog) Enabled(context.Context, slog.Level) bool { return true }

func (c *captureLog) Handle(_ context.Context, r slog.Record) error {
	m := map[string]string{"msg": r.Message}
	for _, a := range c.with {
		m[a.Key] = a.Value.String()
	}
	r.Attrs(func(a slog.Attr) bool { m[a.Key] = a.Value.String(); return true })
	c.mu.Lock()
	c.recs = append(c.recs, m)
	c.mu.Unlock()
	return nil
}

func (c *captureLog) WithAttrs(as []slog.Attr) slog.Handler {
	// Share the record store; extend the pre-set attributes.
	return &captureLogChild{parent: c, with: append(append([]slog.Attr{}, c.with...), as...)}
}

func (c *captureLog) WithGroup(string) slog.Handler { return c }

type captureLogChild struct {
	parent *captureLog
	with   []slog.Attr
}

func (c *captureLogChild) Enabled(context.Context, slog.Level) bool { return true }

func (c *captureLogChild) Handle(ctx context.Context, r slog.Record) error {
	child := &captureLog{recs: nil, with: c.with}
	if err := child.Handle(ctx, r); err != nil {
		return err
	}
	c.parent.mu.Lock()
	c.parent.recs = append(c.parent.recs, child.recs...)
	c.parent.mu.Unlock()
	return nil
}

func (c *captureLogChild) WithAttrs(as []slog.Attr) slog.Handler {
	return &captureLogChild{parent: c.parent, with: append(append([]slog.Attr{}, c.with...), as...)}
}

func (c *captureLogChild) WithGroup(string) slog.Handler { return c }

// TM-TB17-T8 / ADR-0002 logs: every log line Callback writes carries tenant_id equal to the request's
// tenant, for a non-Refusal verifier fault and for a failed privilege check.
func Test_sso_callback_logs_carry_tenant_id(t *testing.T) {
	cases := map[string]struct {
		setup func(r *signintest.Rig)
		msg   string
	}{
		"verifier fault": {
			setup: func(r *signintest.Rig) { r.Verifier.Err = errors.New("replay store down") },
			msg:   "sso: verifier failed",
		},
		"privilege check fails": {
			setup: func(r *signintest.Rig) {
				r.SetMFA()
				r.Verifier.Out.MFAAsserted = true
				r.Priv.Err = errors.New("db down")
			},
			msg: "sso: privilege check failed; completing with the second factor",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := signintest.NewRig()
			cl := &captureLog{}
			r.Service.Log = slog.New(cl)
			tc.setup(r)
			_, _ = r.Callback(context.Background(), started(t, r))
			var seen bool
			for _, rec := range cl.recs {
				if rec["msg"] == tc.msg {
					seen = true
				}
				if got := rec["tenant_id"]; got != signintest.Tenant.String() {
					t.Fatalf("log %q has tenant_id %q, want %q", rec["msg"], got, signintest.Tenant.String())
				}
			}
			if !seen {
				t.Fatalf("expected log %q, got %v", tc.msg, cl.recs)
			}
		})
	}
}
