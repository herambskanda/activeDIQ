package authn

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type stepEnv struct {
	*pendEnv
	su  *StepUp
	res CreateResult
}

// eachStepUp signs in (mfa_at = now, authority_factor_at = now) and hands over a StepUp with the
// default 5 minute window.
func eachStepUp(t *testing.T, fn func(t *testing.T, e *stepEnv)) {
	eachPending(t, func(t *testing.T, p *pendEnv) {
		now := p.now
		res, err := p.sess.Create(context.Background(), CreateInput{Tenant: p.ten, Account: p.account,
			Methods: []string{"password", "totp"}, MFAAt: &now, AuthorityFactorAt: &now,
			ClientIP: netip.MustParseAddr("192.0.2.7"), Epoch: epochOf(t, p.sess, p.ten, p.account)})
		if err != nil {
			t.Fatal(err)
		}
		fn(t, &stepEnv{pendEnv: p, su: &StepUp{Sessions: p.sess, TOTP: p.svc}, res: res})
	})
}

func (e *stepEnv) principal() apihost.Principal {
	return apihost.Principal{ID: e.account, Tenant: e.ten.String(), Kind: apihost.KindSession, SessionID: e.res.Session.ID}
}

func (e *stepEnv) fresh(t *testing.T) bool {
	t.Helper()
	ok, err := e.su.Fresh(context.Background(), e.principal())
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func (e *stepEnv) row(t *testing.T, col string) string {
	t.Helper()
	r := e.query(t, `SELECT coalesce(`+col+`::text, 'NULL') FROM public.authn_sessions`)
	if len(r) != 1 {
		t.Fatalf("read %s: %v", col, r)
	}
	return r[0]
}

func Test_stepup_required_when_stale(t *testing.T) {
	eachStepUp(t, func(t *testing.T, e *stepEnv) {
		if !e.fresh(t) {
			t.Fatal("a session that just passed MFA is not fresh")
		}
		e.now = e.now.Add(DefaultStepUpWindow - time.Second)
		if !e.fresh(t) {
			t.Fatal("inside the window must be fresh")
		}
		e.now = e.now.Add(time.Second) // exactly the window: closed
		if e.fresh(t) {
			t.Fatal("a session whose mfa_at is as old as the window is still fresh")
		}
		e.now = e.now.Add(10 * time.Minute)
		if e.fresh(t) {
			t.Fatal("stale session is fresh")
		}
	})
}

func Test_stepup_window(t *testing.T) {
	eachStepUp(t, func(t *testing.T, e *stepEnv) {
		ctx := context.Background()
		e.now = e.now.Add(10 * time.Minute)
		if e.fresh(t) {
			t.Fatal("precondition: stale")
		}
		before := e.row(t, "mfa_at")
		if _, err := e.su.Reverify(ctx, e.res.Token, e.bad()); !errors.Is(err, ErrStepUpRefused) {
			t.Fatalf("wrong code: %v", err)
		}
		if e.fresh(t) || e.row(t, "mfa_at") != before {
			t.Fatal("a wrong code moved mfa_at")
		}
		s, err := e.su.Reverify(ctx, e.res.Token, e.good())
		if err != nil {
			t.Fatalf("correct code: %v", err)
		}
		if s.MFAAt == nil || !s.MFAAt.Equal(e.now) {
			t.Fatalf("returned mfa_at %v want %v", s.MFAAt, e.now)
		}
		if !e.fresh(t) {
			t.Fatal("not fresh after a successful re-verification")
		}
		// the same code cannot refresh again later (replay guard, T-0196)
		e.now = e.now.Add(4 * time.Minute)
		if _, err := e.su.Reverify(ctx, e.res.Token, hotp(e.seed, stepAt(e.now)-8)); !errors.Is(err, ErrStepUpRefused) {
			t.Fatalf("old code accepted: %v", err)
		}
		e.now = e.now.Add(time.Minute)
		if e.fresh(t) {
			t.Fatal("window did not close 5 minutes after the re-verification")
		}
	})
}

func Test_stepup_failure_clears_authority_factor(t *testing.T) {
	eachStepUp(t, func(t *testing.T, e *stepEnv) {
		if e.row(t, "authority_factor_at") == "NULL" {
			t.Fatal("precondition: authority_factor_at set")
		}
		if _, err := e.su.Reverify(context.Background(), e.res.Token, e.bad()); !errors.Is(err, ErrStepUpRefused) {
			t.Fatalf("got %v", err)
		}
		if got := e.row(t, "authority_factor_at"); got != "NULL" {
			t.Fatalf("authority_factor_at survived a failed step-up: %s", got)
		}
		var failed int
		for _, ev := range e.sess.audit.(*recSink).evs {
			if ev.Kind == KindStepUpFailed && ev.Outcome == audit.Failure {
				failed++
			}
		}
		if failed != 1 {
			t.Fatalf("want one stepup.failed event, got %d", failed)
		}
	})
}

func Test_stepup_never_fresh_without_session_mfa(t *testing.T) {
	eachStepUp(t, func(t *testing.T, e *stepEnv) {
		ctx := context.Background()
		for name, p := range map[string]apihost.Principal{
			"token":          {ID: e.account, Tenant: e.ten.String(), Kind: apihost.KindToken},
			"no session":     {ID: e.account, Tenant: e.ten.String(), Kind: apihost.KindSession},
			"bad session id": {ID: e.account, Tenant: e.ten.String(), Kind: apihost.KindSession, SessionID: "x"},
			"other account":  {ID: "00000000-0000-4000-8000-000000000001", Tenant: e.ten.String(), Kind: apihost.KindSession, SessionID: e.res.Session.ID},
			"other tenant":   {ID: e.account, Tenant: e.b.String(), Kind: apihost.KindSession, SessionID: e.res.Session.ID},
		} {
			if ok, err := e.su.Fresh(ctx, p); err != nil || ok {
				t.Errorf("%s: fresh=%v err=%v", name, ok, err)
			}
		}
		// a session that never passed MFA (for example SSO with a non-asserting IdP) is not fresh
		res, err := e.sess.Create(ctx, CreateInput{Tenant: e.ten, Account: e.account, Methods: []string{"password"},
			Epoch: epochOf(t, e.sess, e.ten, e.account)})
		if err != nil {
			t.Fatal(err)
		}
		p := e.principal()
		p.SessionID = res.Session.ID
		if ok, err := e.su.Fresh(ctx, p); err != nil || ok {
			t.Errorf("no mfa_at: fresh=%v err=%v", ok, err)
		}
		// a revoked session is not fresh even inside the window
		if _, err := e.sess.Revoke(ctx, e.ten, e.res.Session.ID, ReasonOnDemand, accountChain(e.account)); err != nil {
			t.Fatal(err)
		}
		if e.fresh(t) {
			t.Error("revoked session is fresh")
		}
		if _, err := e.su.Reverify(ctx, e.res.Token, e.good()); err == nil {
			t.Error("Reverify on a revoked session succeeded")
		}
	})
}

func Test_stepup_window_bounds(t *testing.T) {
	eachStepUp(t, func(t *testing.T, e *stepEnv) {
		for _, w := range []time.Duration{0, 30 * time.Second, 16 * time.Minute, -time.Minute} {
			u := &StepUp{Sessions: e.sess, TOTP: e.svc, Windows: StaticStepUpWindow(w)}
			if ok, err := u.Fresh(context.Background(), e.principal()); !errors.Is(err, ErrStepUpWindow) || ok {
				t.Errorf("window %s: fresh=%v err=%v", w, ok, err)
			}
		}
		u := &StepUp{Sessions: e.sess, TOTP: e.svc, Windows: StaticStepUpWindow(time.Minute)}
		e.now = e.now.Add(2 * time.Minute)
		if ok, err := u.Fresh(context.Background(), e.principal()); err != nil || ok {
			t.Errorf("1 minute tenant window, 2 minutes old: fresh=%v err=%v", ok, err)
		}
	})
}

func Test_stepup_fresh_by_session(t *testing.T) {
	eachStepUp(t, func(t *testing.T, e *stepEnv) {
		ctx := context.Background()
		ok, err := e.su.FreshSession(ctx, e.ten, e.res.Session.ID)
		if err != nil || !ok {
			t.Fatalf("a session that just passed MFA: %v %v", ok, err)
		}
		if ok, _ := e.su.FreshSession(ctx, e.ten, "not-a-session"); ok {
			t.Fatal("a malformed session handle is fresh")
		}
		if ok, _ := e.su.FreshSession(ctx, tenant.ID{}, e.res.Session.ID); ok {
			t.Fatal("the zero tenant is fresh")
		}
		e.now = e.now.Add(DefaultStepUpWindow)
		if ok, _ := e.su.FreshSession(ctx, e.ten, e.res.Session.ID); ok {
			t.Fatal("a session whose mfa_at is as old as the window is fresh")
		}
	})
}
