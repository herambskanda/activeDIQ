package authn

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRotateKillsOldTokenAndChangesCSRF(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		s := e.node(t, pol)
		ctx := context.Background()
		acct := e.account(t)
		old := create(t, s, e.ten, acct)
		nu, err := s.Rotate(ctx, old.Token, ReasonRoleChanged)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if _, err := s.Lookup(ctx, old.Token); !errors.Is(err, ErrRevoked) {
			t.Fatalf("old token Lookup = %v, want ErrRevoked", err)
		}
		got, err := s.Lookup(ctx, nu.Token)
		if err != nil || got.Account != acct {
			t.Fatalf("new token Lookup = %+v, %v", got, err)
		}
		if old.Token.Reveal() == nu.Token.Reveal() {
			t.Fatal("token survived rotation") // the CSRF value is derived from it (authnhttp)
		}
		if _, err := s.Rotate(ctx, old.Token, ReasonRoleChanged); !errors.Is(err, ErrRevoked) {
			t.Fatalf("second Rotate of the old token = %v, want ErrRevoked", err)
		}
	})
}

func TestRotateKeepsAbsoluteDeadline(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		e.skewClock(t)
		s := e.node(t, pol)
		ctx := context.Background()
		cur := create(t, s, e.ten, e.account(t))
		abs := cur.Session.AbsoluteExpiry
		var err error
		for i := 0; i < 20; i++ {
			e.clk.advance(5 * time.Minute)
			prev := cur
			if cur, err = s.Rotate(ctx, prev.Token, ReasonOnDemand); err != nil {
				if !e.clk.now().Before(abs) && (errors.Is(err, ErrExpired) || errors.Is(err, ErrRevoked)) {
					return // ended no later than the original deadline
				}
				t.Fatalf("Rotate #%d at %v (abs %v): %v", i, e.clk.now(), abs, err)
			}
			if !cur.Session.AbsoluteExpiry.Equal(abs) || !cur.Session.CreatedAt.Equal(prev.Session.CreatedAt) {
				t.Fatalf("rotation moved the window: abs %v->%v created %v->%v", abs, cur.Session.AbsoluteExpiry, prev.Session.CreatedAt, cur.Session.CreatedAt)
			}
			if !e.clk.now().Before(abs) {
				t.Fatalf("rotation succeeded at %v past the original deadline %v", e.clk.now(), abs)
			}
		}
		t.Fatal("session survived 100m of rotation under a 1h absolute limit")
	})
}
