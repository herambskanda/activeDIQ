package authn

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func state(t *testing.T, s *Store, e *sessEnv, id string) (SessionState, string) {
	t.Helper()
	var st, why string
	err := s.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, COALESCE(end_reason, '') FROM public.authn_sessions WHERE tenant_id = $1 AND id = $2::uuid`, e.ten.String(), id).Scan(&st, &why)
	})
	if err != nil {
		t.Fatal(err)
	}
	return SessionState(st), why
}

// Acceptance 1: an account event revokes the account's sessions with the matching reason when the
// caller's transaction commits, and leaves them alone when it rolls back.
func TestAccountEventsRevokeSessions(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		s := e.node(t, pol)
		ctx := context.Background()
		events := []struct {
			name string
			call func(context.Context, store.Tx, string) (int, error)
			why  string
		}{
			{"disabled", func(c context.Context, tx store.Tx, a string) (int, error) {
				return s.OnAccountDisabled(c, tx, e.ten, a, human)
			}, "account_disabled"},
			{"role", func(c context.Context, tx store.Tx, a string) (int, error) {
				return s.OnRoleChanged(c, tx, e.ten, a, human)
			}, "role_changed"},
			{"password", func(c context.Context, tx store.Tx, a string) (int, error) {
				return s.OnPasswordReset(c, tx, e.ten, a, human)
			}, "password_reset"},
			{"mfa", func(c context.Context, tx store.Tx, a string) (int, error) {
				return s.OnMFAReset(c, tx, e.ten, a, human)
			}, "mfa_reset"},
		}
		for _, ev := range events {
			t.Run(ev.name, func(t *testing.T) {
				acct, other := tenant.New().String(), tenant.New().String()
				a1, a2, o := create(t, s, e.ten, acct), create(t, s, e.ten, acct), create(t, s, e.ten, other)

				// A rolled-back change revokes nothing.
				errRollback := fmt.Errorf("rollback")
				err := s.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
					if n, err := ev.call(ctx, tx, acct); err != nil || n != 2 {
						t.Fatalf("revoked %d, %v; want 2", n, err)
					}
					return errRollback
				})
				if err != errRollback && !strings.Contains(fmt.Sprint(err), "rollback") {
					t.Fatalf("got %v", err)
				}
				if _, err := s.Lookup(ctx, a1.Token); err != nil {
					t.Fatalf("a rolled-back account change revoked a session: %v", err)
				}

				e.sink.reset() // the recording sink is not transactional: drop what the rolled-back attempt requested
				var n int
				if err := s.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
					var err error
					n, err = ev.call(ctx, tx, acct)
					return err
				}); err != nil || n != 2 {
					t.Fatalf("revoked %d, %v; want 2", n, err)
				}
				for _, r := range []CreateResult{a1, a2} {
					if _, err := s.Lookup(ctx, r.Token); err != ErrRevoked {
						t.Errorf("Lookup after the account event = %v, want ErrRevoked", err)
					}
					if st, why := state(t, s, e, r.Session.ID); st != SessionRevoked || why != ev.why {
						t.Errorf("session ended as %s/%s, want revoked/%s", st, why, ev.why)
					}
				}
				if _, err := s.Lookup(ctx, o.Token); err != nil {
					t.Errorf("another account's session was revoked: %v", err)
				}
				got := 0
				for _, x := range e.sink.of(KindSessionRevoked) {
					if x.Reason == ev.why && x.Actor.Requester == human.Requester && x.Details[0].Value == acct {
						got++
					}
				}
				if got != 2 {
					t.Errorf("%d revoke events with reason %s by the admin, want 2", got, ev.why)
				}
			})
		}
		if _, err := s.OnAccountDisabled(ctx, nil, e.ten, tenant.New().String(), human); err != ErrInvalid {
			t.Errorf("nil tx = %v, want ErrInvalid", err)
		}
	})
}

// Acceptance 2: create, eviction, expiry and revocation each leave an audit record with the actor, the
// account, the session handle and the reason, and nothing in any record is the token or its hash.
func TestSessionEventsAudited(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		e.skewClock(t)
		small := pol
		small.MaxConcurrent = 1
		s := e.node(t, small)
		ctx := context.Background()
		acct := tenant.New().String()

		first := create(t, s, e.ten, acct)
		second := create(t, s, e.ten, acct) // evicts first
		if second.Evicted != 1 {
			t.Fatalf("evicted %d", second.Evicted)
		}
		if err := s.Logout(ctx, second.Token); err != nil {
			t.Fatal(err)
		}
		third := create(t, s, e.ten, acct)
		e.clk.advance(2 * time.Hour)
		if _, err := s.Lookup(ctx, third.Token); err != ErrExpired {
			t.Fatalf("Lookup = %v, want ErrExpired", err)
		}
		fourth := create(t, s, e.ten, acct)
		e.clk.advance(2 * time.Hour)
		if n, err := s.ExpireDue(ctx, e.ten); err != nil || n != 1 {
			t.Fatalf("ExpireDue = %d, %v", n, err)
		}
		fifth := create(t, s, e.ten, acct)
		if ok, err := s.Revoke(ctx, e.ten, fifth.Session.ID, ReasonOnDemand, human); err != nil || !ok {
			t.Fatalf("Revoke = %v, %v", ok, err)
		}

		want := []struct {
			kind    audit.Kind
			session string
			reason  string
			actor   string
		}{
			{KindSessionCreated, first.Session.ID, "", acct},
			{KindSessionEvicted, first.Session.ID, "concurrent_limit", "authn"},
			{KindSessionCreated, second.Session.ID, "", acct},
			{KindSessionRevoked, second.Session.ID, "logout", acct},
			{KindSessionCreated, third.Session.ID, "", acct},
			{KindSessionExpired, third.Session.ID, "absolute_timeout", "authn"},
			{KindSessionCreated, fourth.Session.ID, "", acct},
			{KindSessionExpired, fourth.Session.ID, "absolute_timeout", "authn"},
			{KindSessionCreated, fifth.Session.ID, "", acct},
			{KindSessionRevoked, fifth.Session.ID, "on_demand", "admin-1"},
		}
		e.sink.mu.Lock()
		defer e.sink.mu.Unlock()
		if len(e.sink.evs) != len(want) {
			t.Fatalf("%d events %v, want %d", len(e.sink.evs), e.sink.evs, len(want))
		}
		secrets := []string{}
		for _, r := range []CreateResult{first, second, third, fourth, fifth} {
			h := r.Token.hash()
			secrets = append(secrets, r.Token.Reveal(), hex.EncodeToString(h), string(h))
		}
		seen := map[string]bool{}
		for i, w := range want {
			g := e.sink.evs[i]
			if g.Kind != w.kind || g.Target.GUID != w.session || g.Reason != w.reason || string(g.Actor.Requester.ID) != w.actor {
				t.Errorf("event %d = %s %s %q by %s; want %s %s %q by %s", i, g.Kind, g.Target.GUID, g.Reason, g.Actor.Requester.ID, w.kind, w.session, w.reason, w.actor)
			}
			if g.Details[0].Key != "account" || g.Details[0].Value != acct {
				t.Errorf("event %d details = %v, want the account", i, g.Details)
			}
			if seen[g.ID] {
				t.Errorf("event ID %s used twice", g.ID)
			}
			seen[g.ID] = true
			dump := fmt.Sprintf("%+v", g)
			for _, sec := range secrets {
				if bytes.Contains([]byte(dump), []byte(sec)) {
					t.Errorf("event %d contains a token or hash", i)
				}
			}
		}
	})
}

// The events are chained in the transaction that ends the session, in the real audit chain.
func TestSessionEventsChained(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		ctx := context.Background()
		db, err := store.Open(ctx, store.Config{DSN: e.d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		ch := audit.NewChainer(db)
		cp := audit.NewCheckpointer(ch, fixedKeys{}, noAnchor{})
		if err := db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error { return cp.InitTenant(ctx, tx, e.ten) }); err != nil {
			t.Fatal(err)
		}
		s, err := New(Config{DB: db, Audit: ch, Policies: StaticPolicy(pol)})
		if err != nil {
			t.Fatal(err)
		}
		acct := tenant.New().String()
		r := create(t, s, e.ten, acct)
		if err := db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := s.OnAccountDisabled(ctx, tx, e.ten, acct, human)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var kinds []string
		err = db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
			rows, err := tx.Query(ctx, `SELECT kind FROM audit_event WHERE kind LIKE 'authn.session.%' ORDER BY seq`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var k string
				if err := rows.Scan(&k); err != nil {
					return err
				}
				kinds = append(kinds, k)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(kinds, ",") != "authn.session.created,authn.session.revoked" {
			t.Errorf("chained kinds = %v (session %s)", kinds, r.Session.ID)
		}
	})
}

type noAnchor struct{}

func (noAnchor) Anchor(context.Context, chain.Checkpoint) error { return nil }

type fixedKeys struct{}

func (fixedKeys) DEK(context.Context, store.Tx, tenant.ID, uint32) (keys.DEK, error) {
	return keys.DEKFromBytes(1, bytes.Repeat([]byte{9}, keys.DEKSize))
}

// A store without an audit sink is refused.
func TestStoreNeedsAudit(t *testing.T) {
	if _, err := New(Config{DB: &store.DB{}}); err == nil {
		t.Fatal("New accepted a missing audit sink")
	}
}

// Acceptance 3: the owner path removes ended sessions older than the retention and leaves the rest.
func TestSessionRetentionPurge(t *testing.T) {
	each(t, func(t *testing.T, e *sessEnv) {
		e.skewClock(t)
		s := e.node(t, pol)
		ctx := context.Background()
		acct := tenant.New().String()

		revokedOld := create(t, s, e.ten, acct)
		if _, err := s.Revoke(ctx, e.ten, revokedOld.Session.ID, ReasonOnDemand, human); err != nil {
			t.Fatal(err)
		}
		expiredOld := create(t, s, e.ten, acct)
		e.clk.advance(2 * time.Hour)
		if _, err := s.ExpireDue(ctx, e.ten); err != nil {
			t.Fatal(err)
		}
		active := create(t, s, e.ten, acct)
		e.clk.advance(91 * 24 * time.Hour)
		revokedNew := create(t, s, e.ten, acct)
		if _, err := s.Revoke(ctx, e.ten, revokedNew.Session.ID, ReasonOnDemand, human); err != nil {
			t.Fatal(err)
		}

		// The runtime role cannot do it.
		if err := s.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM public.authn_sessions WHERE tenant_id = $1`, e.ten.String())
			return err
		}); err == nil {
			t.Fatal("the runtime role deleted sessions")
		}

		owner, err := store.OpenMaintenance(ctx, store.Config{DSN: e.d.OwnerDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(owner.Close)
		if _, err := NewPurger(owner, e.sink, time.Hour, nil); err != ErrRetention {
			t.Fatalf("a one-hour retention = %v, want ErrRetention", err)
		}
		p, err := NewPurger(owner, e.sink, 90*24*time.Hour, e.clk.now)
		if err != nil {
			t.Fatal(err)
		}
		n, err := p.Purge(ctx, e.ten, human)
		if err != nil || n != 2 {
			t.Fatalf("Purge = %d, %v; want 2", n, err)
		}
		count := func(id string) int {
			var c int
			if err := owner.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_sessions WHERE tenant_id = $1 AND id = $2::uuid`, e.ten.String(), id).Scan(&c)
			}); err != nil {
				t.Fatal(err)
			}
			return c
		}
		for id, want := range map[string]int{revokedOld.Session.ID: 0, expiredOld.Session.ID: 0, active.Session.ID: 1, revokedNew.Session.ID: 1} {
			if got := count(id); got != want {
				t.Errorf("session %s: %d rows, want %d", id, got, want)
			}
		}
		if evs := e.sink.of(KindSessionsPurged); len(evs) != 1 || evs[0].Actor.Requester != human.Requester {
			t.Errorf("purge events = %v", evs)
		}
		if n, err := p.Purge(ctx, e.ten, human); err != nil || n != 0 {
			t.Errorf("second Purge = %d, %v", n, err)
		}
		if len(e.sink.of(KindSessionsPurged)) != 1 {
			t.Error("an empty purge recorded an event")
		}
	})
}
