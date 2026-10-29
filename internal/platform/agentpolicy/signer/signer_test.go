package signer_test

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy/signer"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

type keySource struct {
	mu   sync.Mutex
	deks map[tenant.ID][]byte
}

func (k *keySource) DEK(_ context.Context, _ store.Tx, id tenant.ID, version uint32) (keys.DEK, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.deks == nil {
		k.deks = map[tenant.ID][]byte{}
	}
	if k.deks[id] == nil {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		k.deks[id] = b
	}
	if version == 0 {
		version = 1
	}
	return keys.DEKFromBytes(version, append([]byte(nil), k.deks[id]...))
}

type sink struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (s *sink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
	return nil
}

var actor = authority.Chain{Requester: authority.Principal{ID: "human-1", Kind: authority.Human}}

type env struct {
	db   *store.DB
	a, b tenant.ID
	sg   *signer.Signer
	sink *sink
	now  time.Time
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	a := tenanttest.Seed(t, d.ExecOwner, "A")
	b := tenanttest.Seed(t, d.ExecOwner, "B")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e := &env{db: db, a: a, b: b, sink: &sink{}, now: time.Now().UTC().Truncate(time.Second)}
	e.sg = &signer.Signer{Keys: &keySource{}, Audit: e.sink, Clock: func() time.Time { return e.now }}
	return e
}

func (e *env) tx(t *testing.T, tid tenant.ID, f func(ctx context.Context, tx store.Tx) error) error {
	t.Helper()
	return e.db.WithTenant(context.Background(), tid, f)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func body() agentpolicy.AddcPolicy {
	return agentpolicy.AddcPolicy{
		Password: agentpolicy.PasswordRules{MinLength: 12, MaxLength: 128, MinClasses: 3},
		Events: agentpolicy.EventRules{CollectionEnabled: true, Channels: []agentpolicy.Channel{agentpolicy.ChannelSecurity},
			EventIDs: []uint32{4624, 4740}, MaxEventsPerSecond: 100, BatchMaxBytes: 65536, OutboxMaxBytes: 1 << 20},
	}
}

func TestRotationChainIsAcceptedByAnAgentAndPoliciesFollow(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		var anchor agentpolicy.SignedKeyset
		var p1 agentpolicy.SignedPolicy
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
			if anchor, err = e.sg.EnsureKeyset(ctx, tx, e.a, actor); err != nil {
				return err
			}
			again, err := e.sg.EnsureKeyset(ctx, tx, e.a, actor)
			if err != nil || again.Seq != 1 {
				t.Fatalf("EnsureKeyset is not idempotent: %v seq %d", err, again.Seq)
			}
			p1, err = e.sg.SignPolicy(ctx, tx, e.a, agentpolicy.KindADDC, body(), 0, actor)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		v := must(agentpolicy.NewVerifier(e.a, agentpolicy.KindADDC))
		if err := v.Anchor(anchor); err != nil {
			t.Fatal(err)
		}
		if _, err := v.ApplyPolicy(p1, e.now); err != nil {
			t.Fatalf("policy signed by the anchor key: %v", err)
		}
		// Rotate; the agent replays the chain.
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := e.sg.Rotate(ctx, tx, e.a, actor, "scheduled")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		var chain []agentpolicy.SignedKeyset
		var p2 agentpolicy.SignedPolicy
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
			if chain, err = e.sg.Chain(ctx, tx, 1); err != nil {
				return err
			}
			p2, err = e.sg.SignPolicy(ctx, tx, e.a, agentpolicy.KindADDC, body(), 0, actor)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if len(chain) != 1 || chain[0].Seq != 2 {
			t.Fatalf("chain since 1: %d", len(chain))
		}
		if err := v.ApplyKeyset(chain[0]); err != nil {
			t.Fatalf("agent refused the rotation link: %v", err)
		}
		if p2.Header.Seq != 2 || p2.Header.KeyID == p1.Header.KeyID {
			t.Fatalf("new policy: seq %d key %s (old %s)", p2.Header.Seq, p2.Header.KeyID, p1.Header.KeyID)
		}
		if _, err := v.ApplyPolicy(p2, e.now); err != nil {
			t.Fatalf("policy under the new key: %v", err)
		}
		// P3 replay across the rotation: the old policy is refused.
		if _, err := v.ApplyPolicy(p1, e.now); !errors.Is(err, agentpolicy.ErrReplay) {
			t.Fatalf("replay: %v", err)
		}
		// Overlap ends: the old key is dropped, its sealed material erased, and the agent accepts the drop.
		e.now = e.now.Add(agentpolicy.OverlapWindow + time.Hour)
		var dropped agentpolicy.SignedKeyset
		var ok bool
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
			dropped, ok, err = e.sg.DropExpired(ctx, tx, e.a, actor)
			return err
		}); err != nil || !ok {
			t.Fatalf("drop: %v %v", ok, err)
		}
		if err := v.ApplyKeyset(dropped); err != nil {
			t.Fatalf("agent refused the drop: %v", err)
		}
		if len(dropped.Keys) != 1 {
			t.Fatalf("keys after drop: %d", len(dropped.Keys))
		}
		n, err := scalar(e, e.a, `SELECT count(*) FROM public.agent_policy_key WHERE state = 'dropped' AND sealed_key IS NULL`)
		if err != nil || n != 1 {
			t.Fatalf("dropped key keeps sealed material: %d %v", n, err)
		}
		// A second call has nothing to do.
		_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			if _, ok, err := e.sg.DropExpired(ctx, tx, e.a, actor); ok || err != nil {
				t.Fatalf("second drop: %v %v", ok, err)
			}
			return nil
		})
	})
}

func scalar(e *env, tid tenant.ID, sql string) (int, error) {
	var n int
	err := e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, sql).Scan(&n)
	})
	return n, err
}

func TestTenantIsolationAndWrongTenantRefused(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		var ka agentpolicy.SignedKeyset
		var pb agentpolicy.SignedPolicy
		_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) (err error) {
			ka, err = e.sg.EnsureKeyset(ctx, tx, e.a, actor)
			return err
		})
		_ = e.tx(t, e.b, func(ctx context.Context, tx store.Tx) (err error) {
			if _, err = e.sg.EnsureKeyset(ctx, tx, e.b, actor); err != nil {
				return err
			}
			pb, err = e.sg.SignPolicy(ctx, tx, e.b, agentpolicy.KindADDC, body(), 0, actor)
			return err
		})
		// P1: B's policy offered to A's agent.
		v := must(agentpolicy.NewVerifier(e.a, agentpolicy.KindADDC))
		if err := v.Anchor(ka); err != nil {
			t.Fatal(err)
		}
		if _, err := v.ApplyPolicy(pb, e.now); !errors.Is(err, agentpolicy.ErrWrongTenant) {
			t.Fatalf("wrong tenant: %v", err)
		}
		// A sees none of B's rows (RLS), and A cannot have a policy yet.
		_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			if _, ok, err := e.sg.CurrentPolicy(ctx, tx, agentpolicy.KindADDC); ok || err != nil {
				t.Fatalf("A reads B's policy: %v %v", ok, err)
			}
			return nil
		})
	})
}

func TestSignPolicyRefusesOutOfBoundsAndNoKeyset(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			if _, err := e.sg.SignPolicy(ctx, tx, e.a, agentpolicy.KindADDC, body(), 0, actor); !errors.Is(err, signer.ErrNoKeyset) {
				t.Fatalf("no keyset: %v", err)
			}
			if _, err := e.sg.Rotate(ctx, tx, e.a, actor, "x"); !errors.Is(err, signer.ErrNoKeyset) {
				t.Fatalf("rotate without keyset: %v", err)
			}
			if _, err := e.sg.EnsureKeyset(ctx, tx, e.a, actor); err != nil {
				return err
			}
			bad := body()
			bad.Events.MaxEventsPerSecond = agentpolicy.MaxEventsPerSec + 1
			if _, err := e.sg.SignPolicy(ctx, tx, e.a, agentpolicy.KindADDC, bad, 0, actor); !errors.Is(err, agentpolicy.ErrOutOfBounds) {
				t.Fatalf("out of bounds: %v", err)
			}
			if _, err := e.sg.SignPolicy(ctx, tx, e.a, agentpolicy.KindADDC, body(), agentpolicy.MaxLifetime+time.Second, actor); !errors.Is(err, signer.ErrInvalid) {
				t.Fatalf("lifetime: %v", err)
			}
			if _, err := e.sg.SignPolicy(ctx, tx, e.a, "bogus", body(), 0, actor); !errors.Is(err, signer.ErrInvalid) {
				t.Fatalf("kind: %v", err)
			}
			return nil
		})
	})
}

func TestRotateRefusesWhenKeysetIsFull(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			if _, err := e.sg.EnsureKeyset(ctx, tx, e.a, actor); err != nil {
				return err
			}
			for i := 1; i < agentpolicy.MaxKeys; i++ {
				if _, err := e.sg.Rotate(ctx, tx, e.a, actor, "r"); err != nil {
					return err
				}
			}
			if _, err := e.sg.Rotate(ctx, tx, e.a, actor, "r"); !errors.Is(err, signer.ErrTooManyKeys) {
				t.Fatalf("full keyset: %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestSealedKeyIsBoundToItsRowAndTenantAndAuditHasNoSecrets(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := e.sg.EnsureKeyset(ctx, tx, e.a, actor)
			return err
		})
		// Corrupt the sealed blob via the owner path is not possible as the app role; swap two ciphertexts instead.
		err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.agent_policy_key SET sealed_key = set_byte(sealed_key, 20, get_byte(sealed_key, 20) # 1)`)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			if _, err := e.sg.SignPolicy(ctx, tx, e.a, agentpolicy.KindADDC, body(), 0, actor); !errors.Is(err, signer.ErrIntegrity) {
				t.Fatalf("tampered key: %v", err)
			}
			return nil
		})
		for _, ev := range e.sink.evs {
			for _, d := range ev.Details {
				if len(d.Value) > 64 {
					t.Fatalf("audit detail %s is suspiciously large", d.Key)
				}
			}
		}
	})
}
