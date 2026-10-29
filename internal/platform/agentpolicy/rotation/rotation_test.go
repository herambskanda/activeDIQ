package rotation_test

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy/rotation"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy/signer"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

type keySource struct {
	mu  sync.Mutex
	dek []byte
}

func (k *keySource) DEK(_ context.Context, _ store.Tx, _ tenant.ID, version uint32) (keys.DEK, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.dek == nil {
		k.dek = make([]byte, 32)
		_, _ = rand.Read(k.dek)
	}
	if version == 0 {
		version = 1
	}
	return keys.DEKFromBytes(version, append([]byte(nil), k.dek...))
}

type sink struct{ n int }

func (s *sink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	s.n++
	return ev.Validate()
}

func TestMaintenanceRotatesWhenDueThenDropsAfterOverlapAndAgentsFollow(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		tid := tenanttest.Seed(t, d.ExecOwner, "A")
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)

		now := time.Now().UTC().Truncate(time.Second)
		clock := func() time.Time { return now }
		sg := &signer.Signer{Keys: &keySource{}, Audit: &sink{}, Clock: clock}
		reg := jobs.NewRegistry()
		j, err := rotation.RegisterJobs(reg, sg, clock)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := reg.Lookup(rotation.JobKeysetMaintenance); !ok {
			t.Fatal("kind not registered")
		}
		if _, err := rotation.RegisterJobs(reg, sg, clock); err == nil {
			t.Fatal("kind registered twice")
		}

		var anchor agentpolicy.SignedKeyset
		for i := 0; i < 2; i++ { // idempotent
			if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) (err error) {
				anchor, err = j.EnsureAndSchedule(ctx, tx, tid)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		if anchor.Seq != 1 {
			t.Fatalf("anchor seq %d", anchor.Seq)
		}
		v, err := agentpolicy.NewVerifier(tid, agentpolicy.KindADDC)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Anchor(anchor); err != nil {
			t.Fatal(err)
		}

		maintain := func() rotation.Outcome {
			var out rotation.Outcome
			if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) (err error) {
				out, err = j.Maintain(ctx, tx, tid)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return out
		}
		follow := func() int {
			var chain []agentpolicy.SignedKeyset
			_ = db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) (err error) {
				chain, err = sg.Chain(ctx, tx, v.KeysetSeq())
				return err
			})
			for _, sk := range chain {
				if err := v.ApplyKeyset(sk); err != nil {
					t.Fatalf("agent refused keyset %d: %v", sk.Seq, err)
				}
			}
			return len(chain)
		}

		if out := maintain(); out.Rotated || out.Dropped {
			t.Fatalf("fresh key maintained: %+v", out)
		}
		now = now.Add(signer.RotationInterval + time.Hour)
		if out := maintain(); !out.Rotated || out.Dropped {
			t.Fatalf("due rotation: %+v", out)
		}
		if follow() != 1 {
			t.Fatal("agent should follow one link")
		}
		now = now.Add(agentpolicy.OverlapWindow + time.Hour)
		if out := maintain(); !out.Dropped || out.Rotated {
			t.Fatalf("overlap ended: %+v", out)
		}
		if follow() != 1 {
			t.Fatal("agent should follow the drop")
		}
		if out := maintain(); out.Rotated || out.Dropped {
			t.Fatalf("nothing due: %+v", out)
		}
	})
}
