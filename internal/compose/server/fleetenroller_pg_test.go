package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/provision"
)

type enrAllow struct{}

func (enrAllow) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (enrAllow) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

type failKeys struct{}

func (failKeys) DEK(context.Context, store.Tx, tenant.ID, uint32) (keys.DEK, error) {
	return keys.DEK{}, errors.New("keys: ProviderUnavailable")
}

func enrollerEnv(t *testing.T, s *storetest.Server) (*store.DB, *keys.Store) {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db, keys.NewStore(keystest.New("kek-1"))
}

// AC1/AC2: FirstRun runs once and is idempotent on restart; the Enroller is built over the real key
// source for that tenant; a source that cannot serve it stops startup with a clear error.
func TestFirstRunThenEnrollerOverRealKeySource(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		db, ks := enrollerEnv(t, s)
		r1, err := provision.FirstRun(ctx, db, firstRunTenantName, ks.Provision)
		if err != nil || !r1.Created {
			t.Fatalf("first boot: %+v %v", r1, err)
		}
		r2, err := provision.FirstRun(ctx, db, firstRunTenantName, ks.Provision)
		if err != nil || r2.Created || r2.Tenant != r1.Tenant {
			t.Fatalf("restart: %+v %v", r2, err)
		}
		al, _ := newQueueAlerter(db, &recSink{}, nil)
		deps := fleetEnrollerDeps{DB: db, Audit: &recSink{}, Keys: ks.KeySource(), Authz: enrAllow{}, StepUp: enrAllow{}, Alerts: al}
		if e, err := buildEnroller(ctx, deps, r1.Tenant); err != nil || e.Keys == nil || e.Alerts == nil {
			t.Fatalf("buildEnroller = %v, %v", e, err)
		}
		deps.Keys = failKeys{}
		if _, err := buildEnroller(ctx, deps, r1.Tenant); !errors.Is(err, ErrNoFleetKeys) || !strings.Contains(err.Error(), "ProviderUnavailable") {
			t.Fatalf("failing source: %v", err)
		}
		deps.Keys = nil
		if _, err := buildEnroller(ctx, deps, r1.Tenant); !errors.Is(err, ErrNoFleetKeys) {
			t.Fatalf("nil source: %v", err)
		}
	})
}

// AC3: Raise returns at once, even with a full queue, and the queued record names the kind and tenant and
// nothing else.
func TestAlerterQueuesAnAuditRecordWithoutSecrets(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		db, ks := enrollerEnv(t, s)
		res, err := provision.FirstRun(ctx, db, firstRunTenantName, ks.Provision)
		if err != nil {
			t.Fatal(err)
		}
		sink := &recSink{}
		al, err := newQueueAlerter(db, sink, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Not running yet: Raise must still return, even past the queue's capacity.
		start := time.Now()
		for i := 0; i < alertQueueSize+10; i++ {
			al.Raise(ctx, fleetsql.Alert{Kind: fleetsql.AlertCAMaterial, Tenant: res.Tenant})
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("Raise blocked")
		}
		rctx, cancel := context.WithCancel(ctx)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); al.Run(rctx) }()
		cancel() // drains what is queued, then returns
		wg.Wait()
		al.Wait()
		sink.mu.Lock()
		defer sink.mu.Unlock()
		if len(sink.evs) != alertQueueSize {
			t.Fatalf("recorded %d, want %d", len(sink.evs), alertQueueSize)
		}
		ev := sink.evs[0]
		if ev.Kind != audit.Kind(fleetsql.AlertCAMaterial) || ev.Reason != "fleet.ca.material_invalid" || ev.Target.GUID != res.Tenant.String() {
			t.Fatalf("event = %+v", ev)
		}
		for _, d := range ev.Details {
			if d.Key != "alert" {
				t.Fatalf("unexpected detail %q", d.Key)
			}
		}
	})
}
