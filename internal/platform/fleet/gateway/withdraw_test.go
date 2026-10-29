package gateway_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/fleet/gateway"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

type wKeys struct {
	mu   sync.Mutex
	deks map[tenant.ID][]byte
}

func (k *wKeys) DEK(_ context.Context, _ store.Tx, id tenant.ID, version uint32) (keys.DEK, error) {
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

type wSink struct{}

func (wSink) Append(_ context.Context, _ store.Tx, ev audit.Event) error { return ev.Validate() }

type wAuthz struct{}

func (wAuthz) Allow(_ context.Context, _ apihost.Principal, perm, scope string) (bool, error) {
	return perm == fleetsql.PermissionCAWithdraw && scope == "tenant", nil
}

type wAlerts struct{}

func (wAlerts) Raise(context.Context, fleetsql.Alert) {}

// T-0777 / F-POOL-8: the process that commits a CA withdrawal ends that tenant's open streams at once
// (the stream re-check is set far beyond the test so only CloseTenant can end them) and leaves the
// streams of other tenants open. The committing code is the real CAAdmin on a real database, with the
// real gateway and pool provider as its ports.
func TestCAAdminWithdrawEndsTenantStreams(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		d := s.NewDatabase(t)
		d.Migrate(t)
		tidA, tidB := tenanttest.Seed(t, d.ExecOwner, "A"), tenanttest.Seed(t, d.ExecOwner, "B")
		db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		ks := &wKeys{}
		enr := &fleetsql.Enroller{Enrollment: &fleetsql.Enrollment{DB: db}, Keys: ks, Alerts: wAlerts{}, Audit: wSink{}}
		for _, tid := range []tenant.ID{tidA, tidB} {
			tid := tid
			if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error { return enr.InitTenant(ctx, tx, tid) }); err != nil {
				t.Fatal(err)
			}
		}
		var caID string
		if err := db.WithTenant(ctx, tidA, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT id::text FROM public.fleet_ca WHERE state = 'active'`).Scan(&caID)
		}); err != nil {
			t.Fatal(err)
		}

		nb, na, eku := time.Now().Add(-time.Minute), time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		caA, caB := newCA(t, na), newCA(t, na)
		pool := &certSet{}
		pool.AddCert(caA.cert)
		pool.AddCert(caB.cert)
		cas := &casMut{m: map[tenant.ID][]*x509.Certificate{tidA: {caA.cert}, tidB: {caB.cert}}}
		r := start(t, cas, pool, nil, func(c *gateway.Config) { c.Recheck = time.Hour })
		r.fleet.hold.Store(true)

		var errs []chan error
		for _, l := range []struct {
			ca  testCA
			tid tenant.ID
		}{{caA, tidA}, {caA, tidA}, {caB, tidB}} {
			leaf := l.ca.leaf(t, l.tid, nb, na, eku)
			errs = append(errs, recvErr(openTunnel(t, r.dial(t, &leaf))))
		}
		waitFor(t, "three open streams", func() bool { return r.fleet.open.Load() == 3 })

		pp, err := gateway.NewPoolProvider(gateway.PoolConfig{Load: func(context.Context) ([]*x509.Certificate, error) { return pool.cs, nil }})
		if err != nil {
			t.Fatal(err)
		}
		admin := &fleetsql.CAAdmin{DB: db, Authz: wAuthz{}, Keys: ks, Audit: wSink{}, Pool: pp, Streams: r.gw}
		res, err := admin.Withdraw(ctx, tidA, apihost.Principal{ID: "human-1", Kind: apihost.KindSession}, caID, "key exposure suspected")
		if err != nil || res.ClosedStreams != 2 || !res.Replaced {
			t.Fatalf("withdraw: %+v %v", res, err)
		}
		for i := 0; i < 2; i++ {
			select {
			case err := <-errs[i]:
				if code(err) != codes.Unauthenticated {
					t.Fatalf("tenant A stream %d ended with %v", i, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("tenant A stream %d stayed open", i)
			}
		}
		select {
		case err := <-errs[2]:
			t.Fatalf("tenant B stream ended: %v", err)
		case <-time.After(300 * time.Millisecond):
		}
	})
}
