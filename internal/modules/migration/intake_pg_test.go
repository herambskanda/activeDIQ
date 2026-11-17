package migration_test

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/modules/migration"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

// granted holds migration.import for the listed principals only.
type granted map[authority.PrincipalID]bool

func (granted) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (g granted) Authorize(_ context.Context, c authority.Chain, p authz.Permission, _ authority.TargetRef, _ authority.Facts) error {
	if p == migration.PermImport && g[c.Requester.ID] {
		return nil
	}
	return errors.New("not granted")
}

type facts struct{}

func (facts) Facts(context.Context, authority.Pins, authority.FactsQuery) (authority.Facts, error) {
	return authority.Facts{Exists: true}, nil
}

type recorder struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (r *recorder) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

func (r *recorder) last() audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.evs) == 0 {
		return audit.Event{}
	}
	return r.evs[len(r.evs)-1]
}

type env struct {
	d   *storetest.Database
	db  *store.DB
	tid tenant.ID
	svc *migration.Service
	rec *recorder
}

func chain(id string) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(id), Kind: authority.PrincipalKind("human")}}
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var acts []operation.Action
	for _, b := range []func() (operation.Action, error){migration.CreateProject, migration.SubmitJob} {
		a, err := b()
		if err != nil {
			t.Fatal(err)
		}
		acts = append(acts, a)
	}
	reg, err := operation.NewRegistry(acts...)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	runner, err := operation.NewRunner(operation.Config{DB: db, Audit: rec, Facts: facts{}, Registry: reg, Now: time.Now,
		Authz: granted{"ann": true, "bob": true, "cy": true, "di": true, "eve": true}})
	if err != nil {
		t.Fatal(err)
	}
	return &env{d: d, db: db, tid: tid, svc: &migration.Service{Runner: runner, DB: db}, rec: rec}
}

func (e *env) project(t *testing.T) string {
	t.Helper()
	id, err := e.svc.CreateProject(context.Background(), e.tid, chain("ann"), "ADMP cut-over")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func in(project string, size int64) migration.SubmitJobInput {
	return migration.SubmitJobInput{ProjectID: project, SourceKind: "csv", ADMPBuild: "125.3.1", SizeBytes: size,
		SourceSHA256: hex.EncodeToString(make([]byte, 32))}
}

func TestMigration(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()

		t.Run("migration_job_starts_quarantined", func(t *testing.T) {
			e := setup(t, s)
			p := e.project(t)
			j, err := e.svc.SubmitJob(ctx, e.tid, chain("ann"), in(p, 1<<20))
			if err != nil {
				t.Fatal(err)
			}
			if j.State != "quarantined" || j.Actor != "ann" || j.SourceKind != "csv" || len(j.SourceSHA256) != 32 || j.ProjectID != p {
				t.Fatalf("job = %+v", j)
			}
			if got := e.rec.last().Kind; got != migration.AuditJobSubmitted {
				t.Errorf("audit kind %q", got)
			}
			// The identity is fixed by the database.
			err = e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE public.migration_jobs SET source_kind = 'xlsx' WHERE job_id = $1::uuid`, j.ID)
				return err
			})
			if err == nil {
				t.Error("a job's source kind changed")
			}
		})

		t.Run("migration_size_gate_rejects_before_read", func(t *testing.T) {
			e := setup(t, s)
			p := e.project(t)
			// No SHA-256: the source was never read, only its declared size was seen.
			bad := in(p, 257<<20)
			bad.SourceSHA256 = ""
			j, err := e.svc.SubmitJob(ctx, e.tid, chain("ann"), bad)
			if !errors.Is(err, migration.ErrSizeLimit) {
				t.Fatalf("err = %v", err)
			}
			if j.State != "rejected" || j.LimitHit != "upload_size_256mib" || j.SourceSHA256 != nil {
				t.Fatalf("job = %+v", j)
			}
			// A rejected job holds no quota: the user can submit again.
			if _, err := e.svc.SubmitJob(ctx, e.tid, chain("ann"), in(p, 1<<20)); err != nil {
				t.Errorf("submit after rejection: %v", err)
			}
		})

		t.Run("migration_quota_user", func(t *testing.T) {
			e := setup(t, s)
			p := e.project(t)
			if _, err := e.svc.SubmitJob(ctx, e.tid, chain("ann"), in(p, 1)); err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.SubmitJob(ctx, e.tid, chain("ann"), in(p, 1)); !errors.Is(err, migration.ErrQuotaUser) {
				t.Fatalf("second job of one user: %v", err)
			}
		})

		t.Run("migration_quota_tenant", func(t *testing.T) {
			e := setup(t, s)
			p := e.project(t)
			for _, u := range []string{"ann", "bob", "cy"} {
				if _, err := e.svc.SubmitJob(ctx, e.tid, chain(u), in(p, 1)); err != nil {
					t.Fatalf("%s: %v", u, err)
				}
			}
			if _, err := e.svc.SubmitJob(ctx, e.tid, chain("di"), in(p, 1)); !errors.Is(err, migration.ErrQuotaTenant) {
				t.Fatalf("fourth tenant job: %v", err)
			}
		})

		t.Run("migration_quota_concurrent", func(t *testing.T) {
			e := setup(t, s)
			p := e.project(t)
			var wg sync.WaitGroup
			var mu sync.Mutex
			ok := 0
			for _, u := range []string{"ann", "bob", "cy", "di", "eve"} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := e.svc.SubmitJob(ctx, e.tid, chain(u), in(p, 1)); err == nil {
						mu.Lock()
						ok++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			if ok != migration.MaxActivePerTenant {
				t.Errorf("%d concurrent submissions succeeded; want %d", ok, migration.MaxActivePerTenant)
			}
		})

		t.Run("migration_authz_denied_audited", func(t *testing.T) {
			e := setup(t, s)
			_, err := e.svc.CreateProject(ctx, e.tid, chain("mallory"), "x")
			if !errors.Is(err, operation.ErrDenied) {
				t.Fatalf("err = %v", err)
			}
			if ev := e.rec.last(); ev.Outcome != audit.Denied || ev.Actor.Requester.ID != "mallory" {
				t.Errorf("audit event = %+v", ev)
			}
			var n int
			_ = e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM public.migration_projects`).Scan(&n)
			})
			if n != 0 {
				t.Errorf("%d projects after a denied create", n)
			}
		})

		t.Run("migration_tenant_isolation", func(t *testing.T) {
			e := setup(t, s)
			p := e.project(t)
			other := tenanttest.Seed(t, e.d.ExecOwner, "B")
			if _, err := e.svc.SubmitJob(ctx, other, chain("ann"), in(p, 1)); !errors.Is(err, migration.ErrNoSuchProject) {
				t.Errorf("job in another tenant's project: %v", err)
			}
			j, err := e.svc.SubmitJob(ctx, e.tid, chain("ann"), in(p, 1))
			if err != nil {
				t.Fatal(err)
			}
			var n int
			_ = e.db.WithTenant(ctx, other, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM public.migration_jobs WHERE job_id = $1::uuid`, j.ID).Scan(&n)
			})
			if n != 0 {
				t.Error("tenant B reads tenant A's job")
			}
		})
	})
}

func TestModuleRegisters(t *testing.T) {
	c, err := moduletest.Register(migration.New(platform.Deps{}, directory.Services{}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(c.Permissions(), migration.PermImport) {
		t.Errorf("permission not registered: %v", c.Permissions())
	}
}
