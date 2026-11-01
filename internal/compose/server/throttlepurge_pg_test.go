package server

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authn/throttlejob"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/jobs/jobstest"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

// throttleRig is a migrated database with two tenants and the console stack bound to the first.
type throttleRig struct {
	db   *store.DB
	d    *storetest.Database
	a, b tenant.ID
	ks   *keys.Store
	now  time.Time
}

func (r *throttleRig) adminStrings(sql string, args ...any) ([]string, error) {
	ctx := context.Background()
	c, err := r.d.Admin(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close(ctx)
	rows, err := c.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func newThrottleRig(t *testing.T, s *storetest.Server) *throttleRig {
	t.Helper()
	ctx := context.Background()
	d := s.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ks := keys.NewStore(keystest.New("kek-1"))
	r := &throttleRig{db: db, d: d, ks: ks, now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	r.a = tenanttest.Seed(t, d.ExecOwner, firstRunTenantName)
	r.b = tenanttest.Seed(t, d.ExecOwner, "other")
	for _, ten := range []tenant.ID{r.a, r.b} {
		if err := db.WithTenant(ctx, ten, func(ctx context.Context, tx store.Tx) error { return ks.Provision(ctx, tx, ten) }); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func throttleKeyOf(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

// put inserts one throttle row for the tenant, as the sign-in path would have left it.
func (r *throttleRig) put(t *testing.T, ten tenant.ID, name string, windowAge, notBeforeFromNow time.Duration) {
	t.Helper()
	err := r.db.WithTenant(context.Background(), ten, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO public.authn_signin_throttle (tenant_id, key_hash, failures, window_start, not_before)
VALUES ($1::uuid, $2, 6, $3, $4)`, ten.String(), throttleKeyOf(name), r.now.Add(-windowAge), r.now.Add(notBeforeFromNow))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// keys returns which of the named rows the tenant still holds.
func (r *throttleRig) held(t *testing.T, ten tenant.ID, names ...string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, n := range names {
		var c int
		err := r.db.WithTenant(context.Background(), ten, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_signin_throttle WHERE key_hash = $1`, throttleKeyOf(n)).Scan(&c)
		})
		if err != nil {
			t.Fatal(err)
		}
		out[n] = c == 1
	}
	return out
}

func (r *throttleRig) total(t *testing.T, ten tenant.ID) int {
	t.Helper()
	var c int
	if err := r.db.WithTenant(context.Background(), ten, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_signin_throttle`).Scan(&c)
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

func (r *throttleRig) purge(t *testing.T, l *authn.LocalCredentials, ten tenant.ID) int {
	t.Helper()
	var n int
	err := r.db.WithTenant(context.Background(), ten, func(ctx context.Context, tx store.Tx) error {
		var err error
		n, err = l.PurgeThrottle(ctx, tx, ten)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (r *throttleRig) local(t *testing.T) (*authn.LocalCredentials, http.Handler, *consoleStack) {
	t.Helper()
	h, console := hardeningHandler(t, r.db, r.a, r.ks)
	console.Local.Clock = func() time.Time { return r.now }
	console.Local.LatencyFloor = -1
	return console.Local, h, console
}

func TestThrottlePurge(t *testing.T) {
	const (
		dead = authn.ThrottleWindow + authn.ThrottlePurgeMargin + time.Minute
		live = authn.ThrottleWindow - time.Minute
		// inside the margin: past the window but not yet purged.
		margin = authn.ThrottleWindow + time.Minute
	)
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		t.Run("purge_keeps_live_throttle", func(t *testing.T) {
			r := newThrottleRig(t, s)
			l, _, _ := r.local(t)
			r.put(t, r.a, "dead", dead, -time.Minute)
			r.put(t, r.a, "live", live, -time.Minute)
			r.put(t, r.a, "in-margin", margin, -time.Minute)
			// An old window whose delay has not passed: a key inside its not_before delay is kept.
			r.put(t, r.a, "delayed", dead, 10*time.Minute)
			if n := r.purge(t, l, r.a); n != 1 {
				t.Errorf("purge deleted %d rows, want 1", n)
			}
			got := r.held(t, r.a, "dead", "live", "in-margin", "delayed")
			want := map[string]bool{"dead": false, "live": true, "in-margin": true, "delayed": true}
			for k, w := range want {
				if got[k] != w {
					t.Errorf("row %q held = %v, want %v", k, got[k], w)
				}
			}
			if n := r.purge(t, l, r.a); n != 0 {
				t.Errorf("a second purge deleted %d rows, want 0 (idempotent)", n)
			}
		})

		t.Run("purge_is_tenant_scoped", func(t *testing.T) {
			r := newThrottleRig(t, s)
			l, _, _ := r.local(t)
			r.put(t, r.a, "a-dead", dead, -time.Minute)
			r.put(t, r.b, "b-dead", dead, -time.Minute)
			r.put(t, r.b, "b-live", live, -time.Minute)
			if n := r.purge(t, l, r.a); n != 1 {
				t.Errorf("purge under A deleted %d rows, want 1", n)
			}
			if r.held(t, r.a, "a-dead")["a-dead"] {
				t.Error("A's dead row survived")
			}
			if got := r.held(t, r.b, "b-dead", "b-live"); !got["b-dead"] || !got["b-live"] {
				t.Errorf("B's rows were touched by A's purge: %v", got)
			}
			if n := r.total(t, r.b); n != 2 {
				t.Errorf("tenant B holds %d rows, want 2", n)
			}
		})

		t.Run("purge_frees_capacity", func(t *testing.T) {
			r := newThrottleRig(t, s)
			l, h, _ := r.local(t)
			l.MaxKeys = 3
			for i := 0; i < 3; i++ {
				r.put(t, r.a, "old"+strconv.Itoa(i), dead, -time.Minute)
			}
			if n := r.purge(t, l, r.a); n != 3 {
				t.Fatalf("purge deleted %d rows, want 3", n)
			}
			if n := r.total(t, r.a); n != 0 {
				t.Fatalf("table holds %d rows after the purge, want 0", n)
			}
			w := postJSON(h, "/api/v1/auth/break-glass/password", `{"username":"never-seen-before","password":"not the password at all"}`)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("unknown name answered %d, want the uniform 401: %s", w.Code, w.Body)
			}
			// The name got its own row: it was not folded into the shared overflow bucket.
			if n := r.total(t, r.a); n != 1 {
				t.Errorf("table holds %d rows after one attempt, want exactly the name's own row", n)
			}
		})

		t.Run("job_registered_enqueued_and_runs", func(t *testing.T) {
			r := newThrottleRig(t, s)
			l, _, _ := r.local(t)
			l.Clock = nil // the job runs on the real clock
			real := time.Now().UTC()
			if err := r.db.WithTenant(context.Background(), r.a, func(ctx context.Context, tx store.Tx) error {
				_, err := tx.Exec(ctx, `INSERT INTO public.authn_signin_throttle (tenant_id, key_hash, failures, window_start, not_before)
VALUES ($1::uuid, $2, 1, $3, $3), ($1::uuid, $4, 1, $5, $5)`, r.a.String(), throttleKeyOf("job-dead"), real.Add(-2*time.Hour), throttleKeyOf("job-live"), real)
				return err
			}); err != nil {
				t.Fatal(err)
			}

			jreg := jobs.NewRegistry()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// A restart registers into a fresh registry and seeds again: still one cadence.
			if err := startThrottlePurge(ctx, r.db, jobs.NewRegistry(), l, r.a); err != nil {
				t.Fatal(err)
			}
			if err := startThrottlePurge(ctx, r.db, jreg, l, r.a); err != nil {
				t.Fatal(err)
			}
			if v, err := jobstest.CountQueued(r.adminStrings, throttlejob.JobPurge); err != nil || v != "1" {
				t.Fatalf("queued purge jobs = %q, %v; want exactly one after two starts", v, err)
			}

			w, err := jobs.NewWorker(r.db, jreg, jobs.WorkerConfig{Holder: "node-1", PollMin: 10 * time.Millisecond, PollMax: 20 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- w.Run(ctx) }()
			deadline := time.Now().Add(15 * time.Second)
			for r.held(t, r.a, "job-dead")["job-dead"] {
				if time.Now().After(deadline) {
					t.Fatal("the purge job did not run: the dead row is still there")
				}
				time.Sleep(50 * time.Millisecond)
			}
			cancel()
			<-done
			if !r.held(t, r.a, "job-live")["job-live"] {
				t.Error("the job deleted a live row")
			}
			if v, err := jobstest.CountQueued(r.adminStrings, throttlejob.JobPurge); err != nil || v != "1" {
				t.Errorf("queued purge jobs after a run = %q, %v; want its successor", v, err)
			}
		})
	})
}
