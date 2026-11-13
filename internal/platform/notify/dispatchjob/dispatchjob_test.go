package dispatchjob_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/egress"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/jobs/jobstest"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/notify/dispatchjob"
	nm "github.com/skenzeriq/activediq/internal/platform/notify/mail"
	"github.com/skenzeriq/activediq/internal/platform/notify/mailtest"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type sink struct{}

func (sink) Append(_ context.Context, _ store.Tx, ev audit.Event) error { return ev.Validate() }

type renderer struct{}

func (renderer) Render(_ context.Context, _ store.Tx, d delivery.Delivery) (delivery.Content, error) {
	return delivery.Content{Subject: "Report", Text: "body"}, nil
}

// AC 1: queued Deliveries due now; the job attempts each once and records its state.
func TestJobAttemptsEachDueDeliveryOnce(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		ten := tenanttest.Seed(t, d.ExecOwner, "t1")
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		dl, err := delivery.New(sink{})
		if err != nil {
			t.Fatal(err)
		}
		srv := mailtest.Start(t, mailtest.STARTTLS)
		eg, err := egress.New(egress.Config{Allow: mailtest.Loopback(), RootCAs: srv.CA()})
		if err != nil {
			t.Fatal(err)
		}
		srv.RejectRcpt("carol@ok.example", 451)
		ids := map[string]string{}
		if err := db.WithTenant(context.Background(), ten, func(ctx context.Context, tx store.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO public.notify_settings (tenant_id, allowed_domains, smtp_host, smtp_port, smtp_security, smtp_from, plaintext_opt_in)
				VALUES ($1::uuid, $2, $3, $4, 'starttls', 'noreply@ok.example', false)`, ten.String(), []string{"ok.example"}, srv.Host(), srv.Port()); err != nil {
				return err
			}
			for _, who := range []string{"alice", "bob", "carol"} {
				del, err := dl.Enqueue(ctx, tx, delivery.NewDelivery{DedupKey: "fire:" + who, Purpose: "test.report", TemplateVersion: 1,
					Variables: map[string]string{}, Recipient: delivery.Recipient{Address: who + "@ok.example"},
					Source: delivery.SourceRef{Kind: "report_export", ID: "exp-1"}, MaxAttempts: 3},
					authority.Chain{Requester: authority.Principal{ID: "owner-1", Kind: authority.Human}})
				if err != nil {
					return err
				}
				ids[who] = del.ID
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		disp := &delivery.Dispatcher{DB: db, Deliveries: dl, Sender: &nm.Sender{Dialer: eg},
			Renderers: map[string]delivery.Renderer{"test.report": renderer{}},
			Backoff:   func(int) time.Duration { return time.Hour }}
		reg := jobs.NewRegistry()
		jb, err := dispatchjob.Register(reg, disp, dispatchjob.Config{Every: time.Hour, BatchSize: 2})
		if err != nil {
			t.Fatal(err)
		}
		seed := func() {
			if err := db.WithTenant(context.Background(), ten, func(ctx context.Context, tx store.Tx) error {
				return jb.Schedule(ctx, tx, ten)
			}); err != nil {
				t.Fatal(err)
			}
		}
		seed()
		seed() // a second start leaves one cadence
		adm := func(q string, a ...any) ([]string, error) { return d.OwnerStrings(context.Background(), q, a...) }
		if v, err := jobstest.CountQueued(adm, dispatchjob.JobDispatch); err != nil || v != "1" {
			t.Fatalf("queued dispatch jobs = %q, %v; want one", v, err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w, err := jobs.NewWorker(db, reg, jobs.WorkerConfig{Holder: "n1", PollMin: 10 * time.Millisecond, PollMax: 20 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- w.Run(ctx) }()
		deadline := time.Now().Add(20 * time.Second)
		state := func(id string) delivery.Delivery {
			var out delivery.Delivery
			if err := db.WithTenant(context.Background(), ten, func(ctx context.Context, tx store.Tx) error {
				var err error
				out, err = dl.Get(ctx, tx, id)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return out
		}
		for state(ids["alice"]).State != delivery.Sent || state(ids["bob"]).State != delivery.Sent || state(ids["carol"]).Attempts == 0 {
			if time.Now().After(deadline) {
				t.Fatal("the dispatch job did not attempt the due deliveries")
			}
			time.Sleep(50 * time.Millisecond)
		}
		cancel()
		<-done

		if c := state(ids["carol"]); c.State != delivery.Failed || c.Attempts != 1 {
			t.Errorf("carol = %+v, want failed after exactly one attempt", c)
		}
		for _, who := range []string{"alice", "bob"} {
			if g := state(ids[who]); g.Attempts != 1 || g.ProviderMessageID == "" {
				t.Errorf("%s = %+v, want one attempt and a message id", who, g)
			}
		}
		if n := len(srv.Messages()); n != 2 {
			t.Errorf("relay got %d messages, want 2", n)
		}
		if v, err := jobstest.CountQueued(adm, dispatchjob.JobDispatch); err != nil || v != "1" {
			t.Errorf("queued dispatch jobs after a run = %q, %v; want the successor", v, err)
		}
	})
}

func TestRegisterRefusesBadConfig(t *testing.T) {
	if _, err := dispatchjob.Register(nil, &delivery.Dispatcher{}, dispatchjob.Config{}); err == nil {
		t.Error("nil registry accepted")
	}
	if _, err := dispatchjob.Register(jobs.NewRegistry(), nil, dispatchjob.Config{}); err == nil {
		t.Error("nil dispatcher accepted")
	}
	if _, err := dispatchjob.Register(jobs.NewRegistry(), &delivery.Dispatcher{}, dispatchjob.Config{BatchSize: 501}); err == nil {
		t.Error("batch 501 accepted")
	}
}
