package schedule_test

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/schedule"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type tt struct {
	db *store.DB
	tn tenant.ID
}

func (x tt) Run(ctx context.Context, fn func(context.Context, store.Tx) error) error {
	return x.db.WithTenant(ctx, x.tn, fn)
}

func (g *rig) fire(t *testing.T) *schedule.Fire {
	t.Helper()
	dl, err := delivery.New(g.ch)
	if err != nil {
		t.Fatal(err)
	}
	f := &schedule.Fire{Env: g.env, DB: g.db, Jobs: jobs.NewRegistry(), Deliveries: dl, Audit: g.ch}
	for _, k := range f.Kinds() {
		if err := f.Jobs.Register(k); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (g *rig) sql(q string, args ...any) {
	g.t.Helper()
	if err := g.db.WithTenant(context.Background(), g.tn, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, q, args...)
		return err
	}); err != nil {
		g.t.Fatal(err)
	}
}

func (g *rig) count(q string, args ...any) (n int) {
	g.t.Helper()
	if err := g.db.WithTenant(context.Background(), g.tn, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, q, args...).Scan(&n)
	}); err != nil {
		g.t.Fatal(err)
	}
	return n
}

func (g *rig) str(q string, args ...any) (s string) {
	g.t.Helper()
	if err := g.db.WithTenant(context.Background(), g.tn, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, q, args...).Scan(&s)
	}); err != nil {
		g.t.Fatal(err)
	}
	return s
}

func (g *rig) create(w schedule.WriteInput) string {
	g.t.Helper()
	var conf []operation.Confirmation
	if len(w.ConfirmedExternal) > 0 {
		conf = append(conf, operation.Confirmation{Kind: schedule.ConfirmExternal, Items: w.ConfirmedExternal})
	}
	g.must(owner, schedule.CreateID, in(w), conf...)
	return w.ScheduleID
}

func (g *rig) runKind(f *schedule.Fire, i int, args any) error {
	b, _ := jsonv2.Marshal(args)
	return f.Kinds()[i].RunManaged(context.Background(), tt{g.db, g.tn}, jobs.Claimed{Tenant: g.tn, Args: jsontext.Value(b)})
}

// The tick enqueues one fire per due occurrence and moves next_run_at past now; a repeated tick, even over the
// same occurrence, enqueues nothing more (the missed-run policy and the idempotency key).
func TestTickEnqueuesOnceAndAdvances(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		g := newRig(t, srv)
		f := g.fire(t)
		id := g.create(daily("tst-01", acct(newOw)))
		g.sql(`UPDATE public.report_schedules SET next_run_at = now() - interval '3 days' WHERE id = $1::uuid`, id)
		for range 2 {
			if err := g.runKind(f, 0, struct{}{}); err != nil {
				t.Fatal(err)
			}
		}
		if n := g.count(`SELECT count(*) FROM public.report_schedule_fires WHERE schedule_id = $1::uuid`, id); n != 1 {
			t.Fatalf("fires = %d, want 1 (three missed days coalesce, a repeated tick adds none)", n)
		}
		if n := g.count(`SELECT count(*) FROM public.report_schedules WHERE id = $1::uuid AND next_run_at > now()`, id); n != 1 {
			t.Fatal("next_run_at was not moved past now")
		}
		// the same occurrence again (a crash before the commit of the move) is still one fire
		g.sql(`UPDATE public.report_schedules SET next_run_at = (SELECT due_at FROM public.report_schedule_fires WHERE schedule_id = $1::uuid) WHERE id = $1::uuid`, id)
		if err := g.runKind(f, 0, struct{}{}); err != nil {
			t.Fatal(err)
		}
		if n := g.count(`SELECT count(*) FROM public.report_schedule_fires WHERE schedule_id = $1::uuid`, id); n != 1 {
			t.Fatalf("fires = %d after the same occurrence again", n)
		}
	})
}

// AC-31, AC-32: at fire time an owner who is disabled, lost reports.run or whose scope became empty pauses the
// schedule with its reason, the fire sends nothing, and the pause is audited.
func TestFirePausesWhenOwnerLosesAuthority(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		for _, c := range []struct {
			name, reason string
			break_       func(g *rig)
		}{
			{"disabled", schedule.PauseOwnerDisabled, func(g *rig) { g.env.Owners.(active)[owner] = false }},
			{"lost reports.run", schedule.PauseOwnerLostPerm, func(g *rig) { delete(g.env.Authz.(grants), owner+"/reports.run") }},
			{"scope became empty", schedule.PauseOwnerLostPerm, func(g *rig) { g.env.Scopes.(scopes)[owner] = authz.ReadScope{} }},
		} {
			t.Run(c.name, func(t *testing.T) {
				g := newRig(t, srv)
				f := g.fire(t)
				id := g.create(daily("tst-01", acct(newOw)))
				var fid string
				if err := g.db.WithTenant(context.Background(), g.tn, func(ctx context.Context, tx store.Tx) (err error) {
					fid, err = f.QueueNow(ctx, tx, g.tn, id)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				c.break_(g)
				if err := g.runKind(f, 1, map[string]string{"fireId": fid}); err != nil {
					t.Fatal(err)
				}
				if st, why := g.str(`SELECT state FROM public.report_schedule_fires WHERE id = $1::uuid`, fid), g.str(`SELECT COALESCE(reason, '') FROM public.report_schedule_fires WHERE id = $1::uuid`, fid); st != "paused" || why != c.reason {
					t.Fatalf("fire = %s/%s, want paused/%s", st, why, c.reason)
				}
				s := g.get(id)
				if s.State != schedule.Paused || s.PauseReason != c.reason || s.NextRunAt != nil {
					t.Fatalf("schedule = %s/%s next %v", s.State, s.PauseReason, s.NextRunAt)
				}
				if n := g.count(`SELECT count(*) FROM public.audit_event WHERE kind = $1`, string(schedule.AuditSystemPaused)); n != 1 {
					t.Fatalf("system_paused events = %d", n)
				}
				if n := g.count(`SELECT count(*) FROM public.notify_deliveries WHERE purpose = $1`, schedule.PurposeDelivery); n != 0 {
					t.Fatalf("a paused fire queued %d deliveries", n)
				}
			})
		}
	})
}

// AC-33, AC-46: every recipient is evaluated again at fire time and fails alone with its reason.
func TestDeliverRevalidatesEveryRecipient(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		g := newRig(t, srv)
		f := g.fire(t)
		w := daily("tst-01", acct(other), mailTo("auditor@ext.example"), mailTo("second@ext.example"), acct(newOw))
		w.ConfirmedExternal = []string{"auditor@ext.example", "other@elsewhere.example", "second@ext.example"}
		w.Recipients[0].AsLink = false
		id := g.create(w)
		g.sql(`UPDATE public.report_schedule_recipients SET delivery = 'attachment' WHERE schedule_id = $1::uuid`, id)
		// the owner confirmed auditor@ and second@; now second@ is dropped from the confirmed set, and the owner
		// has lost reports.deliver.external for the rest
		g.sql(`UPDATE public.report_schedules SET confirmed_external = ARRAY['auditor@ext.example'] WHERE id = $1::uuid`, id)
		delete(g.env.Authz.(grants), owner+"/reports.deliver.external")
		g.env.Owners.(active)[newOw] = false
		var fid string
		if err := g.db.WithTenant(context.Background(), g.tn, func(ctx context.Context, tx store.Tx) (err error) {
			if fid, err = f.QueueNow(ctx, tx, g.tn, id); err != nil {
				return err
			}
			return f.Deliver(ctx, tx, g.tn, id, fid, map[string]string{})
		}); err != nil {
			t.Fatal(err)
		}
		var res []schedule.RecipientResult
		if err := jsonv2.Unmarshal([]byte(g.str(`SELECT recipients::text FROM public.report_schedule_fires WHERE id = $1::uuid`, fid)), &res); err != nil {
			t.Fatal(err)
		}
		want := []string{schedule.ReasonAccountExternal, schedule.ReasonOwnerExternal, schedule.ReasonBecameExternal, schedule.ReasonRecipientInactive}
		if len(res) != len(want) {
			t.Fatalf("results = %+v", res)
		}
		for i, r := range res {
			if r.Outcome != "failed" || r.Reason != want[i] {
				t.Errorf("recipient %d = %+v, want failed/%s", i, r, want[i])
			}
		}
		if n := g.count(`SELECT count(*) FROM public.audit_event WHERE kind = $1`, string(schedule.AuditDeliveryFailed)); n != 4 {
			t.Errorf("delivery_failed events = %d, want 4", n)
		}
		if st := g.str(`SELECT state || '/' || COALESCE(reason, '') FROM public.report_schedule_fires WHERE id = $1::uuid`, fid); st != "failed/"+schedule.ReasonAllFailed {
			t.Errorf("fire = %s", st)
		}
		if n := g.count(`SELECT count(*) FROM public.notify_deliveries`); n != 0 {
			t.Errorf("deliveries queued = %d, want 0", n)
		}
	})
}

var _ = authztest.ReadScope
var _ = time.Now
