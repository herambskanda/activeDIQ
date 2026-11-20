package schedule_test

import (
	"context"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/modules/reports/schedule"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/blob"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const objectsDDL = `
CREATE TABLE public.rpt_objects (
  tenant_id uuid NOT NULL, connection_id uuid NOT NULL, object_guid uuid NOT NULL, nc_guid uuid, parent_guid uuid,
  ancestry uuid[] NOT NULL DEFAULT '{}', ancestry_complete boolean NOT NULL DEFAULT true,
  sam text NOT NULL,
  PRIMARY KEY (tenant_id, connection_id, object_guid));
GRANT SELECT ON public.rpt_objects TO activediq_app;
ALTER TABLE public.rpt_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rpt_objects FORCE ROW LEVEL SECURITY;
CREATE POLICY rpt_t ON public.rpt_objects FOR SELECT USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY rpt_w ON public.rpt_objects FOR INSERT WITH CHECK (true);`

func oid(b byte) authz.ObjectID { var o authz.ObjectID; o[15] = b; return o }

type fixedFresh struct{ at time.Time }

func (f fixedFresh) Freshness(_ context.Context, _ tenant.ID, cs []authz.ObjectID, now time.Time) (run.FreshnessRead, error) {
	var ws []report.NCWatermark
	for _, c := range cs {
		ws = append(ws, report.NCWatermark{Connection: c, NC: oid(0x10), LastPassAt: f.at, State: report.NCOK})
	}
	return run.FreshnessRead{Label: report.Label(ws, time.Hour, now), Threshold: time.Hour}, nil
}

// AC-30: an owner whose scope shrank from two OUs (here two connections) to one gets, at the next fire, a run
// over the smaller scope only; the fire records the scope that was applied.
func TestFireUsesOwnersCurrentScope(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		ctx := context.Background()
		g := newRig(t, srv)
		conn1, conn2, nc := oid(1), oid(2), oid(0x10)
		for i, r := range []struct {
			c   authz.ObjectID
			sam string
		}{{conn1, "ann"}, {conn1, "cat"}, {conn2, "dan"}} {
			if err := g.d.ExecOwner(ctx, `INSERT INTO public.rpt_objects (tenant_id, connection_id, object_guid, nc_guid, sam)
				VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5)`, g.tn.String(), report.GUIDString(r.c), report.GUIDString(oid(byte(0x30+i))), report.GUIDString(nc), r.sam); err != nil {
				t.Fatal(err)
			}
		}
		term := func(c authz.ObjectID) authz.ScopeTerm {
			return authz.ScopeTerm{Kind: authz.TermNamingContext, Connection: c, Root: nc}
		}
		g.env.Scopes.(scopes)[owner] = authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{term(conn1), term(conn2)}})

		src := dataset()
		src.Columns = src.Columns[:1]
		var reg *reportsql.Registry
		if err := g.db.WithTenant(ctx, g.tn, func(ctx context.Context, tx store.Tx) error {
			sc, err := reportsql.CatalogSchema(ctx, tx)
			if err != nil {
				return err
			}
			reg, err = reportsql.NewRegistry(reportsql.Options{Schema: sc, SecretKey: func(string) bool { return false }}, src)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		sqlDS, _ := reg.Dataset(src.ID)
		def := report.Definition{ID: "tst-01", Version: 1, Category: report.CategoryUsers, Title: "Accounts", Dataset: src.ID,
			Columns: []report.ColumnID{"sam"}, Sort: []report.SortKey{{Column: "sam", Dir: report.Asc}}, Presets: []report.Preset{{ID: "all"}}}
		cat := catalog{map[string]run.Definition{"tst-01": {Def: def, SHA256: [32]byte{1}, Dataset: src, SQL: sqlDS}}}
		g.env.Catalog = cat

		reg2 := jobs.NewRegistry()
		now := time.Now().UTC()
		runs := &run.Service{DB: g.db, Jobs: reg2, Scopes: g.env.Scopes, Audit: g.ch, Catalog: cat, Codec: codec{}, Fresh: fixedFresh{now.Add(-time.Minute)}}
		bs, err := blob.NewFS(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		exps := &export.Service{DB: g.db, Jobs: reg2, Runs: runs, Blob: bs, Audit: g.ch, Authz: g.env.Authz}
		dl, err := delivery.New(g.ch)
		if err != nil {
			t.Fatal(err)
		}
		f := &schedule.Fire{Env: g.env, DB: g.db, Jobs: reg2, Runs: runs, Exports: exps, Deliveries: dl, Audit: g.ch}
		ks := append(f.Kinds(), runs.Kind(), exps.Kind())
		for _, k := range ks {
			if err := reg2.Register(k); err != nil {
				t.Fatal(err)
			}
		}
		work := func() {
			t.Helper()
			cl, err := jobs.Claim(ctx, g.db, reg2.TenantLeases(), 20)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range cl {
				if c.Kind == run.JobKind || c.Kind == export.JobKind {
					if _, err := jobs.NewRunner(g.db, reg2).Execute(ctx, c); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		fireOnce := func(id string) (fid string) {
			t.Helper()
			if err := g.db.WithTenant(ctx, g.tn, func(ctx context.Context, tx store.Tx) (err error) {
				fid, err = f.QueueNow(ctx, tx, g.tn, id)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			// the fire starts the run, waits for it, makes the export, waits again, then delivers
			for range 6 {
				if err := g.runKind(f, 1, map[string]string{"fireId": fid}); err != nil {
					t.Fatal(err)
				}
				work()
				if g.str(`SELECT state FROM public.report_schedule_fires WHERE id = $1::uuid`, fid) == "sent" {
					break
				}
			}
			return fid
		}

		w := daily("tst-01", mailTo("auditor@ext.example"))
		w.ConfirmedExternal = []string{"auditor@ext.example"}
		id := g.create(w)
		rowsOf := func(fid string) (int, string) {
			t.Helper()
			return g.count(`SELECT row_count FROM public.report_schedule_fires WHERE id = $1::uuid`, fid),
				g.str(`SELECT COALESCE(scope_applied::text, '') FROM public.report_schedule_fires WHERE id = $1::uuid`, fid)
		}
		fid1 := fireOnce(id)
		if st := g.str(`SELECT state FROM public.report_schedule_fires WHERE id = $1::uuid`, fid1); st != "sent" {
			t.Fatalf("first fire = %s/%s recipients %s", st, g.str(`SELECT COALESCE(reason,'') FROM public.report_schedule_fires WHERE id = $1::uuid`, fid1), g.str(`SELECT recipients::text FROM public.report_schedule_fires WHERE id = $1::uuid`, fid1))
		}
		n1, sc1 := rowsOf(fid1)
		if n1 != 3 || sc1 == "" {
			t.Fatalf("two-OU fire: rows %d scope %q, want 3 and a recorded scope", n1, sc1)
		}

		// the owner's scope shrinks to one OU before the next fire
		g.env.Scopes.(scopes)[owner] = authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{term(conn1)}})
		fid2 := fireOnce(id)
		if st := g.str(`SELECT state FROM public.report_schedule_fires WHERE id = $1::uuid`, fid2); st != "sent" {
			t.Fatalf("second fire = %s", st)
		}
		n2, sc2 := rowsOf(fid2)
		if n2 != 2 {
			t.Fatalf("one-OU fire rows = %d, want 2 (dan is outside the smaller scope)", n2)
		}
		if sc2 == "" {
			t.Fatalf("scope applied not recorded on the smaller-scope fire")
		}
		// the run itself holds only the owner's current-scope rows
		if n := g.count(`SELECT count(*) FROM public.report_runs WHERE schedule_id = $1::uuid AND row_count = 2`, id); n != 1 {
			t.Fatalf("runs with 2 rows = %d", n)
		}
	})
}
