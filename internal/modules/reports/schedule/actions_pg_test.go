package schedule_test

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/run"
	"github.com/skenzeriq/activediq/internal/modules/reports/schedule"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

const (
	owner = "00000000-0000-4000-8000-0000000000a1"
	other = "00000000-0000-4000-8000-0000000000b2"
	admin = "00000000-0000-4000-8000-0000000000c3" // manage_all, not the owner
	newOw = "00000000-0000-4000-8000-0000000000d4"
)

type keySrc struct{}

func (keySrc) DEK(context.Context, store.Tx, tenant.ID, uint32) (keys.DEK, error) {
	return keys.DEKFromBytes(1, bytes.Repeat([]byte{7}, keys.DEKSize))
}

// grants is the principals' permissions at any target (the runner's authorizer) and, through Allow, the
// module's own checks.
type grants map[string]bool

func (grants) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}
func (g grants) Authorize(_ context.Context, c authority.Chain, p authz.Permission, _ authority.TargetRef, _ authority.Facts) error {
	if g[string(c.Requester.ID)+"/"+string(p)] {
		return nil
	}
	return errors.New("not granted")
}
func (g grants) Allow(_ context.Context, _ tenant.ID, c authority.Chain, p authz.Permission) (bool, error) {
	return g[string(c.Requester.ID)+"/"+string(p)], nil
}

type scopes map[string]authz.ReadScope

func (s scopes) For(_ context.Context, _ store.Tx, _ tenant.ID, c authority.Chain, _ authz.Permission) (authz.ReadScope, error) {
	return s[string(c.Requester.ID)], nil
}

type mail map[string]string

func (m mail) MailAddress(_ context.Context, _ store.Tx, id string) (string, error) {
	if a, ok := m[id]; ok {
		return a, nil
	}
	return "", delivery.ErrNoAddress
}

type active map[string]bool

func (a active) Active(_ context.Context, _ store.Tx, _ tenant.ID, id string) (bool, error) {
	return a[id], nil
}

type catalog struct{ defs map[string]run.Definition }

func (c catalog) Definition(id string, _ int) (run.Definition, bool) {
	d, ok := c.defs[id]
	return d, ok
}

type codec struct{}

func (codec) Decode(jsontext.Value, report.Definition) (report.RunParams, error) {
	return report.RunParams{}, nil
}

func dataset() report.Dataset {
	anchor := report.Anchor{ID: "t", Table: "rpt_objects", Mode: report.RowAnchor, Project: []report.Ident{"object_guid"},
		Connection: "connection_id", NC: "nc_guid", Object: "object_guid", Parent: "parent_guid", Ancestry: "ancestry", Complete: "ancestry_complete"}
	return report.Dataset{
		ID: "tst.objects", Base: report.Relation{Table: "rpt_objects"}, RowKey: report.SQL("{t}.object_guid"), Anchors: []report.Anchor{anchor},
		Columns: []report.Column{
			{ID: "sam", Label: "Account", Type: report.TypeText, Source: report.Attr{Col: "sam"}, Sortable: true, Default: true},
			{ID: "lastlogon", Label: "Last logon", Type: report.TypeTime, Source: report.PerDC{Attr: report.PerDCLastLogon, Agg: report.AggMax}},
		},
		Freshness: report.FreshNCWatermark, Tables: []string{"rpt_objects"},
	}
}

type rig struct {
	t   *testing.T
	r   *operation.Runner
	tn  tenant.ID
	env *schedule.Env
	db  *store.DB
}

func newRig(t *testing.T, srv *storetest.Server) *rig {
	t.Helper()
	ctx := context.Background()
	d := srv.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ch := audit.NewChainer(db)
	cp := audit.NewCheckpointer(ch, keySrc{})
	tn := tenanttest.Seed(t, d.ExecOwner, "A")
	if err := db.WithTenant(ctx, tn, func(ctx context.Context, tx store.Tx) error { return cp.InitTenant(ctx, tx, tn) }); err != nil {
		t.Fatal(err)
	}
	ds := dataset()
	plain := report.Definition{ID: "tst-01", Version: 1, Category: report.CategoryUsers, Title: "Accounts", Dataset: ds.ID,
		Columns: []report.ColumnID{"sam"}, Presets: []report.Preset{{ID: "all"}}}
	perdc := report.Definition{ID: "tst-02", Version: 1, Category: report.CategoryUsers, Title: "Last logon", Dataset: ds.ID,
		Columns: []report.ColumnID{"sam", "lastlogon"}, Presets: []report.Preset{{ID: "all"}}}
	g := grants{}
	for _, who := range []string{owner, other} {
		g[who+"/reports.schedule"], g[who+"/reports.run"] = true, true
	}
	g[owner+"/reports.deliver.external"] = true
	g[admin+"/reports.schedule"], g[admin+"/reports.schedule.manage_all"] = true, true
	grant := authz.ScopeGrant{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext}}}
	env := &schedule.Env{
		Catalog: catalog{map[string]run.Definition{"tst-01": {Def: plain, Dataset: ds}, "tst-02": {Def: perdc, Dataset: ds}}},
		Codec:   codec{}, Authz: g, Owners: active{owner: true, other: true, admin: true, newOw: true},
		Accounts: mail{owner: "owner@corp.example", other: "other@elsewhere.example"},
		Scopes:   scopes{owner: authztest.ReadScope(grant), other: authztest.ReadScope(grant)},
		Perm:     schedule.Permissions{Run: "reports.run", Schedule: "reports.schedule", ManageAll: "reports.schedule.manage_all", DeliverExternal: "reports.deliver.external"},
	}
	acts, err := env.Actions()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := operation.NewRegistry(acts...)
	if err != nil {
		t.Fatal(err)
	}
	rn, err := operation.NewRunner(operation.Config{DB: db, Audit: ch, Authz: g, Registry: reg, Gate: operation.PermissionOnly{}, Component: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ExecOwner(ctx, `UPDATE public.tenant_settings SET value = value WHERE false`); err != nil {
		_ = err // the allowed domains default to none: every address is external
	}
	return &rig{t: t, r: rn, tn: tn, env: env, db: db}
}

func human(id string) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(id), Kind: authority.Human}}
}

var seq int

func opID() step.OperationID {
	seq++
	return step.OperationID(fmt.Sprintf("00000000-0000-4000-8000-%012d", seq))
}

func schedID() string { seq++; return fmt.Sprintf("11111111-0000-4000-8000-%012d", seq) }

func in(v any) operation.Input {
	b, err := jsonv2.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func daily(def string, rs ...schedule.Recipient) schedule.WriteInput {
	return schedule.WriteInput{ScheduleID: schedID(), Name: "Weekly accounts", DefinitionID: def, Recurrence: schedule.Recurrence{Kind: "daily", Time: "06:30"},
		TimeZone: "Europe/Berlin", Recipients: rs}
}

func acct(id string) schedule.Recipient {
	return schedule.Recipient{Kind: "account", AccountID: id, Formats: []string{"csv"}}
}
func mailTo(a string) schedule.Recipient {
	return schedule.Recipient{Kind: "email", Address: a, Formats: []string{"csv"}}
}

func (g *rig) preview(who string, a operation.ActionID, input operation.Input) operation.Preview {
	g.t.Helper()
	p, err := g.r.PreviewStore(context.Background(), operation.Request{Tenant: g.tn, Actor: human(who), Action: a, Input: input})
	if err != nil {
		g.t.Fatalf("preview %s: %v", a, err)
	}
	return p
}

func (g *rig) submit(who string, a operation.ActionID, input operation.Input, conf ...operation.Confirmation) (operation.Result, error) {
	return g.r.SubmitStore(context.Background(), operation.Request{Tenant: g.tn, Actor: human(who), Action: a, Input: input, Operation: opID(), Confirmed: conf, FreshStepUp: true})
}

func (g *rig) must(who string, a operation.ActionID, input operation.Input, conf ...operation.Confirmation) operation.Result {
	g.t.Helper()
	res, err := g.submit(who, a, input, conf...)
	if err != nil {
		g.t.Fatalf("%s: %v", a, err)
	}
	return res
}

func (g *rig) get(id string) schedule.Schedule {
	g.t.Helper()
	var s schedule.Schedule
	err := g.db.WithTenant(context.Background(), g.tn, func(ctx context.Context, tx store.Tx) error {
		var err error
		s, err = g.env.Store.Get(ctx, tx, id, false)
		return err
	})
	if err != nil {
		g.t.Fatal(err)
	}
	return s
}

func blocked(p operation.Preview) string {
	if p.Outcome != operation.PreviewRefused || len(p.Blocked) != 1 {
		return fmt.Sprintf("not refused: %+v", p.Outcome)
	}
	return p.Blocked[0].Code
}

// AC-38: a per-DC report more often than daily is refused; a daily one is not.
func TestPerDCReportNoMoreOftenThanDaily(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		g := newRig(t, srv)
		h := daily("tst-02", acct(newOw))
		min := 0
		h.Recurrence = schedule.Recurrence{Kind: "hourly", EveryHours: 1, Minute: &min}
		if c := blocked(g.preview(owner, schedule.CreateID, in(h))); c != schedule.CodePerDCDaily {
			t.Fatalf("hourly per-DC = %s", c)
		}
		h.Recurrence = schedule.Recurrence{Kind: "hourly", EveryHours: 24, Minute: &min}
		if p := g.preview(owner, schedule.CreateID, in(h)); p.Outcome != operation.PreviewReady {
			t.Fatalf("every 24 h per-DC = %+v", p)
		}
		plain := daily("tst-01", acct(newOw))
		plain.Recurrence = schedule.Recurrence{Kind: "hourly", EveryHours: 1, Minute: &min}
		if p := g.preview(owner, schedule.CreateID, in(plain)); p.Outcome != operation.PreviewReady {
			t.Fatalf("hourly plain = %+v", p)
		}
	})
}

// AC-33: an external recipient needs reports.deliver.external, the preview carries the confirmation, and the
// step-up rule follows the confirmed set.
func TestExternalRecipientNeedsPermissionAndConfirmation(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		g := newRig(t, srv)
		ext := daily("tst-01", acct(owner), mailTo("auditor@ext.example"))
		if c := blocked(g.preview(other, schedule.CreateID, in(ext))); c != schedule.CodeExternalNotAllowed {
			t.Fatalf("without the permission = %s", c)
		}
		ext.ConfirmedExternal = []string{"auditor@ext.example", "owner@corp.example"} // the account's address is external too (no allowed domains)
		p := g.preview(owner, schedule.CreateID, in(ext))
		if p.Outcome != operation.PreviewReady || !p.StepUpRequired || len(p.Confirmations) != 1 || p.Confirmations[0].Kind != schedule.ConfirmExternal ||
			len(p.Confirmations[0].Items) != 2 {
			t.Fatalf("preview = %+v", p)
		}
		ext.ConfirmedExternal = []string{"auditor@ext.example"} // incomplete
		if c := blocked(g.preview(owner, schedule.CreateID, in(ext))); c != schedule.CodeExternalUnconfirm {
			t.Fatalf("partial confirmation = %s", c)
		}
	})
}

// AC-45: each Action is previewed, applied, audited and undone to the previous version.
func TestEveryActionHasPreviewAuditAndUndo(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		g := newRig(t, srv)
		ctx := context.Background()
		w := daily("tst-01", mailTo("x@ext.example"))
		w.Recipients = []schedule.Recipient{acct(owner)}
		w.ConfirmedExternal = []string{"owner@corp.example"}
		created := g.must(owner, schedule.CreateID, in(w), operation.Confirmation{Kind: schedule.ConfirmExternal, Items: w.ConfirmedExternal})
		if s := g.get(w.ScheduleID); s.State != schedule.Active || s.Version != 1 || s.NextRunAt == nil {
			t.Fatalf("created = %+v", s)
		}
		// update by the owner; a manage_all holder cannot edit (R1)
		w2 := w
		w2.Name = "Renamed"
		if c := blocked(g.preview(admin, schedule.UpdateID, in(w2))); c != schedule.CodeNotOwner {
			t.Fatalf("manage_all update = %s", c)
		}
		upd := g.must(owner, schedule.UpdateID, in(w2), operation.Confirmation{Kind: schedule.ConfirmExternal, Items: w.ConfirmedExternal})
		if g.get(w.ScheduleID).Name != "Renamed" {
			t.Fatal("update not applied")
		}
		// pause by manage_all, resume by the owner only
		pause := g.must(admin, schedule.PauseID, in(schedule.IDInput{ScheduleID: w.ScheduleID}))
		if s := g.get(w.ScheduleID); s.State != schedule.Paused || s.NextRunAt != nil {
			t.Fatalf("paused = %+v", s)
		}
		if c := blocked(g.preview(admin, schedule.ResumeID, in(schedule.ResumeInput{ScheduleID: w.ScheduleID, ConfirmedExternal: w.ConfirmedExternal}))); c != schedule.CodeNotOwner {
			t.Fatalf("manage_all resume = %s", c)
		}
		// undo of pause = active again (the owner), then pause again to continue
		if _, err := g.r.UndoStore(ctx, operation.UndoRequest{Tenant: g.tn, Actor: human(owner), Family: "reports.schedule", Base: "reports.schedule",
			Original: pause.Operation, Operation: opID(), FreshStepUp: true,
			Confirmed: []operation.Confirmation{{Kind: schedule.ConfirmExternal, Items: w.ConfirmedExternal}}}); err != nil {
			t.Fatalf("undo pause: %v", err)
		}
		if g.get(w.ScheduleID).State != schedule.Active {
			t.Fatal("undo of pause did not reactivate")
		}
		// reassign needs manage_all, leaves it paused; undo is the previous owner, still paused (Lossy)
		if c := blocked(g.preview(owner, schedule.ReassignID, in(schedule.ReassignInput{ScheduleID: w.ScheduleID, OwnerAccountID: newOw}))); c == "" {
			t.Fatal("owner reassign should be refused")
		}
		re := g.must(admin, schedule.ReassignID, in(schedule.ReassignInput{ScheduleID: w.ScheduleID, OwnerAccountID: newOw}))
		if s := g.get(w.ScheduleID); s.Owner != newOw || s.State != schedule.Paused || s.PauseReason != schedule.PauseReassigned {
			t.Fatalf("reassigned = %+v", s)
		}
		if _, err := g.r.UndoStore(ctx, operation.UndoRequest{Tenant: g.tn, Actor: human(admin), Family: "reports.schedule", Base: "reports.schedule",
			Original: re.Operation, Operation: opID()}); err != nil {
			t.Fatalf("undo reassign: %v", err)
		}
		if s := g.get(w.ScheduleID); s.Owner != owner || s.State != schedule.Paused {
			t.Fatalf("after undo of reassign = %+v", s)
		}
		// the undo of an update that a later write superseded is refused
		var nu *operation.NotUndoableError
		if _, err := g.r.UndoStore(ctx, operation.UndoRequest{Tenant: g.tn, Actor: human(owner), Family: "reports.schedule", Base: "reports.schedule",
			Original: upd.Operation, Operation: opID(), FreshStepUp: true}); !errors.As(err, &nu) || nu.Code != operation.UndoSuperseded {
			t.Fatalf("undo of a superseded update = %v", err)
		}
		// delete (owner only) and undo it
		resume := g.must(owner, schedule.ResumeID, in(schedule.ResumeInput{ScheduleID: w.ScheduleID, ConfirmedExternal: w.ConfirmedExternal}),
			operation.Confirmation{Kind: schedule.ConfirmExternal, Items: w.ConfirmedExternal})
		_ = resume
		del := g.must(owner, schedule.DeleteID, in(schedule.IDInput{ScheduleID: w.ScheduleID}))
		if g.get(w.ScheduleID).State != schedule.Archived {
			t.Fatal("not archived")
		}
		if _, err := g.r.UndoStore(ctx, operation.UndoRequest{Tenant: g.tn, Actor: human(owner), Family: "reports.schedule", Base: "reports.schedule",
			Original: del.Operation, Operation: opID(), FreshStepUp: true,
			Confirmed: []operation.Confirmation{{Kind: schedule.ConfirmExternal, Items: w.ConfirmedExternal}}}); err != nil {
			t.Fatalf("undo delete: %v", err)
		}
		if g.get(w.ScheduleID).State != schedule.Active {
			t.Fatal("undo of delete did not restore the schedule")
		}
		// undo of create archives it ("Schedule removed"), for the owner only
		g2 := daily("tst-01", acct(newOw)) // an account with no address is not external
		c2 := g.must(other, schedule.CreateID, in(g2))
		if _, err := g.r.UndoStore(ctx, operation.UndoRequest{Tenant: g.tn, Actor: human(admin), Family: "reports.schedule", Base: "reports.schedule",
			Original: c2.Operation, Operation: opID()}); err == nil {
			t.Fatal("manage_all undid a create (an archive is a delete, R2)")
		}
		if _, err := g.r.UndoStore(ctx, operation.UndoRequest{Tenant: g.tn, Actor: human(other), Family: "reports.schedule", Base: "reports.schedule",
			Original: c2.Operation, Operation: opID()}); err != nil {
			t.Fatalf("undo create: %v", err)
		}
		if g.get(g2.ScheduleID).State != schedule.Archived {
			t.Fatal("undo of create did not archive")
		}
		_, _ = created, time.Now
	})
}
