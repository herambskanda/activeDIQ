package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/modules/notify"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/notify/settings"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

// roles maps a principal to a role name; "owner" holds the permission (the tenant owner, DM-34.I1),
// every other name takes its permissions from the shipped roles.
type roles map[authority.PrincipalID]string

func (h roles) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (h roles) Authorize(_ context.Context, c authority.Chain, p authz.Permission, t authority.TargetRef, _ authority.Facts) error {
	name := h[c.Requester.ID]
	perms := []authz.Permission{notify.PermUpdateSettings}
	if name != "owner" {
		perms = nil
		for _, r := range rbac.BuiltInRoles() {
			if r.Name == name {
				perms = r.Permissions
			}
		}
	}
	if slices.Contains(perms, p) && t.Class == notify.TargetClassSettings {
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
	db     *store.DB
	tid    tenant.ID
	runner *operation.Runner
	rec    *recorder
	seq    int
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
	a, err := notify.UpdateSettings()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := operation.NewRegistry(a)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	runner, err := operation.NewRunner(operation.Config{DB: db, Audit: rec, Facts: facts{}, Registry: reg, Now: time.Now,
		Authz: roles{"olga": "owner", "helen": "helpdesk-operator", "paula": "platform-administrator"}})
	if err != nil {
		t.Fatal(err)
	}
	return &env{db: db, tid: tid, runner: runner, rec: rec}
}

func (e *env) req(actor string, kind authority.PrincipalKind, stepUp bool, in notify.SettingsInput) operation.Request {
	e.seq++
	raw, _ := json.Marshal(in)
	return operation.Request{Tenant: e.tid, Actor: authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(actor), Kind: kind}},
		Action: notify.UpdateSettingsActionID, Input: raw, Operation: step.OperationID("op-notify-" + string(rune('a'+e.seq))), FreshStepUp: stepUp}
}

func (e *env) get(t *testing.T) settings.Settings {
	t.Helper()
	var got settings.Settings
	if err := e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) (err error) {
		got, err = settings.Store{}.Get(ctx, tx)
		return
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestModuleRegisters(t *testing.T) {
	if _, err := moduletest.Register(notify.New(platform.Deps{}, directory.Services{})); err != nil {
		t.Fatal(err)
	}
}

func TestDescriptorIsStepUpControlPlane(t *testing.T) {
	a, err := notify.UpdateSettings()
	if err != nil {
		t.Fatal(err)
	}
	d := a.Describe()
	if !d.StepUp || !d.ControlPlane || d.Permission != notify.PermUpdateSettings {
		t.Fatalf("descriptor %+v", d)
	}
	if !authz.NeverCrosses(d.Permission) {
		t.Fatal("permission can cross a correlation")
	}
}

func TestNoBuiltInRoleHoldsPermission(t *testing.T) {
	for _, r := range rbac.BuiltInRoles() {
		if slices.Contains(r.Permissions, notify.PermUpdateSettings) {
			t.Errorf("built-in role %q holds %q", r.Name, notify.PermUpdateSettings)
		}
	}
}

// Acceptance 3: an empty list makes every address external; after the Action adds the domain it is internal.
// The audit event shows the list before and after. Matching is exact: a subdomain is not admitted.
func TestAllowedDomainsClassifyAfterUpdate(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()

		def := e.get(t)
		if def.Version != 0 || len(def.AllowedDomains) != 0 {
			t.Fatalf("default %+v", def)
		}
		if _, c, err := def.ClassifyString("ann@ok.example"); err != nil || c != settings.External {
			t.Fatalf("empty list: %v %v", c, err)
		}

		if _, err := e.runner.RunStore(ctx, e.req("olga", authority.Human, true, notify.SettingsInput{AllowedDomains: []string{"OK.example"}})); err != nil {
			t.Fatal(err)
		}
		ev := e.rec.last()
		if ev.Kind != notify.AuditSettingsUpdated || ev.Outcome != audit.Success || ev.Actor.Requester.ID != "olga" || ev.Target.Class != notify.TargetClassSettings {
			t.Fatalf("event %+v", ev)
		}
		if len(ev.Changes) != 1 || ev.Changes[0].Attribute != "allowed_domains" || len(ev.Changes[0].Before) != 0 ||
			!slices.Equal(ev.Changes[0].After, []string{"ok.example"}) {
			t.Fatalf("changes %+v", ev.Changes)
		}

		got := e.get(t)
		if got.Version != 1 {
			t.Fatalf("version %d", got.Version)
		}
		for raw, want := range map[string]settings.Class{
			"ann@ok.example":              settings.Internal,
			"Ann@OK.EXAMPLE":              settings.Internal,
			"ann@sub.ok.example":          settings.External,
			"ann@ok.example.evil.example": settings.External,
			"ann@other.example":           settings.External,
		} {
			if _, c, err := got.ClassifyString(raw); err != nil || c != want {
				t.Errorf("%s: %v %v, want %v", raw, c, err, want)
			}
		}
	})
}

func TestUpdateRefusals(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		in := notify.SettingsInput{AllowedDomains: []string{"ok.example"}}
		for _, c := range []struct {
			name string
			req  operation.Request
		}{
			{"no step-up", e.req("olga", authority.Human, false, in)},
			{"help desk", e.req("helen", authority.Human, true, in)},
			{"platform admin", e.req("paula", authority.Human, true, in)},
			{"unknown", e.req("mallory", authority.Human, true, in)},
		} {
			if _, err := e.runner.RunStore(ctx, c.req); !errors.Is(err, operation.ErrDenied) {
				t.Errorf("%s: %v", c.name, err)
			}
			if got := e.get(t); got.Version != 0 || len(got.AllowedDomains) != 0 {
				t.Fatalf("%s changed the settings: %+v", c.name, got)
			}
		}
		if ev := e.rec.last(); ev.Outcome == audit.Success {
			t.Fatalf("last event %+v", ev)
		}
	})
}

func TestUpdateInputValidated(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		for name, in := range map[string]notify.SettingsInput{
			"wildcard":        {AllowedDomains: []string{"*.ok.example"}},
			"leading dot":     {AllowedDomains: []string{".ok.example"}},
			"address":         {AllowedDomains: []string{"a@ok.example"}},
			"ip literal":      {AllowedDomains: []string{"[10.0.0.1]"}},
			"plaintext no ok": {Relay: &notify.RelayInput{Host: "smtp.ok.example", Security: "none", From: "noreply@ok.example"}},
			"bad security":    {Relay: &notify.RelayInput{Host: "smtp.ok.example", Security: "ssl", From: "noreply@ok.example"}},
			"bad sender":      {Relay: &notify.RelayInput{Host: "smtp.ok.example", Security: "starttls", From: "Bob <b@ok.example>"}},
			"host with port":  {Relay: &notify.RelayInput{Host: "smtp.ok.example:25", Security: "starttls", From: "n@ok.example"}},
		} {
			if _, err := e.runner.RunStore(context.Background(), e.req("olga", authority.Human, true, in)); !errors.Is(err, operation.ErrInvalid) {
				t.Errorf("%s: %v", name, err)
			}
		}
		if got := e.get(t); got.Version != 0 {
			t.Fatalf("invalid input wrote: %+v", got)
		}
	})
}

// The relay is stored defaulted and canonical, the diff names every changed attribute without a secret,
// and the same Action's inverse (the before-image) restores the previous settings.
func TestRelayUpdateAndInverse(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		first := notify.SettingsInput{AllowedDomains: []string{"b.example", "a.example", "a.example"},
			Relay: &notify.RelayInput{Host: "SMTP.ok.example", Security: "starttls", From: "NoReply@ok.example"}}
		if _, err := e.runner.RunStore(ctx, e.req("olga", authority.Human, true, first)); err != nil {
			t.Fatal(err)
		}
		got := e.get(t)
		if !slices.Equal(got.AllowedDomains, []string{"a.example", "b.example"}) || got.Relay == nil ||
			got.Relay.Host != "smtp.ok.example" || got.Relay.Port != 587 || got.Relay.Security != settings.StartTLS {
			t.Fatalf("stored %+v relay %+v", got, got.Relay)
		}
		attrs := map[string]bool{}
		for _, c := range e.rec.last().Changes {
			attrs[c.Attribute] = true
		}
		for _, want := range []string{"allowed_domains", "smtp_host", "smtp_port", "smtp_security", "smtp_from"} {
			if !attrs[want] {
				t.Errorf("no change for %s: %+v", want, e.rec.last().Changes)
			}
		}

		// Second update clears the relay and narrows the list; then the inverse of the first change
		// is what the before-image says: the settings of the second call.
		second := notify.SettingsInput{AllowedDomains: []string{"a.example"}}
		if _, err := e.runner.RunStore(ctx, e.req("olga", authority.Human, true, second)); err != nil {
			t.Fatal(err)
		}
		got = e.get(t)
		if got.Version != 2 || got.Relay != nil || !slices.Equal(got.AllowedDomains, []string{"a.example"}) {
			t.Fatalf("after second %+v", got)
		}
		// Restoring the first settings (what Inverse of the second step returns) round-trips.
		if _, err := e.runner.RunStore(ctx, e.req("olga", authority.Human, true, first)); err != nil {
			t.Fatal(err)
		}
		got = e.get(t)
		if got.Version != 3 || got.Relay == nil || got.Relay.Host != "smtp.ok.example" || len(got.AllowedDomains) != 2 {
			t.Fatalf("after restore %+v", got)
		}
	})
}

// Inverse returns the before-image, so undoing a change restores the previous list and relay.
func TestUpdateInverseIsBeforeImage(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		first := notify.SettingsInput{AllowedDomains: []string{"a.example"},
			Relay: &notify.RelayInput{Host: "smtp.ok.example", Port: 587, Security: "starttls", From: "noreply@ok.example"}}
		if _, err := e.runner.RunStore(ctx, e.req("olga", authority.Human, true, first)); err != nil {
			t.Fatal(err)
		}
		act, err := notify.UpdateSettings()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(notify.SettingsInput{AllowedDomains: []string{"a.example", "b.example"}})
		var plan []operation.StepPlan
		if err := e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) (err error) {
			plan, err = act.Plan(ctx, operation.PlanContext{Tx: tx}, raw)
			return
		}); err != nil || len(plan) != 1 {
			t.Fatalf("plan %v %v", plan, err)
		}
		inv, err := act.Inverse(plan[0], operation.Outcome{Payload: []byte(`{"version":2}`)})
		if err != nil {
			t.Fatal(err)
		}
		var back notify.SettingsInput
		if err := json.Unmarshal(inv, &back); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(back.AllowedDomains, first.AllowedDomains) || back.Relay == nil || *back.Relay != *first.Relay {
			t.Fatalf("inverse %+v", back)
		}
		if plan[0].Reversibility != operation.Reversible {
			t.Fatalf("plan reversibility %v", plan[0].Reversibility)
		}
	})
}

// The version rises by one per write.
func TestVersionAdvancesPerWrite(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		for i, d := range []string{"a.example", "b.example"} {
			if _, err := e.runner.RunStore(context.Background(), e.req("olga", authority.Human, true, notify.SettingsInput{AllowedDomains: []string{d}})); err != nil {
				t.Fatal(err)
			}
			if got := e.get(t); got.Version != i+1 {
				t.Fatalf("version %d after write %d", got.Version, i+1)
			}
		}
	})
}
