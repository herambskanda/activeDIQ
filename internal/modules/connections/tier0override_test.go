package connections_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory"
	dirclient "github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

const (
	cred       = "11111111-1111-4111-8111-111111111111"
	forestRoot = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	fingerp    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// holders is the platform-scope permission, as the authz kernel would resolve it.
type holders map[authority.PrincipalID]bool

func (h holders) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (h holders) Authorize(_ context.Context, c authority.Chain, p authz.Permission, _ authority.TargetRef, _ authority.Facts) error {
	if p == connections.Tier0OverridePermission && h[c.Requester.ID] {
		return nil
	}
	return errors.New("not granted")
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

func (r *recorder) all() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.evs...)
}

func (r *recorder) last() audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.evs[len(r.evs)-1]
}

type client struct{ res connection.VerifyResult }

func (c client) VerifyConnection(context.Context, connection.VerifyRequest) (connection.VerifyResult, error) {
	return c.res, nil
}

func human(id string) authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(id), Kind: authority.Human}}
}

type env struct {
	db     *store.DB
	reg    *connection.Registry
	tid    tenant.ID
	runner *operation.Runner
	rec    *recorder
	conn   connection.Connection
	ver    connection.Verification
}

// refusedDraft builds a draft connection whose activation was refused for over-privilege alone.
func refusedDraft(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	return refusedDraftWith(t, s, nil, nil)
}

// refusedDraftWith is refusedDraft with the runner's Authorizer and Facts port replaced by the real ones when
// non-nil; seed runs against the tenant before the runner is built.
func refusedDraftWith(t *testing.T, s *storetest.Server, mk func(*testing.T, *store.DB, tenant.ID) operation.Authorizer, facts operation.LiveFacts) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	reg, rec := connection.NewRegistry(db), &recorder{}
	ctx := context.Background()
	c, err := reg.Create(ctx, tid, connection.New{Kind: connection.KindADForest, DisplayName: "corp", CredentialID: cred, Transport: connection.TransportLDAPS})
	if err != nil {
		t.Fatal(err)
	}
	res := connection.VerifyResult{DirectoryIdentity: forestRoot, CheckListVersion: 1, Verdict: connection.VerdictRefused,
		Outcomes: map[connection.Check]connection.Outcome{"V5": connection.OutcomePass, "V7": connection.OutcomeFail, "V8": connection.OutcomePass},
		Findings: []connection.Finding{{Check: "V7", Code: "over.tier0_group", Kind: connection.FindingExcessiveRight, Severity: connection.SeverityBlock, Fingerprint: fingerp}}}
	svc, err := connection.NewService(reg, client{res}, rec)
	if err != nil {
		t.Fatal(err)
	}
	out, err := svc.Activate(ctx, tid, c.ID, human("alice"))
	if !errors.Is(err, connection.ErrActivationRefused) {
		t.Fatalf("setup activation: %v", err)
	}
	act, err := connections.Tier0OverrideAcknowledge()
	if err != nil {
		t.Fatal(err)
	}
	r, err := operation.NewRegistry(act)
	if err != nil {
		t.Fatal(err)
	}
	var az operation.Authorizer = holders{"owner": true, "tok": true, "sys": true}
	if mk != nil {
		az = mk(t, db, tid)
	}
	runner, err := operation.NewRunner(operation.Config{DB: db, Audit: rec, Authz: az, Facts: facts, Registry: r,
		Now: time.Now, NewID: nil})
	if err != nil {
		t.Fatal(err)
	}
	return &env{db: db, reg: reg, tid: tid, runner: runner, rec: rec, conn: c, ver: out.Verification}
}

func (e *env) request(actor string, stepUp bool, typed string) operation.Request {
	in, _ := json.Marshal(connections.Tier0OverrideInput{ConnectionID: string(e.conn.ID), VerificationID: string(e.ver.ID), Acknowledgment: typed})
	return operation.Request{Tenant: e.tid, Actor: human(actor), Action: connections.Tier0OverrideActionID, Input: in,
		Operation: step.OperationID("op-" + actor), FreshStepUp: stepUp}
}

func (e *env) assertNoOverride(t *testing.T) {
	t.Helper()
	h, err := e.reg.Health(context.Background(), e.tid, e.conn.ID, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if h.Tier0Installation || h.State != connection.StateDraft {
		t.Fatalf("a denied override must change nothing: %+v", h)
	}
}

// Acceptance 3: without step-up, without the platform-scope permission, or without the typed text,
// the override is denied and nothing changes. A denial is audited.
func TestOverrideDenied(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := refusedDraft(t, s)
		ctx := context.Background()
		cases := []struct {
			name string
			req  operation.Request
			want error
		}{
			{"no step-up", e.request("owner", false, connections.TypedAcknowledgement), operation.ErrDenied},
			{"no permission", e.request("bob", true, connections.TypedAcknowledgement), operation.ErrDenied},
		}
		for _, c := range cases {
			if _, err := e.runner.RunStore(ctx, c.req); !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", c.name, err, c.want)
			}
			if ev := e.rec.last(); ev.Outcome != audit.Denied || ev.Kind != connections.AuditTier0OverrideAcknowledged {
				t.Errorf("%s: last event %+v", c.name, ev)
			}
			e.assertNoOverride(t)
		}
		if _, err := e.runner.RunStore(ctx, e.request("owner", true, "yes")); err == nil {
			t.Error("a wrong typed acknowledgement was accepted")
		}
		e.assertNoOverride(t)
	})
}

// Acceptance 4: with step-up and the permission the override is recorded, audited, the connection
// activates, and health reports the permanent Tier-0 banner state.
func TestOverrideSucceeds(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := refusedDraft(t, s)
		ctx := context.Background()
		res, err := e.runner.RunStore(ctx, e.request("owner", true, connections.TypedAcknowledgement))
		if err != nil {
			t.Fatal(err)
		}
		var out connections.Tier0OverrideOutcome
		if err := json.Unmarshal(res.Steps[0].Outcome.Payload, &out); err != nil || !out.Activated || out.OverrideID == "" {
			t.Fatalf("outcome %+v %v", out, err)
		}
		ev := e.rec.last()
		if ev.Kind != connections.AuditTier0OverrideAcknowledged || ev.Outcome != audit.Success || ev.Actor.Requester.ID != "owner" ||
			ev.Target.Class != rbac.TargetClassTenant {
			t.Fatalf("audit event %+v", ev)
		}
		for _, ch := range ev.Changes {
			for _, v := range append(ch.Before, ch.After...) {
				if v == fingerp {
					t.Fatalf("the audit event carries a finding fingerprint (DM-24.I5)")
				}
			}
		}
		// DM-25.I7: the event commits to the acknowledged set by count and a salted digest of its own tag.
		got := map[string]string{}
		for _, ch := range ev.Changes {
			if len(ch.After) == 1 {
				got[ch.Attribute] = ch.After[0]
			}
		}
		if got["acknowledged_count"] != "1" {
			t.Fatalf("acknowledged_count = %q", got["acknowledged_count"])
		}
		if d := got["override_digest"]; len(d) != 64 || d == fmt.Sprintf("%x", e.ver.FindingsDigest) {
			t.Fatalf("override_digest %q must be a SHA-256 distinct from the findings digest", d)
		}
		h, err := e.reg.Health(ctx, e.tid, e.conn.ID, false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if h.State != connection.StateActive || !h.Tier0Installation || h.Status != connection.HealthTier0 ||
			h.Override == nil || h.Override.AcknowledgedBy != "owner" {
			t.Fatalf("health %+v", h)
		}
	})
}

func TestModuleRegistersTheAction(t *testing.T) {
	c, err := moduletest.Register(connections.New(platform.Deps{}, directory.Services{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Actions(); len(got) != 5 || got[0].Describe().ID != connections.Tier0OverrideActionID {
		t.Fatalf("actions %v", got)
	}
	d := c.Actions()[0].Describe()
	if !d.StepUp || d.Reversibility != operation.Irreversible || d.Target != operation.TargetStore {
		t.Fatalf("descriptor %+v", d)
	}
}

// A non-human requester holding the permission, even with FreshStepUp set, cannot record an
// override: it is the operator's acknowledgement (security review of TM-D1).
func TestOverrideRefusesNonHumanRequesters(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := refusedDraft(t, s)
		for name, kind := range map[string]authority.PrincipalKind{"tok": authority.APIToken, "sys": authority.System} {
			req := e.request(name, true, connections.TypedAcknowledgement)
			req.Actor = authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(name), Kind: kind}}
			if _, err := e.runner.RunStore(context.Background(), req); err == nil {
				t.Errorf("%s requester recorded an override", kind)
			}
			e.assertNoOverride(t)
		}
	})
}

// The override runs through the real rbac.Authorizer and the server's facts reader (ConnectorFacts, no
// directory reads wired): the connection target is answered without a directory read, the tenant owner is
// granted, and the acknowledgement commits an audit event whose connection target passes audit.Validate.
func TestOverrideThroughRealAuthorizer(t *testing.T) {
	const owner = "33333333-3333-4333-8333-333333333333"
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		mk := func(t *testing.T, db *store.DB, tid tenant.ID) operation.Authorizer {
			if err := db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
				if err := rbac.SeedBuiltIns(ctx, tx, tid); err != nil {
					return err
				}
				var aid string
				if err := tx.QueryRow(ctx, `INSERT INTO public.authz_assignments (tenant_id, account_id, role_id, valid_from, granted_by)
SELECT $1::uuid, $2::uuid, r.id, now() - interval '1 hour', 'seed' FROM public.authz_roles r WHERE r.tenant_id = $1::uuid AND r.role_name = $3 RETURNING id::text`,
					tid.String(), owner, rbac.TenantOwnerRole).Scan(&aid); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `INSERT INTO public.authz_assignment_roots (tenant_id, assignment_id, ordinal, is_exclude, root_kind, connection_id, root_guid)
VALUES ($1::uuid, $2::uuid, 0, false, 'tenant', $1::uuid, $1::uuid)`, tid.String(), aid)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			src, err := rbac.NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			az, err := rbac.New(src)
			if err != nil {
				t.Fatal(err)
			}
			return az
		}
		e := refusedDraftWith(t, s, mk, dirclient.NewConnectorFacts(nil))
		res, err := e.runner.RunStore(context.Background(), e.request(owner, true, connections.TypedAcknowledgement))
		if err != nil {
			t.Fatalf("override through the real authorizer: %v", err)
		}
		var out connections.Tier0OverrideOutcome
		if err := json.Unmarshal(res.Steps[0].Outcome.Payload, &out); err != nil || !out.Activated {
			t.Fatalf("outcome %+v %v", out, err)
		}
		ev := e.rec.last()
		if ev.Kind != connections.AuditTier0OverrideAcknowledged || ev.Outcome != audit.Success || ev.Target.Class != rbac.TargetClassTenant {
			t.Fatalf("audit event %+v", ev)
		}
		if err := ev.Validate(); err != nil {
			t.Fatalf("the committed override event must pass audit.Validate: %v", err)
		}
	})
}
