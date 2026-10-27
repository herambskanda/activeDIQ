package connections_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	entraTenantID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	otherTenantID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	gaOID         = "99999999-9999-4999-8999-999999999999"
	secretToken   = "eyJ0eXAi.SECRET-ACCESS-TOKEN-0123456789.sig"
)

// attestAuthz grants TakeoverAttestPermission to the named requesters over entra_tenant.
type attestAuthz map[authority.PrincipalID]bool

func (a attestAuthz) Authorize(_ context.Context, c authority.Chain, p authz.Permission, t authority.TargetRef) error {
	if p == connections.TakeoverAttestPermission && t.Class == "entra_tenant" && a[c.Requester.ID] {
		return nil
	}
	return errors.New("not granted")
}

type stepUp struct{ fresh bool }

func (s stepUp) Fresh(context.Context, tenant.ID, string) (bool, error) { return s.fresh, nil }

// fakeIdP plays the Microsoft token endpoint: it records what it was asked and hands out a grant.
type fakeIdP struct {
	mu       sync.Mutex
	reqs     []connections.ExchangeRequest
	tid, oid string
	scopes   []string
	token    []byte // the buffer the Bearer wraps, kept so the test can see it zeroed
	fail     bool
}

func (f *fakeIdP) Exchange(_ context.Context, r connections.ExchangeRequest) (connections.Grant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r)
	if f.fail {
		return connections.Grant{}, errors.New("idp said " + secretToken)
	}
	f.token = []byte(secretToken)
	return connections.Grant{TenantID: f.tid, ObjectID: f.oid, Scopes: f.scopes, Token: connections.NewBearer(f.token)}, nil
}

// fakeGraph plays GET /directory/onPremisesSynchronization. It checks the bearer is what the IdP
// issued, so a Graph read with a zeroed or missing token fails like the real one.
type fakeGraph struct {
	feat  connections.SyncFeatures
	calls int
	err   error
}

func (g *fakeGraph) ReadSyncFeatures(_ context.Context, t connections.Bearer) (connections.SyncFeatures, error) {
	g.calls++
	if g.err != nil {
		return connections.SyncFeatures{}, g.err
	}
	var ok bool
	_ = t.Use(func(b []byte) error { ok = string(b) == secretToken; return nil })
	if !ok {
		return connections.SyncFeatures{}, errors.New("401")
	}
	return g.feat, nil
}

type attestEnv struct {
	db    *store.DB
	d     *storetest.Database
	reg   *connection.Registry
	tid   tenant.ID
	conn  connection.Connection
	ad    connection.Connection
	rec   *recorder
	idp   *fakeIdP
	graph *fakeGraph
	at    *connections.Attester
	now   time.Time
	seq   int
}

func newAttestEnv(t *testing.T, s *storetest.Server) *attestEnv {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e := &attestEnv{db: db, d: d, reg: connection.NewRegistry(db), tid: tid, rec: &recorder{},
		idp:   &fakeIdP{tid: entraTenantID, oid: gaOID, scopes: []string{connections.AttestScope}},
		graph: &fakeGraph{feat: connections.SyncFeatures{BlockCloudObjectTakeoverThroughHardMatch: true, BlockSoftMatch: true}},
		now:   time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)}
	e.conn = e.activeEntra(t)
	e.at = e.attester(t, stepUp{fresh: true})
	return e
}

func (e *attestEnv) attester(t *testing.T, su stepUp) *connections.Attester {
	t.Helper()
	at, err := connections.NewAttester(connections.AttestConfig{
		DB: e.db, Audit: e.rec, Authz: attestAuthz{"admin": true}, StepUp: su, IdP: e.idp, Graph: e.graph,
		ClientID: "app-client", RedirectURI: "https://diq.example/attest/callback", Authority: "https://login.example",
		Component: "connections", NewID: func() string { e.seq++; return fmt.Sprintf("ev-%d", e.seq) },
		Now: func() time.Time { return e.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// activeEntra walks a tenant connection through the one legal door into active.
func (e *attestEnv) activeEntra(t *testing.T) connection.Connection {
	t.Helper()
	ctx := context.Background()
	c, err := e.reg.Create(ctx, e.tid, connection.New{Kind: connection.KindEntraTenant, DisplayName: "tenant", CredentialID: cred})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.Transition(ctx, e.tid, c.ID, connection.StateDraft, connection.StateVerifying); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.SetDirectoryIdentity(ctx, e.tid, c.ID, entraTenantID); err != nil {
		t.Fatal(err)
	}
	err = e.db.WithTenant(ctx, e.tid, func(ctx context.Context, tx store.Tx) error {
		if _, err := (connection.Store{}).RecordVerification(ctx, tx, connection.NewVerification{
			ID: "00000000-0000-4000-b000-000000000280", ConnectionID: c.ID, CredentialID: cred, Kind: connection.KindManual,
			RequestedBy: "principal-test", StartedAt: e.now, CheckListVersion: 1, Verdict: connection.VerdictPass,
			Outcomes: map[connection.Check]connection.Outcome{"EV2": connection.OutcomePass,
				connection.CheckEV3OverPrivilege: connection.OutcomePass, connection.CheckEV4Sufficiency: connection.OutcomePass},
		}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.connector_bindings (tenant_id, connection_id, target)
			VALUES (current_setting('app.tenant_id')::uuid, $1::uuid, 'embedded')`, string(c.ID)); err != nil {
			return err
		}
		c, err = connection.Store{}.Activate(ctx, tx, c.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *attestEnv) start(t *testing.T, requester string) (string, error) {
	t.Helper()
	return e.at.Start(context.Background(), connections.StartRequest{Tenant: e.tid, ConnectionID: e.conn.ID,
		Chain: human(requester), SessionID: "sess"})
}

func stateOf(t *testing.T, authURL string) (state string, q url.Values) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state"), u.Query()
}

func (e *attestEnv) callback(state string) (connections.Result, error) {
	return e.at.Callback(context.Background(), connections.CallbackRequest{Tenant: e.tid, State: state, Code: "auth-code"})
}

func (e *attestEnv) takeover(t *testing.T) connection.Takeover {
	t.Helper()
	tk, err := e.reg.GetTakeover(context.Background(), e.tid, e.conn.ID, e.now)
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func (e *attestEnv) attest(t *testing.T) connections.Result {
	t.Helper()
	u, err := e.start(t, "admin")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := stateOf(t, u)
	res, err := e.callback(st)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func lastOfKind(t *testing.T, r *recorder, kind string) audit.Event {
	t.Helper()
	evs := r.all()
	for i := len(evs) - 1; i >= 0; i-- {
		if string(evs[i].Kind) == kind {
			return evs[i]
		}
	}
	t.Fatalf("no %s event in %d events", kind, len(evs))
	return audit.Event{}
}

// Acceptance 1.
func TestAttestStartRequiresPermissionAndStepUp(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newAttestEnv(t, s)

		if _, err := e.start(t, "stranger"); !errors.Is(err, connections.ErrNotPermitted) {
			t.Fatalf("no permission: %v", err)
		}
		ev := lastOfKind(t, e.rec, connections.AuditAttestStarted)
		if ev.Outcome != audit.Denied || ev.Reason != connections.ReasonNotPermitted || ev.Actor.Requester.ID != "stranger" {
			t.Fatalf("refusal not audited with its reason: %+v", ev)
		}

		stale := e.attester(t, stepUp{fresh: false})
		_, err := stale.Start(context.Background(), connections.StartRequest{Tenant: e.tid, ConnectionID: e.conn.ID, Chain: human("admin"), SessionID: "sess"})
		if !errors.Is(err, connections.ErrStepUpRequired) {
			t.Fatalf("no step-up: %v", err)
		}
		ev = lastOfKind(t, e.rec, connections.AuditAttestStarted)
		if ev.Outcome != audit.Denied || ev.Reason != connections.ReasonStepUpRequired {
			t.Fatalf("step-up refusal not audited: %+v", ev)
		}

		// A token or automation actor never starts one: the flow ends in a person's sign-in.
		_, err = e.at.Start(context.Background(), connections.StartRequest{Tenant: e.tid, ConnectionID: e.conn.ID,
			Chain: authority.Chain{Requester: authority.Principal{ID: "admin", Kind: authority.Human}, Via: []authority.Principal{{ID: "tok", Kind: authority.APIToken}}}})
		if !errors.Is(err, connections.ErrNotPermitted) {
			t.Fatalf("delegated token start: %v", err)
		}

		// Nothing was stored for any refusal.
		var n int
		_ = e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.connection_attestation_attempts`).Scan(&n)
		})
		if n != 0 {
			t.Fatalf("%d attempts stored by refused starts", n)
		}

		// An AD connection has no entra_tenant to attest.
		ad, err := e.reg.Create(context.Background(), e.tid, connection.New{Kind: connection.KindADForest, DisplayName: "corp", CredentialID: cred, Transport: connection.TransportLDAPS})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.at.Start(context.Background(), connections.StartRequest{Tenant: e.tid, ConnectionID: ad.ID, Chain: human("admin"), SessionID: "sess"}); !errors.Is(err, connections.ErrNotAttestable) {
			t.Fatalf("AD connection: %v", err)
		}

		if _, err := e.start(t, "admin"); err != nil {
			t.Fatalf("permitted + fresh: %v", err)
		}
		if ev := lastOfKind(t, e.rec, connections.AuditAttestStarted); ev.Outcome != audit.Success {
			t.Fatalf("start not audited: %+v", ev)
		}
	})
}

// Acceptance 2.
func TestAttestScopeAndTid(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newAttestEnv(t, s)
		u, err := e.start(t, "admin")
		if err != nil {
			t.Fatal(err)
		}
		st, q := stateOf(t, u)
		if !strings.HasPrefix(u, "https://login.example/"+entraTenantID+"/oauth2/v2.0/authorize?") {
			t.Fatalf("authorize endpoint is not the connection's tenant: %s", u)
		}
		if q.Get("scope") != connections.AttestScope || connections.AttestScope != "OnPremDirectorySynchronization.Read.All" {
			t.Fatalf("scope %q", q.Get("scope"))
		}
		if strings.Contains(strings.ToLower(u), "offline_access") || strings.Contains(strings.ToLower(u), "openid") {
			t.Fatalf("extra scope requested: %s", u)
		}
		if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			t.Fatalf("not authorization code + PKCE S256: %v", q)
		}

		if _, err := e.callback(st); err != nil {
			t.Fatal(err)
		}
		r := e.idp.reqs[0]
		sum := sha256.Sum256([]byte(r.CodeVerifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") {
			t.Fatal("code_verifier does not match the code_challenge sent")
		}
		if len(r.Scopes) != 1 || r.Scopes[0] != connections.AttestScope || r.TenantID != entraTenantID {
			t.Fatalf("token request: %+v", r)
		}

		// A token from another tenant is rejected, nothing is read and nothing recorded.
		before := lastOfKind(t, e.rec, connections.AuditAttestRecorded)
		e.idp.tid = otherTenantID
		e.graph.calls = 0
		u, _ = e.start(t, "admin")
		st, _ = stateOf(t, u)
		if _, err := e.callback(st); !errors.Is(err, connections.ErrTenantMismatch) {
			t.Fatalf("foreign tid: %v", err)
		}
		if e.graph.calls != 0 {
			t.Fatal("Graph was called with a foreign-tenant token")
		}
		if ev := lastOfKind(t, e.rec, connections.AuditAttestFailed); ev.Reason != connections.ReasonTenantMismatch {
			t.Fatalf("mismatch not audited: %+v", ev)
		}
		if lastOfKind(t, e.rec, connections.AuditAttestRecorded).ID != before.ID {
			t.Fatal("a rejected token recorded an attestation")
		}

		// A grant that carries offline_access (or any extra scope) is refused.
		e.idp.tid = entraTenantID
		e.idp.scopes = []string{connections.AttestScope, "offline_access"}
		u, _ = e.start(t, "admin")
		st, _ = stateOf(t, u)
		if _, err := e.callback(st); !errors.Is(err, connections.ErrScopeMismatch) {
			t.Fatalf("offline_access grant: %v", err)
		}
		if e.graph.calls != 0 {
			t.Fatal("Graph was called with an over-scoped token")
		}
	})
}

// Acceptance 3.
func TestAttestNoTokenRetained(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newAttestEnv(t, s)
		e.graph.feat = connections.SyncFeatures{BlockCloudObjectTakeoverThroughHardMatch: true, BlockSoftMatch: false}
		res := e.attest(t)

		ev := lastOfKind(t, e.rec, connections.AuditAttestRecorded)
		want := map[string]string{"attester_object_id": gaOID, "block_cloud_object_takeover_through_hard_match": "true",
			"block_soft_match": "false", "takeover_protection": "open"}
		for _, d := range ev.Details {
			if want[d.Key] != d.Value {
				t.Errorf("detail %s = %q", d.Key, d.Value)
			}
			delete(want, d.Key)
		}
		if len(want) != 0 || ev.Actor.Requester.ID != "admin" || !ev.At.Equal(e.now) || ev.Outcome != audit.Success {
			t.Fatalf("attestation audit incomplete: missing %v, %+v", want, ev)
		}
		if res.State != connection.TakeoverOpen || res.AttesterOID != gaOID {
			t.Fatalf("result %+v", res)
		}

		// The bearer buffer was overwritten, not just dropped.
		for _, b := range e.idp.token {
			if b != 0 {
				t.Fatal("token bytes survive in memory after return")
			}
		}
		// It does not print, whatever verb is used.
		for _, s := range []string{fmt.Sprint(connections.NewBearer([]byte(secretToken))), fmt.Sprintf("%+v %#v %v", res, connections.NewBearer([]byte(secretToken)), e.idp.reqs)} {
			if strings.Contains(s, "SECRET-ACCESS") {
				t.Fatalf("token printed: %s", s)
			}
		}
		// Not in any audit record (envelope or detail), including failures.
		for _, a := range e.rec.all() {
			if strings.Contains(fmt.Sprintf("%+v", a), "SECRET-ACCESS") {
				t.Fatalf("token in audit event %s", a.Kind)
			}
		}
		// Not in any table: every row of every public table, as text, as the owner (RLS bypassed).
		e.scanTablesFor(t, "SECRET-ACCESS")

		// A failure path zeroes the token too, and the failure text carries nothing from the IdP.
		e.graph.err = errors.New("graph said " + secretToken)
		u, _ := e.start(t, "admin")
		st, _ := stateOf(t, u)
		_, err := e.callback(st)
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("graph failure: %v", err)
		}
		for _, b := range e.idp.token {
			if b != 0 {
				t.Fatal("token survives a failed read")
			}
		}
		e.scanTablesFor(t, "SECRET-ACCESS")

		// The attempt is single use.
		if _, err := e.callback(st); !errors.Is(err, connection.ErrAttemptInvalid) {
			t.Fatalf("replayed state: %v", err)
		}
		if _, err := e.callback("never-issued"); !errors.Is(err, connection.ErrAttemptInvalid) {
			t.Fatalf("unknown state: %v", err)
		}
	})
}

// scanTablesFor fails if text appears in any column of any public table. The owner role bypasses RLS.
func (e *attestEnv) scanTablesFor(t *testing.T, needle string) {
	t.Helper()
	ctx := context.Background()
	tables, err := e.d.OwnerStrings(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil || len(tables) < 10 {
		t.Fatalf("listing tables: %v (%d)", err, len(tables))
	}
	for _, tb := range tables {
		hits, err := e.d.OwnerStrings(ctx, fmt.Sprintf(`SELECT 'hit' FROM public.%q x WHERE x::text LIKE $1 LIMIT 1`, tb), "%"+needle+"%")
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 0 {
			t.Fatalf("token found in table %s", tb)
		}
	}
}

// Acceptance 4.
func TestTakeoverStateMachine(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	at := func(hard, soft bool) *connection.Attestation {
		return &connection.Attestation{By: gaOID, At: t0, BlockHardMatch: hard, BlockSoftMatch: soft}
	}
	demoted := func(d time.Time) *time.Time { return &d }
	cases := []struct {
		name string
		rec  connection.TakeoverRecord
		now  time.Time
		want connection.TakeoverProtection
	}{
		{"never attested", connection.TakeoverRecord{MaxAge: 90 * day}, t0, connection.TakeoverUnattested},
		{"both true, fresh", connection.TakeoverRecord{Attestation: at(true, true), MaxAge: 90 * day}, t0.Add(89 * day), connection.TakeoverAttested},
		{"both true, exactly at the age", connection.TakeoverRecord{Attestation: at(true, true), MaxAge: 90 * day}, t0.Add(90 * day), connection.TakeoverStale},
		{"both true, aged out", connection.TakeoverRecord{Attestation: at(true, true), MaxAge: 90 * day}, t0.Add(91 * day), connection.TakeoverStale},
		{"shortened age", connection.TakeoverRecord{Attestation: at(true, true), MaxAge: 30 * day}, t0.Add(31 * day), connection.TakeoverStale},
		{"hard match off", connection.TakeoverRecord{Attestation: at(false, true), MaxAge: 90 * day}, t0, connection.TakeoverOpen},
		{"soft match off", connection.TakeoverRecord{Attestation: at(true, false), MaxAge: 90 * day}, t0, connection.TakeoverOpen},
		{"open stays open when aged", connection.TakeoverRecord{Attestation: at(false, false), MaxAge: 90 * day}, t0.Add(200 * day), connection.TakeoverOpen},
		{"demotion after attestation", connection.TakeoverRecord{Attestation: at(true, true), MaxAge: 90 * day, DemotedAt: demoted(t0.Add(day))}, t0.Add(2 * day), connection.TakeoverStale},
		{"demotion before attestation is superseded", connection.TakeoverRecord{Attestation: at(true, true), MaxAge: 90 * day, DemotedAt: demoted(t0.Add(-day))}, t0, connection.TakeoverAttested},
		{"max age over the cap fails closed", connection.TakeoverRecord{Attestation: at(true, true), MaxAge: 120 * day}, t0, connection.TakeoverStale},
		{"zero max age fails closed", connection.TakeoverRecord{Attestation: at(true, true)}, t0, connection.TakeoverStale},
		{"attestation from the future fails closed", connection.TakeoverRecord{Attestation: at(true, true), MaxAge: 90 * day}, t0.Add(-time.Hour), connection.TakeoverStale},
	}
	for _, c := range cases {
		if got := connection.EvaluateTakeover(c.rec, c.now); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}

	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newAttestEnv(t, s)
		ctx := context.Background()
		if tk := e.takeover(t); tk.State != connection.TakeoverUnattested || tk.Record.MaxAge != 90*day {
			t.Fatalf("new connection: %+v", tk)
		}
		// Every non-attested state makes a correlation that passes (a)-(e) a candidate, tenant_takeover_open.
		gate := func(st connection.TakeoverProtection, first *time.Time) inventory.Verdict {
			yes := true
			sid := []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1}
			in := inventory.GateInput{EntraSyncEnabled: &yes, EntraSID: sid, ADSID: sid, LinkConfirmed: true, AnchorMatches: 1,
				Takeover: inventory.TakeoverProtection(st)}
			if first != nil {
				in.FirstAttestedAt = *first
			}
			return inventory.Evaluate(in, e.now)
		}
		expectOpen := func(label string) {
			t.Helper()
			tk := e.takeover(t)
			if tk.State == connection.TakeoverAttested {
				t.Fatalf("%s: state attested", label)
			}
			if v := gate(tk.State, tk.Record.FirstAttestedAt); v.State != inventory.StateCandidate || v.Reason != inventory.ReasonTenantTakeoverOpen {
				t.Fatalf("%s: correlation %s/%s in state %s", label, v.State, v.Reason, tk.State)
			}
		}
		expectOpen("unattested")

		e.graph.feat = connections.SyncFeatures{BlockCloudObjectTakeoverThroughHardMatch: false, BlockSoftMatch: true}
		e.attest(t)
		expectOpen("a flag off")
		if tk := e.takeover(t); tk.State != connection.TakeoverOpen || tk.Record.FirstAttestedAt != nil {
			t.Fatalf("open attestation: %+v", tk)
		}

		e.graph.feat = connections.SyncFeatures{BlockCloudObjectTakeoverThroughHardMatch: true, BlockSoftMatch: true}
		e.now = e.now.Add(time.Hour)
		e.attest(t)
		tk := e.takeover(t)
		if tk.State != connection.TakeoverAttested || tk.Record.FirstAttestedAt == nil || tk.Record.Attestation.By != gaOID {
			t.Fatalf("both true: %+v", tk)
		}
		if v := gate(tk.State, tk.Record.FirstAttestedAt); v.State != inventory.StateMatched {
			t.Fatalf("attested tenant: correlation %s/%s", v.State, v.Reason)
		}
		first := *tk.Record.FirstAttestedAt

		// Ageing out needs no job: the state is computed.
		e.now = e.now.Add(91 * day)
		expectOpen("aged out")
		if tk := e.takeover(t); tk.State != connection.TakeoverStale {
			t.Fatalf("aged: %s", tk.State)
		}

		// Re-attest, then a demotion signal.
		e.attest(t)
		if tk := e.takeover(t); tk.State != connection.TakeoverAttested {
			t.Fatalf("re-attested: %s", tk.State)
		}
		if err := e.reg.RecordDemotion(ctx, e.tid, e.conn.ID, e.now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		e.now = e.now.Add(time.Hour)
		expectOpen("demotion signal")
		e.attest(t)
		tk = e.takeover(t)
		if tk.State != connection.TakeoverAttested || tk.Record.DemotedAt != nil {
			t.Fatalf("a new attestation supersedes the demotion: %+v", tk)
		}
		if !tk.Record.FirstAttestedAt.Equal(first) {
			t.Fatal("first_attested_at moved")
		}
		// The database holds first_attested_at too (I7(f)).
		if _, err := e.rawExec(`UPDATE public.connections SET first_attested_at = now() WHERE id = $1::uuid`, string(e.conn.ID)); err == nil {
			t.Fatal("first_attested_at was rewritten")
		}
	})
}

func (e *attestEnv) rawExec(sql string, args ...any) (int64, error) {
	var n int64
	err := e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) error {
		tag, err := tx.Exec(ctx, sql, args...)
		if err == nil {
			n = tag.RowsAffected()
		}
		return err
	})
	return n, err
}

// Acceptance 5.
func TestAttestMaxAgeCap(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newAttestEnv(t, s)
		ctx := context.Background()
		day := 24 * time.Hour
		for _, d := range []time.Duration{90*day + time.Second, 91 * day, 365 * day, 0, -day, 90*day + time.Millisecond} {
			if err := e.at.SetMaxAge(ctx, e.tid, e.conn.ID, human("admin"), d); !errors.Is(err, connection.ErrAttestationMaxAge) {
				t.Errorf("%v: %v, want refused", d, err)
			}
		}
		if ev := lastOfKind(t, e.rec, connections.AuditMaxAgeSet); ev.Outcome != audit.Denied {
			t.Fatalf("refusal not audited: %+v", ev)
		}
		if tk := e.takeover(t); tk.Record.MaxAge != 90*day {
			t.Fatalf("a refused save changed the age: %v", tk.Record.MaxAge)
		}
		// The database refuses it too, whatever the Go says.
		if _, err := e.rawExec(`UPDATE public.connections SET attestation_max_age_seconds = $2 WHERE id = $1::uuid`, string(e.conn.ID), 91*86400); err == nil {
			t.Fatal("the database accepted 91 days")
		}
		if err := e.at.SetMaxAge(ctx, e.tid, e.conn.ID, human("stranger"), 30*day); !errors.Is(err, connections.ErrNotPermitted) {
			t.Fatalf("no permission: %v", err)
		}
		for _, d := range []time.Duration{30 * day, 90 * day} {
			if err := e.at.SetMaxAge(ctx, e.tid, e.conn.ID, human("admin"), d); err != nil {
				t.Fatalf("%v: %v", d, err)
			}
			if tk := e.takeover(t); tk.Record.MaxAge != d {
				t.Fatalf("saved %v, read %v", d, tk.Record.MaxAge)
			}
		}
	})
}
