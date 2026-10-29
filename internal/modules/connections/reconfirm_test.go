package connections_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	dirinv "github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	rcAD      = "aaaaaaaa-0000-4000-8000-0000000000a1"
	rcEntra   = "eeeeeeee-0000-4000-8000-0000000000e1"
	rcAD2     = "aaaaaaaa-0000-4000-8000-0000000000a2"
	rcEntra2  = "eeeeeeee-0000-4000-8000-0000000000e2"
	ownerHex  = "0a0a0a0a-0000-4000-8000-000000000001"
	helperHex = "b0b00000-0000-4000-8000-000000000002"
)

// grantAll grants ReconfirmPermission to every listed principal; whether one is a tenant-owner is the
// Action's own check, so a principal granted the permission but not owning the tenant must be refused.
type grantAll map[authority.PrincipalID]bool

func (grantAll) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t}
}

func (g grantAll) Authorize(_ context.Context, c authority.Chain, p authz.Permission, _ authority.TargetRef, _ authority.Facts) error {
	if p == connections.ReconfirmPermission && g[c.Requester.ID] {
		return nil
	}
	return errors.New("not granted")
}

type owners []string

func (o owners) TenantOwners(context.Context, store.Tx, tenant.ID) ([]string, error) { return o, nil }

type rcEnv struct {
	db     *store.DB
	tid    tenant.ID
	ad, en connection.Connection
	runner *operation.Runner
	rec    *recorder
	reader *dirinv.Reader
	n      int
}

func newRCEnv(t *testing.T, s *storetest.Server) *rcEnv {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	reg := connection.NewRegistry(db)
	ctx := context.Background()
	ad, err := reg.Create(ctx, tid, connection.New{Kind: connection.KindADForest, DisplayName: "corp", CredentialID: cred, Transport: connection.TransportLDAPS})
	if err != nil {
		t.Fatal(err)
	}
	en, err := reg.Create(ctx, tid, connection.New{Kind: connection.KindEntraTenant, DisplayName: "tenant", CredentialID: cred})
	if err != nil {
		t.Fatal(err)
	}
	act, err := connections.ReconfirmCorrelation(owners{ownerHex})
	if err != nil {
		t.Fatal(err)
	}
	r, err := operation.NewRegistry(act)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	runner, err := operation.NewRunner(operation.Config{DB: db, Audit: rec, Registry: r, Now: time.Now,
		Authz: grantAll{ownerHex: true, helperHex: true}})
	if err != nil {
		t.Fatal(err)
	}
	return &rcEnv{db: db, tid: tid, ad: ad, en: en, runner: runner, rec: rec, reader: dirinv.NewReader(db, dirinv.NewGroups(db))}
}

var (
	rcT0  = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	rcYes = true
	rcNo  = false
	rcSID = []byte{1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 7, 0, 0, 0}
)

// formation is a pair that passes (a)–(e) in a tenant whose first attestation was at rcT0; the caller
// chooses the takeover state.
func (e *rcEnv) formation(ad, en string, st dirinv.TakeoverProtection, now time.Time) dirinv.Formation {
	return dirinv.Formation{
		AD:    dirinv.Ref{Connection: dirinv.ConnectionID(e.ad.ID), Object: dirinv.GUID(ad)},
		Entra: dirinv.Ref{Connection: dirinv.ConnectionID(e.en.ID), Object: dirinv.GUID(en)},
		Match: dirinv.MatchAnchor, AnchorAttr: "ms-DS-ConsistencyGuid", AnchorValue: []byte("0123456789abcdef"),
		Gate: dirinv.GateInput{EntraSyncEnabled: &rcYes, EntraCloudManaged: &rcNo, EntraSID: rcSID, ADSID: rcSID,
			EntraDomainName: "corp.example.com", ADDomainName: "corp.example.com", LinkConfirmed: true, AnchorMatches: 1,
			Takeover: st, FirstAttestedAt: rcT0},
		Now: now, FactsAsOf: now,
	}
}

func (e *rcEnv) form(t *testing.T, f dirinv.Formation) dirinv.Formed {
	t.Helper()
	var out dirinv.Formed
	var w dirinv.Writer
	err := e.db.WithTenant(context.Background(), e.tid, func(ctx context.Context, tx store.Tx) (err error) { out, err = w.Form(ctx, tx, f); return })
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *rcEnv) link(t *testing.T, ad string) dirinv.Link {
	t.Helper()
	c, err := e.reader.CorrelationsFor(context.Background(), e.tid, dirinv.Ref{Connection: dirinv.ConnectionID(e.ad.ID), Object: dirinv.GUID(ad)})
	if err != nil || len(c.Links) != 1 {
		t.Fatalf("read: %v %v", c, err)
	}
	return c.Links[0]
}

func (e *rcEnv) run(id, actor string, kind authority.PrincipalKind, stepUp bool) (operation.Result, error) {
	e.n++
	in, _ := json.Marshal(connections.ReconfirmInput{CorrelationID: id})
	return e.runner.RunStore(context.Background(), operation.Request{Tenant: e.tid, Action: connections.ReconfirmActionID, Input: in, FreshStepUp: stepUp,
		Actor:     authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(actor), Kind: kind}},
		Operation: step.OperationID("op-rc-" + string(rune('a'+e.n)))})
}

// held makes a correlation barred by rule 4 (g): eligible while the attestation had lapsed.
func (e *rcEnv) held(t *testing.T, ad, en string) dirinv.Link {
	t.Helper()
	f := e.formation(ad, en, dirinv.TakeoverStale, rcT0.Add(time.Hour))
	if g := e.form(t, f); g.Verdict.State != dirinv.StateCandidate || g.Verdict.EligibilityClass != dirinv.ClassLapsed {
		t.Fatalf("lapsed formation: %+v", g)
	}
	f.Gate.Takeover, f.Now, f.FactsAsOf = dirinv.TakeoverAttested, rcT0.Add(2*time.Hour), rcT0.Add(2*time.Hour)
	if g := e.form(t, f); g.Verdict.State != dirinv.StateCandidate || g.Verdict.Reason != dirinv.ReasonReconfirmRequired {
		t.Fatalf("re-attested: %+v", g)
	}
	return e.link(t, ad)
}

// Acceptance 1: a tenant-owner with fresh step-up turns the held correlation into matched, audited with
// the actor, the correlation and the time; the next sync cycle keeps it matched.
func Test_reconfirm_by_owner_with_stepup(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newRCEnv(t, s)
		l := e.held(t, rcAD, rcEntra)
		before := time.Now().Add(-time.Second)
		if _, err := e.run(l.ID, ownerHex, authority.Human, true); err != nil {
			t.Fatal(err)
		}
		got := e.link(t, rcAD)
		if got.State != dirinv.StateMatched || got.Reason != "" || got.ReconfirmedBy != ownerHex || got.ReconfirmedAt.Before(before) {
			t.Fatalf("after: %+v", got)
		}
		ev := e.rec.last()
		if ev.Kind != connections.AuditCorrelationReconfirmed || ev.Outcome != audit.Success || ev.Actor.Requester.ID != ownerHex ||
			ev.Target.GUID != l.ID || ev.Target.Class != connections.TargetClassCorrelation || ev.At.Before(before) {
			t.Fatalf("audit: %+v", ev)
		}
		// The next sync cycle keeps it matched: the confirmation outlives the gate's re-evaluation.
		f := e.formation(rcAD, rcEntra, dirinv.TakeoverAttested, time.Now())
		if g := e.form(t, f); g.Verdict.State != dirinv.StateMatched {
			t.Fatalf("next cycle: %+v", g)
		}
		// A cloud observation newer than the confirmation puts it back to candidate (I4(g)).
		f.Gate.CloudSeenAt, f.Now = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
		if g := e.form(t, f); g.Verdict.State != dirinv.StateCandidate || g.Verdict.Reason != dirinv.ReasonReconfirmRequired {
			t.Fatalf("after cloud observation: %+v", g)
		}
		// Re-confirming what is not waiting is refused at Plan; so is an unknown correlation.
		if _, err := e.run(l.ID+"0", ownerHex, authority.Human, true); err == nil {
			t.Error("malformed id accepted")
		}
	})
}

// Acceptance 2: a non-owner (even one granted the permission), an owner without fresh step-up and an
// automation are refused, audited, and change nothing.
func Test_reconfirm_refused(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newRCEnv(t, s)
		l := e.held(t, rcAD, rcEntra)
		cases := []struct {
			name, actor string
			kind        authority.PrincipalKind
			stepUp      bool
		}{
			{"owner without step-up", ownerHex, authority.Human, false},
			{"non-owner with permission and step-up", helperHex, authority.Human, true},
			{"stranger", "c0c00000-0000-4000-8000-000000000003", authority.Human, true},
			{"automation as owner", ownerHex, authority.Automation, true},
		}
		for _, c := range cases {
			cnt := len(e.rec.all())
			if _, err := e.run(l.ID, c.actor, c.kind, c.stepUp); !errors.Is(err, operation.ErrDenied) {
				t.Errorf("%s: %v", c.name, err)
			}
			evs := e.rec.all()
			if len(evs) != cnt+1 || evs[len(evs)-1].Kind != connections.AuditCorrelationReconfirmed || evs[len(evs)-1].Outcome == audit.Success {
				t.Errorf("%s: not audited as refused: %+v", c.name, evs[cnt:])
			}
			if got := e.link(t, rcAD); got.State != dirinv.StateCandidate || got.ReconfirmedBy != "" {
				t.Fatalf("%s changed the correlation: %+v", c.name, got)
			}
		}
		// A correlation that fails another check is not re-confirmable by anyone.
		f := e.formation(rcAD2, rcEntra2, dirinv.TakeoverAttested, rcT0.Add(time.Hour))
		f.Gate.LinkConfirmed = false
		e.form(t, f)
		other := e.link(t, rcAD2)
		if _, err := e.run(other.ID, ownerHex, authority.Human, true); err == nil {
			t.Error("a candidate failing link_unconfirmed was re-confirmed")
		}
		if got := e.link(t, rcAD2); got.State != dirinv.StateCandidate {
			t.Fatalf("overridden: %+v", got)
		}
	})
}

// Acceptance 3: a correlation first eligible while the attestation had lapsed stays candidate until
// re-confirmed; an install-time correlation, never seen cloud-only, is matched on the first attestation
// with no re-confirmation, and the Operation refuses it (nothing to confirm).
func Test_reconfirm_vs_install_population(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newRCEnv(t, s)
		// Install-time: eligible before the tenant's first attestation (open, no first_attested_at).
		f := e.formation(rcAD2, rcEntra2, dirinv.TakeoverOpen, rcT0.Add(-time.Hour))
		f.Gate.FirstAttestedAt = time.Time{}
		if g := e.form(t, f); g.Verdict.State != dirinv.StateCandidate || g.Verdict.EligibilityClass != dirinv.ClassInstallTime {
			t.Fatalf("install-time: %+v", g)
		}
		f.Gate.Takeover, f.Gate.FirstAttestedAt, f.Now, f.FactsAsOf = dirinv.TakeoverAttested, rcT0, rcT0, rcT0
		if g := e.form(t, f); g.Verdict.State != dirinv.StateMatched {
			t.Fatalf("install-time population on first attestation: %+v", g)
		}
		inst := e.link(t, rcAD2)
		if _, err := e.run(inst.ID, ownerHex, authority.Human, true); err == nil {
			t.Error("a matched correlation was re-confirmed")
		}
		// Lapsed: eligible after the first attestation while stale; stays candidate until the owner confirms.
		l := e.held(t, rcAD, rcEntra)
		if l.State != dirinv.StateCandidate || l.EligibilityClass != dirinv.ClassLapsed {
			t.Fatalf("lapsed: %+v", l)
		}
		g := e.form(t, e.formation(rcAD, rcEntra, dirinv.TakeoverAttested, rcT0.Add(3*time.Hour)))
		if g.Verdict.State != dirinv.StateCandidate {
			t.Fatalf("a further attested cycle matched it without re-confirmation: %+v", g)
		}
		if _, err := e.run(l.ID, ownerHex, authority.Human, true); err != nil {
			t.Fatal(err)
		}
		if got := e.link(t, rcAD); got.State != dirinv.StateMatched {
			t.Fatalf("after re-confirmation: %+v", got)
		}
	})
}
