//go:build lab

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	"github.com/skenzeriq/activediq/internal/testlab"
)

// T-0421 on Samba: `make lab-up && go test -tags lab ./internal/compose/server -run TestLabRule5`.
// TM-D19 rule 5 end to end: a real Postgres, the real operation runner, the real rbac authorizer with
// the backing-object guard and root resolver, the real client.ConnectorReads / ConnectorFacts, and a
// real read handler over a real LDAPS session to the lab DC. Only the gRPC hop is in-process.
// Samba proves the LDAP reads and the DSA pin; a second DC (two replicas of one NC) is a Windows-lab case.

const labDom = "DC=lab,DC=activediq,DC=test"

// readRec is one read the facts reader made: which object, whether it carried a DSA pin, and the
// DC (DSA GUID) whose header answered.
type readRec struct {
	Object   string
	Pinned   bool
	PinDSA   string
	ServedBy string
}

// recTransport is an in-process client.ReadTransport over the connector's read.Handler. It records
// every read. It adds exactly one thing to the request: the connector's DirectoryIdentity, which
// client.ConnectorReads does not send and the handler requires (BUG T-0465; delete the injection when
// that is fixed, and the test must still pass).
type recTransport struct {
	h     *read.Handler
	ident *connectorv1.DirectoryIdentity
	mu    sync.Mutex
	rs    []readRec
}

type replay struct {
	ms []*connectorv1.ReadResponse
}

func (r *replay) Recv() (*connectorv1.ReadResponse, error) {
	if len(r.ms) == 0 {
		return nil, ioEOF
	}
	m := r.ms[0]
	r.ms = r.ms[1:]
	return m, nil
}

type collect struct{ ms []*connectorv1.ReadResponse }

func (c *collect) Send(m *connectorv1.ReadResponse) error { c.ms = append(c.ms, m); return nil }

func (t *recTransport) Read(ctx context.Context, req *connectorv1.ReadRequest) (client.ReadStream, error) {
	c := &collect{}
	if req.Connection.DirectoryIdentity == nil {
		req.Connection.DirectoryIdentity = t.ident
	}
	rec := readRec{Object: uuidText(req.GetGuid().GetValue())}
	if p := req.GetDc().GetPinnedDsaGuid().GetValue(); len(p) != 0 {
		rec.Pinned, rec.PinDSA = true, uuidText(p)
	}
	err := t.h.Read(ctx, req, c)
	for _, m := range c.ms {
		if h := m.GetHeader(); h != nil {
			rec.ServedBy = uuidText(h.GetObserved().GetDc().GetDsaGuid().GetValue())
		}
	}
	t.mu.Lock()
	t.rs = append(t.rs, rec)
	t.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &replay{ms: c.ms}, nil
}

func (t *recTransport) take() []readRec {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.rs
	t.rs = nil
	return out
}

func uuidText(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// labPinner pins the lab DC (the one the session is bound to) for every naming context.
type labPinner struct{ dsa string }

func (p labPinner) Pin(context.Context, string, authority.NamingContextID, string) (operation.DCPin, error) {
	return operation.DCPin{Host: "localhost", DSAGUID: p.dsa}, nil
}

type labSettings struct{}

func (labSettings) ApprovalForIrreversible(context.Context) (bool, error) { return false, nil }

type resetIn struct{ GUID string }
type resetPayload struct{}
type resetOut struct{}

// resetAction is a stand-in for the objects.user.reset_password Action, which has no product
// implementation yet: the permission, the AD target and the planned NC are what rule 5 sees. It never
// writes (the lab user is not modified); the test is about the decision, not the write.
func resetAction(t *testing.T, conn, nc string) operation.Action {
	t.Helper()
	a, err := operation.Define(operation.Typed[resetIn, resetPayload, resetOut]{
		Descriptor: operation.Descriptor{ID: "objects.user.reset_password", Version: 1, Permission: "objects.user.reset_password",
			Input: "#/components/schemas/ResetPassword", Target: operation.TargetAD, Reversibility: operation.Irreversible, AuditKind: "directory.user.password_reset"},
		Plan: func(_ context.Context, _ operation.PlanContext, in resetIn) ([]operation.TypedStep[resetPayload], error) {
			return []operation.TypedStep[resetPayload]{{Plan: operation.StepPlan{
				Target: authority.TargetRef{Connection: conn, GUID: in.GUID, Class: "user", NC: authority.NamingContextID(nc)},
				Kind:   "ldap.modify", Reversibility: operation.Irreversible, Credential: true,
				Diff: []operation.Change{{Attribute: "unicodePwd", Secret: true}}}}}, nil
		},
		Apply: func(context.Context, step.Step, operation.TypedStep[resetPayload]) (resetOut, error) {
			return resetOut{}, nil
		},
		Verify: func(context.Context, step.Step, operation.TypedStep[resetPayload], resetOut) (operation.Verdict, error) {
			return operation.Verdict{OK: true}, nil
		},
		Inverse: func(operation.TypedStep[resetPayload], resetOut) (resetIn, error) {
			return resetIn{}, operation.ErrIrreversible
		},
		Observe: func(context.Context, authority.Pins, operation.TypedStep[resetPayload], time.Time) (operation.Observation, error) {
			return operation.ObservedBefore, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// labRig is one tenant's product wiring over the lab: the objects it made, the recording transport and
// the authorizer and runner built the way the composition root builds them.
type labRig struct {
	e                         *bkEnv
	ctx                       context.Context
	tr                        *recTransport
	rd                        client.Reads
	az                        operation.Authorizer
	runner                    *operation.Runner
	cp                        *audit.Checkpointer
	dsa, nc                   string
	broad, kid, plain, backer string
	helpdsk                   string
}

func newLabRig(t *testing.T, s *storetest.Server) *labRig {
	t.Helper()
	{
		le := testlab.Load(t)
		e := bkSetup(t, s)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t.Cleanup(cancel)

		// --- the lab: an admin connection for fixtures, a service session for the connector.
		admin, err := ldap.DialURL("ldaps://localhost:"+le.Port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: le.Pool, ServerName: "localhost"}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { admin.Close() })
		if err := admin.Bind("Administrator@lab.activediq.test", le.Values["LAB_ADMIN_PASSWORD"]); err != nil {
			t.Fatal(err)
		}
		sess, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + le.Port}, RootCAs: le.Pool, PageSize: 500,
			Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(le.Values["LAB_SVC_PASSWORD"]))}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sess.Close() })
		guidOf := func(dn string) string {
			r, err := admin.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
			if err != nil || len(r.Entries) != 1 {
				t.Fatalf("guid of %s: %v", dn, err)
			}
			g, err := guid.FromBytes(r.Entries[0].GetRawAttributeValue("objectGUID"))
			if err != nil {
				t.Fatal(err)
			}
			return uuidText(write.GUIDToWire(g).GetValue())
		}
		seq := time.Now().UnixNano() % 1_000_000
		mkOU := func(name, parent string) string {
			dn := "OU=" + name + "," + parent
			add := ldap.NewAddRequest(dn, nil)
			add.Attribute("objectClass", []string{"top", "organizationalUnit"})
			if err := admin.Add(add); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = admin.Del(ldap.NewDelRequest(dn, nil)) })
			return dn
		}
		mkUser := func(cn, parent string) string {
			dn := "CN=" + cn + "," + parent
			add := ldap.NewAddRequest(dn, nil)
			add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
			add.Attribute("sAMAccountName", []string{cn})
			if err := admin.Add(add); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = admin.Del(ldap.NewDelRequest(dn, nil)) })
			return dn
		}
		broadDN := mkOU(fmt.Sprintf("T0421b%d", seq), labDom)
		kidDN := mkOU("Kid", broadDN)
		plainDN := mkUser(fmt.Sprintf("t0421p%d", seq), kidDN)
		backerDN := mkUser(fmt.Sprintf("t0421k%d", seq), kidDN)
		deskDN := mkUser(fmt.Sprintf("t0421d%d", seq), "CN=Users,"+labDom)
		broad, kid, plain, backer, desk, nc := guidOf(broadDN), guidOf(kidDN), guidOf(plainDN), guidOf(backerDN), guidOf(deskDN), guidOf(labDom)

		// --- the connector: handler over the lab session; the identity the handler expects is the one
		// the connection record carries.
		ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
			ForestRootNcGuid: &connectorv1.Guid{Value: mustUUID(t, nc)}}}}
		prov := write.NewADProvider(sess, nil, ident, &labPins{})
		src, err := read.NewADSource(sess, prov)
		if err != nil {
			t.Fatal(err)
		}
		h, err := read.New(src)
		if err != nil {
			t.Fatal(err)
		}
		dc, err := prov.BoundDC(ctx)
		if err != nil {
			t.Fatal(err)
		}
		dsa := uuidText(dc.GetDsaGuid().GetValue())

		// --- the product: connection record, reads, facts, authorizer, runner.
		reg := connection.NewRegistry(e.db)
		if _, err := reg.Transition(ctx, e.ten, connection.ID(e.ad), connection.StateDraft, connection.StateVerifying); err != nil {
			t.Fatalf("connection transition: %v", err)
		}
		if _, err := reg.SetDirectoryIdentity(ctx, e.ten, connection.ID(e.ad), connectionIdentity(nc)); err != nil {
			t.Fatalf("connection identity: %v", err)
		}
		tr := &recTransport{h: h, ident: ident}
		reads, err := client.NewConnectorReads(reg, tr)
		if err != nil {
			t.Fatal(err)
		}
		facts := directoryFacts(reads)
		if err := e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error { return rbac.SeedBuiltIns(ctx, tx, e.ten) }); err != nil {
			t.Fatal(err)
		}
		az, err := rbacAuthorizer(e.db, facts)
		if err != nil {
			t.Fatal(err)
		}
		ch := audit.NewChainer(e.db)
		cp := audit.NewCheckpointer(ch, fixedKeys{}, noAnchor{})
		if err := e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error { return cp.InitTenant(ctx, tx, e.ten) }); err != nil {
			t.Fatal(err)
		}
		actions, err := operation.NewRegistry(resetAction(t, e.ad, nc))
		if err != nil {
			t.Fatal(err)
		}
		runner, err := operation.NewRunner(operation.Config{DB: e.db, Audit: ch, Authz: az, Registry: actions, Facts: facts, Jobs: jobs.NewRegistry(),
			Keys: fixedKeys{}, Pinner: labPinner{dsa: dsa}, Settings: labSettings{}, Component: "lab"})
		if err != nil {
			t.Fatal(err)
		}

		// --- accounts and grants: helpdesk (a directory account on `desk`) holds helpdesk-operator over
		// the Kid OU; an administrator account rests on `backer` and holds platform-administrator over
		// the broader OU that contains Kid.
		const (
			helpdsk = "c0000000-0000-4000-8000-0000000004a1"
			admAcct = "c0000000-0000-4000-8000-0000000004a2"
		)
		e.account(t, helpdsk, "directory", e.ad, desk, "", "active")
		e.account(t, admAcct, "directory", e.ad, backer, "", "active")
		assignRole(t, e, "helpdesk-operator", helpdsk, kid)
		assignRole(t, e, "platform-administrator", admAcct, broad)

		return &labRig{rd: reads, e: e, ctx: ctx, tr: tr, az: az, runner: runner, cp: cp, dsa: dsa, nc: nc, broad: broad, kid: kid, plain: plain, backer: backer, helpdsk: helpdsk}
	}
}

// pinnedCtx is the context the runner hands the facts port for one pinned decision.
func (r *labRig) pinnedCtx() context.Context {
	return authority.WithDSAPins(authority.WithTenant(r.ctx, r.e.ten.String()), authority.DSAPins{authority.NamingContextID(r.nc): r.dsa})
}

func (r *labRig) target(g string) authority.TargetRef {
	return authority.TargetRef{Connection: r.e.ad, GUID: g, Class: "user", NC: authority.NamingContextID(r.nc)}
}

func (r *labRig) human() authority.Chain {
	return authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(r.helpdsk), Kind: authority.Human}}
}

const resetPerm = "objects.user.reset_password"

// T-0421 acceptance 1 (decision half) and 3: the composed authorizer over LIVE lab facts. The target's
// facts are read pinned to the lab DC; the root resolver walks the scope roots' ancestry unpinned. The
// test records which DC served each read and pins the contract: the target read is served by the pinned
// DC, every read names the DC that served it, and the unpinned ancestry reads are visible (on a one-DC
// lab they necessarily agree with the pin; with two replicas nothing forces them to, which is the
// consistency residual of the T-0385 review and a Windows-lab case).
func TestLabRule5LiveFactsDecideBackingObject(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := newLabRig(t, s)
		pc := r.pinnedCtx()
		decide := func(g string) (error, []readRec) {
			r.tr.take()
			f, err := directoryFacts(r.rd).Facts(pc, authority.Pins{authority.NamingContextID(r.nc): "localhost"}, r.az.FactsQuery(r.human(), resetPerm, r.target(g)))
			if err != nil {
				t.Fatalf("live facts of %s: %v", g, err)
			}
			err = r.az.Authorize(pc, r.human(), resetPerm, r.target(g), f)
			return err, r.tr.take()
		}
		if err, _ := decide(r.plain); err != nil {
			t.Fatalf("reset of an ordinary user in scope: %v", err)
		}
		err, rs := decide(r.backer)
		if !errors.Is(err, rbac.ErrDenied) || !strings.Contains(err.Error(), string(rbac.ReasonBackingObject)) {
			t.Fatalf("reset of the backing object = %v, want a %s denial", err, rbac.ReasonBackingObject)
		}
		t.Logf("pinned DC (DSA): %s", r.dsa)
		var pinned, unpinned int
		for _, x := range rs {
			t.Logf("read of %s: pinned=%v pin=%s served-by=%s", x.Object, x.Pinned, x.PinDSA, x.ServedBy)
			if x.ServedBy == "" {
				t.Errorf("read of %s names no serving DC", x.Object)
			}
			if x.Pinned {
				pinned++
				if x.ServedBy != r.dsa || x.PinDSA != r.dsa {
					t.Errorf("pinned read of %s served by %s (pin %s), want the pinned DC %s", x.Object, x.ServedBy, x.PinDSA, r.dsa)
				}
			} else {
				unpinned++
				if x.ServedBy != r.dsa {
					t.Errorf("unpinned ancestry read of %s served by %s; the lab has one DC (%s)", x.Object, x.ServedBy, r.dsa)
				}
			}
		}
		if pinned == 0 || unpinned == 0 {
			t.Errorf("want both a pinned target read and unpinned ancestry reads for one decision, got %d pinned, %d unpinned: %+v", pinned, unpinned, rs)
		}
	})
}

// openBugs lists the product bugs this test is marked expected-to-fail for. While any is open the run
// must fail with its symptom; the moment it passes, the test fails and says to remove the marker.
var openBugs = []string{"T-0465 (ConnectorReads sends no DirectoryIdentity)"}

// T-0421 acceptance 1: through SubmitDirectory. EXPECTED TO FAIL until T-0465 and T-0466 land: today
// the ordinary in-scope reset is blocked facts_unavailable as well, because no live read reaches the
// connector. The transport here injects the identity (the T-0465 gap) so the T-0466 symptom is what
// shows; both are asserted so the marker cannot hide a different failure.
func TestLabRule5ResetOfBackingObjectIsRefusedThroughTheRunner(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := newLabRig(t, s)
		var fails []string
		failf := func(f string, a ...any) { fails = append(fails, fmt.Sprintf(f, a...)) }
		submit := func(target string) operation.Submission {
			sub, err := r.runner.SubmitDirectory(r.ctx, operation.Request{Tenant: r.e.ten, Action: "objects.user.reset_password",
				Input: operation.Input(fmt.Sprintf(`{"GUID":%q}`, target)), Actor: r.human()})
			if err != nil {
				failf("submit %s: %v", target, err)
			}
			return sub
		}
		ok := submit(r.plain)
		if ok.Blocked != 0 || ok.Planned != 1 {
			failf("ordinary user in scope: %+v (item reason %q); want one planned, none blocked", ok, itemReason(t, r.e, ok.Operation))
		}
		bad := submit(r.backer)
		if bad.Blocked != 1 || bad.Planned != 0 {
			failf("backing object: %+v; want blocked at plan", bad)
		} else if reason := itemReason(t, r.e, bad.Operation); reason != "denied" {
			failf("backing object blocked as %q, want denied", reason)
		}
		if got := auditOutcomes(t, r.e, r.cp, r.ctx, "lab"); !contains(got, "denied") {
			failf("audit outcomes %v: none is denied", got)
		}
		if len(fails) == 0 {
			t.Fatalf("passes: remove the expected-to-fail marker for %v", openBugs)
		}
		for _, f := range fails {
			t.Logf("EXPECTED FAILURE (%v): %s", openBugs, f)
		}
	})
}
