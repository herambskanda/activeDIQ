//go:build lab

package write

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/graph"
	"github.com/skenzeriq/activediq/internal/connector/graph/graphtest"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// CC-WK-01..10, 28, 29 against Samba AD: `make lab-up && go test -tags lab ./internal/connector/write -run TestWK`.
// CC-WK-11 (Plan class with the Recycle Bin) and the Windows halves are the Windows-lab ticket.

type wkRig struct {
	t      *testing.T
	h      *Handler
	sess   *ad.Session
	admin  *ldap.Conn
	dc     *connectorv1.DcIdentity
	env    map[string]string
	pool   *x509.CertPool
	port   string
	ou     string // DN of this test's scratch OU
	ouID   guid.GUID
	now    time.Time
	svcSID string
	schema *ldapfilter.Schema
	guard  PropertyGuard
}

func newWKRig(t *testing.T) *wkRig { return newWKRigRule(t, false) }

// newWKRigRule: withRule designates a dynamic group with a rule on `title` (CC-WRITE-25/27).
func newWKRigRule(t *testing.T, withRule bool) *wkRig {
	t.Helper()
	env := labEnv(t)
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	port := env["LAB_LDAPS_PORT"]
	if port == "" {
		port = "636"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	schema := ad.DefaultSchema().With(
		ldapfilter.AttrInfo{Name: "manager", Syntax: ldapfilter.SynDN},
		ldapfilter.AttrInfo{Name: "directReports", Syntax: ldapfilter.SynDN, Constructed: true},
		ldapfilter.AttrInfo{Name: "title", Syntax: ldapfilter.SynString},
		ldapfilter.AttrInfo{Name: "telephoneNumber", Syntax: ldapfilter.SynString},
		ldapfilter.AttrInfo{Name: "otherTelephone", Syntax: ldapfilter.SynString},
		ldapfilter.AttrInfo{Name: "mail", Syntax: ldapfilter.SynString},
	)
	sess, err := ad.Open(ctx, ad.Config{
		Servers: []string{"localhost:" + port}, RootCAs: pool, PageSize: 500, Schema: schema,
		Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	admin, err := ldap.DialURL("ldaps://localhost:"+port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "localhost"}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	if err := admin.Bind("Administrator@lab.activediq.test", env["LAB_ADMIN_PASSWORD"]); err != nil {
		t.Fatal(err)
	}

	// A dynamic group designated in the Entra snapshot with a rule on `title` (CC-WK-08, CC-WRITE-27).
	const gA, gD = "77777777-7777-7777-7777-000000000100", "77777777-7777-7777-7777-000000000150"
	groups := []graph.Group{{ID: gA}}
	members := map[string][]graph.DirectoryObject{}
	if withRule {
		groups = append(groups, graph.Group{ID: gD, GroupTypes: []string{"DynamicMembership"}, MembershipRule: `user.jobTitle -eq "X"`})
		members[gA] = []graph.DirectoryObject{{ID: gD, ODataType: "#microsoft.graph.group"}}
	}
	cred := graphtest.NewCredential(t)
	srv := graphtest.New(t, &graphtest.Tenant{
		TenantID: "11111111-1111-1111-1111-111111111111", ClientID: "22222222-2222-2222-2222-222222222222",
		SPID: "33333333-3333-3333-3333-333333333333", AppObjectID: "44444444-4444-4444-4444-444444444444",
		ServicePrincipals: map[string]graph.ServicePrincipal{"33333333-3333-3333-3333-333333333333": {ID: "33333333-3333-3333-3333-333333333333", AppID: "22222222-2222-2222-2222-222222222222"},
			"55555555-5555-5555-5555-555555555555": {ID: "55555555-5555-5555-5555-555555555555", AppID: "00000003-0000-0000-c000-000000000000"}},
		Groups: groups, Members: members,
	}, cred)
	gc, err := graph.New(srv.Config(cred))
	if err != nil {
		t.Fatal(err)
	}
	set, err := tier0.New(gc).Snapshot(ctx, tier0.Designation{ID: gA, Kind: tier0.KindGroup})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	run := passRun(nil)
	run.CompletedAt = now
	book, _ := NewGateBook(&memBaseline{}, time.Now)
	book.Complete(connID, run)
	prov := NewADProvider(sess, nil, adIdentity(), &memPins{})
	prov.Dynamic = set
	dc, err := prov.BoundDC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(prov, book, WithRecorder(&memRecorder{}))
	if err != nil {
		t.Fatal(err)
	}
	r := &wkRig{schema: schema, guard: set, t: t, h: h, sess: sess, admin: admin, dc: dc, env: env, pool: pool, port: port, now: now}
	r.ou = fmt.Sprintf("OU=wk%d,%s", time.Now().UnixNano()%1_000_000_000, labDom)
	r.adminAdd(r.ou, "organizationalUnit", nil)
	r.ouID = r.guidOf(r.ou)
	// The connector's account needs rights on the scratch OU (the lab DACL grants it none there).
	sid := strings.TrimSpace(r.lab("samba-tool", "user", "show", "svc-activediq", "--attributes=objectSid"))
	if i := strings.Index(sid, "S-1-5"); i >= 0 {
		sid = strings.Fields(sid[i:])[0]
	}
	r.svcSID = sid
	r.lab("samba-tool", "dsacl", "set", "--objectdn="+r.ou, "--sddl=(A;CIOI;GA;;;"+sid+")")
	t.Cleanup(func() { r.deleteTree(r.ou) })
	return r
}

// rebind replaces the connector's session and handler with one bound as another account.
func (r *wkRig) rebind(user, pw string) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	sess, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + r.port}, RootCAs: r.pool, PageSize: 500, Schema: r.schema,
		Credential: ad.Credential{BindName: user + "@lab.activediq.test", Password: secret.FromBytes([]byte(pw))}})
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { sess.Close() })
	run := passRun(nil)
	run.CompletedAt = time.Now()
	book, _ := NewGateBook(&memBaseline{}, time.Now)
	book.Complete(connID, run)
	prov := NewADProvider(sess, nil, adIdentity(), &memPins{})
	prov.Dynamic = r.guard
	r.sess = sess
	if r.h, err = New(prov, book, WithRecorder(&memRecorder{})); err != nil {
		r.t.Fatal(err)
	}
}

func (r *wkRig) lab(args ...string) string {
	r.t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", r.env["LAB_CONTAINER"]}, args...)...).CombinedOutput()
	if err != nil {
		r.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (r *wkRig) adminAdd(dnText, class string, attrs map[string][]string) {
	r.t.Helper()
	add := ldap.NewAddRequest(dnText, nil)
	add.Attribute("objectClass", classChain(class))
	for k, v := range attrs {
		add.Attribute(k, v)
	}
	if err := r.admin.Add(add); err != nil {
		r.t.Fatalf("admin add %s: %v", dnText, err)
	}
}

func classChain(class string) []string {
	switch class {
	case "user":
		return []string{"top", "person", "organizationalPerson", "user"}
	case "group", "computer", "organizationalUnit":
		return []string{"top", class}
	case "contact":
		return []string{"top", "person", "organizationalPerson", "contact"}
	}
	return []string{class}
}

func (r *wkRig) deleteTree(base string) {
	res, err := r.admin.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dn"}, nil))
	if err != nil {
		return
	}
	dns := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		dns = append(dns, e.DN)
	}
	for pass := 0; pass < 4; pass++ {
		for _, d := range dns {
			_ = r.admin.Del(ldap.NewDelRequest(d, nil))
		}
	}
}

func (r *wkRig) entry(dnText string, attrs ...string) *ldap.Entry {
	r.t.Helper()
	res, err := r.admin.Search(ldap.NewSearchRequest(dnText, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", attrs, nil))
	if err != nil || len(res.Entries) != 1 {
		r.t.Fatalf("read %s: %v", dnText, err)
	}
	return res.Entries[0]
}

func (r *wkRig) exists(dnText string) bool {
	_, err := r.admin.Search(ldap.NewSearchRequest(dnText, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dn"}, nil))
	return err == nil
}

func (r *wkRig) guidOf(dnText string) guid.GUID {
	r.t.Helper()
	ref, err := dn.ParseObjectRef(dnText)
	if err != nil {
		r.t.Fatal(err)
	}
	e, err := (tier0.SessionDirectory{S: r.sess}).Get(context.Background(), ref, []string{"objectGUID"})
	if err != nil {
		r.t.Fatal(err)
	}
	g, err := e.GUID()
	if err != nil {
		r.t.Fatal(err)
	}
	return g
}

func (r *wkRig) tier0Ctx(ids ...guid.GUID) *connectorv1.Tier0Context {
	c := &connectorv1.Tier0Context{Tier0Revision: 1}
	for _, id := range ids {
		c.Statements = append(c.Statements, noLink(id, r.now))
	}
	return c
}

var wkNC = mk(77)

func (r *wkRig) planReq(kind connectorv1.WriteKind, target guid.GUID, ch *connectorv1.WriteChange) *connectorv1.PlanRequest {
	return &connectorv1.PlanRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: connID, DirectoryIdentity: adIdentity()},
		Step:       &connectorv1.StepKey{OperationId: toWire(mk(50)), Item: 1, Step: 2},
		Target:     &connectorv1.WriteTarget{Object: toWire(target), NcGuid: toWire(wkNC)}, Tier0: r.tier0Ctx(target),
		Dc: &connectorv1.DcSelection{PinnedDsaGuid: r.dc.GetDsaGuid()}, ActingPrincipal: &connectorv1.ActingPrincipal{AccountId: toWire(mk(51))},
		Kind: kind, Change: ch}
}

// applyFrom builds the Apply of a Plan: precondition from the plan response, the digest the runner
// would have minted (the same op.Digest the handler checks).
func (r *wkRig) applyFrom(p *connectorv1.PlanRequest, pr *connectorv1.PlanResponse, secretIn []byte) *connectorv1.ApplyRequest {
	a := &connectorv1.ApplyRequest{Connection: p.Connection, Step: p.Step, Attempt: 1, Target: p.Target, Tier0: p.Tier0,
		Precondition: pr.GetPrecondition(), ActingPrincipal: p.ActingPrincipal, Kind: p.Kind, Change: p.Change}
	if a.Precondition == nil {
		a.Precondition = &connectorv1.TargetPrecondition{}
	}
	a.Precondition.Dc = r.dc
	d, err := operations[p.Kind].Digest(a)
	if err != nil {
		r.t.Fatal(err)
	}
	a.PlanDigest = d
	if secretIn != nil {
		a.SecretInput = &connectorv1.SecretValue{Material: secretIn}
	}
	return a
}

func (r *wkRig) plan(p *connectorv1.PlanRequest) (*connectorv1.PlanResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return r.h.Plan(ctx, p)
}

func (r *wkRig) apply(a *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return r.h.Apply(ctx, a)
}

func (r *wkRig) planApply(kind connectorv1.WriteKind, target guid.GUID, ch *connectorv1.WriteChange) (*connectorv1.ApplyResponse, error) {
	r.t.Helper()
	p := r.planReq(kind, target, ch)
	pr, err := r.plan(p)
	if err != nil {
		return nil, err
	}
	return r.apply(r.applyFrom(p, pr, nil))
}

func createChange(oc *connectorv1.ObjectCreate) *connectorv1.WriteChange {
	return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectCreate{ObjectCreate: oc}}
}
func updateChange(edits ...*connectorv1.AttributeEdit) *connectorv1.WriteChange {
	return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectUpdate{ObjectUpdate: &connectorv1.ObjectUpdate{Edits: edits}}}
}
func deleteChange() *connectorv1.WriteChange {
	return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectDelete{ObjectDelete: &connectorv1.ObjectDelete{}}}
}

func wantCode(t *testing.T, what string, err error, code connectorv1.ErrorCode) *connectorv1.ConnectorError {
	t.Helper()
	ce := connErr(t, err)
	if ce.GetCode() != code {
		t.Fatalf("%s: got %s (%v), want %s", what, ce.GetCode(), ce.GetRejectedInput(), code)
	}
	return ce
}

func wantRule(t *testing.T, what string, err error, rule string) {
	t.Helper()
	ce := wantCode(t, what, err, connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT)
	if got := ce.GetRejectedInput().GetRuleId(); got != rule {
		t.Fatalf("%s: rule %q, want %q", what, got, rule)
	}
}

func ed(op connectorv1.EditOp, attr string, vals ...string) *connectorv1.AttributeEdit {
	e := &connectorv1.AttributeEdit{Attribute: attr, Op: op}
	for _, v := range vals {
		e.Values = append(e.Values, txt(v))
	}
	return e
}

const (
	opSet    = connectorv1.EditOp_EDIT_OP_SET
	opClear  = connectorv1.EditOp_EDIT_OP_CLEAR
	opAdd    = connectorv1.EditOp_EDIT_OP_ADD_VALUE
	opRemove = connectorv1.EditOp_EDIT_OP_REMOVE_VALUE
)

// CC-WK-01 / 02: every class is created with the derived attributes; a retry is ALREADY_APPLIED;
// a different object at the name is NameInUse.
func TestWKCreateClassesAndRetry(t *testing.T) {
	r := newWKRig(t)
	sam := func(n string) *connectorv1.AttributeEdit { return ed(opSet, "sAMAccountName", n) }
	type tc struct {
		name, class string
		oc          *connectorv1.ObjectCreate
		check       func(*ldap.Entry)
	}
	cases := []tc{
		{"Jane, \"Q\" Doé", "user", &connectorv1.ObjectCreate{ObjectClass: ctUser, Initial: []*connectorv1.AttributeEdit{sam("wkjane"), ed(opSet, "description", "d1")}},
			func(e *ldap.Entry) {
				if e.GetAttributeValue("userAccountControl") != "514" || e.GetAttributeValue("description") != "d1" {
					t.Errorf("user: uac %s", e.GetAttributeValue("userAccountControl"))
				}
			}},
		{"g-global-sec", "group", &connectorv1.ObjectCreate{ObjectClass: ctGroup, GroupScope: connectorv1.GroupScope_GROUP_SCOPE_GLOBAL, GroupIsSecurity: true, Initial: []*connectorv1.AttributeEdit{sam("wkgg")}},
			func(e *ldap.Entry) {
				if e.GetAttributeValue("groupType") != "-2147483646" {
					t.Errorf("groupType %s", e.GetAttributeValue("groupType"))
				}
			}},
		{"g-universal-dist", "group", &connectorv1.ObjectCreate{ObjectClass: ctGroup, GroupScope: connectorv1.GroupScope_GROUP_SCOPE_UNIVERSAL, Initial: []*connectorv1.AttributeEdit{sam("wkgu")}},
			func(e *ldap.Entry) {
				if e.GetAttributeValue("groupType") != "8" {
					t.Errorf("groupType %s", e.GetAttributeValue("groupType"))
				}
			}},
		{"g-dl-sec", "group", &connectorv1.ObjectCreate{ObjectClass: ctGroup, GroupScope: connectorv1.GroupScope_GROUP_SCOPE_DOMAIN_LOCAL, GroupIsSecurity: true, Initial: []*connectorv1.AttributeEdit{sam("wkgdl")}},
			func(e *ldap.Entry) {
				if e.GetAttributeValue("groupType") != "-2147483644" {
					t.Errorf("groupType %s", e.GetAttributeValue("groupType"))
				}
			}},
		{"WKPC1", "computer", &connectorv1.ObjectCreate{ObjectClass: ctComputer, Initial: []*connectorv1.AttributeEdit{sam("WKPC1$")}},
			func(e *ldap.Entry) {
				if e.GetAttributeValue("userAccountControl") != "4098" {
					t.Errorf("computer uac %s", e.GetAttributeValue("userAccountControl"))
				}
			}},
		{"WKPC2", "computer", &connectorv1.ObjectCreate{ObjectClass: ctComputer, AccountEnabled: true, Initial: []*connectorv1.AttributeEdit{sam("WKPC2$")}},
			func(e *ldap.Entry) {
				if e.GetAttributeValue("userAccountControl") != "4096" {
					t.Errorf("computer uac %s", e.GetAttributeValue("userAccountControl"))
				}
			}},
		{"wk contact", "contact", &connectorv1.ObjectCreate{ObjectClass: ctContact}, func(*ldap.Entry) {}},
		{"wkou", "organizationalUnit", &connectorv1.ObjectCreate{ObjectClass: ctOU}, func(*ldap.Entry) {}},
	}
	for _, c := range cases {
		c.oc.RdnValue = c.name
		t.Run(c.name, func(t *testing.T) {
			ch := createChange(c.oc)
			p := r.planReq(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, r.ouID, ch)
			pr, err := r.plan(p)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			a := r.applyFrom(p, pr, nil)
			resp, err := r.apply(a)
			if err != nil {
				t.Fatalf("apply: %v", err)
			}
			if resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED || resp.GetReadBack().GetObjectGuid() == nil {
				t.Fatalf("outcome %v read_back %v", resp.GetOutcome(), resp.GetReadBack())
			}
			prefix := "CN="
			if c.class == "organizationalUnit" {
				prefix = "OU="
			}
			wantDN := prefix + ldap.EscapeDN(c.name) + "," + r.ou
			e := r.entry(wantDN, "objectClass", "groupType", "userAccountControl", "description", "sAMAccountName")
			if got := e.GetAttributeValues("objectClass"); got[len(got)-1] != ldapClass[c.oc.ObjectClass] {
				t.Errorf("objectClass %v", got)
			}
			c.check(e)
			// CC-WK-02: the same step retried after success.
			again, err := r.apply(a)
			if err != nil || again.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED || again.GetReadBack() == nil {
				t.Fatalf("retry: %v %v", again.GetOutcome(), err)
			}
			// A fresh Plan never adopts: the name is in use.
			_, err = r.plan(p)
			wantRule(t, "plan over an existing object", err, "NameInUse")
		})
	}
}

// CC-WK-02: a different object at the name; a pre-existing identical object created before plan_observed_at.
func TestWKCreateNameInUse(t *testing.T) {
	r := newWKRig(t)
	oc := &connectorv1.ObjectCreate{ObjectClass: ctGroup, RdnValue: "wk-clash", GroupScope: connectorv1.GroupScope_GROUP_SCOPE_GLOBAL, GroupIsSecurity: true,
		Initial: []*connectorv1.AttributeEdit{ed(opSet, "sAMAccountName", "wkclash")}}
	p := r.planReq(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, r.ouID, createChange(oc))
	pr, err := r.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	// An identical object appears between Plan and Apply, but created after plan_observed_at: the
	// connector did not write it, but it is the planned result: ALREADY_APPLIED. One created BEFORE
	// plan_observed_at would have shown in Plan. Here: a different object (a user) takes the name.
	r.adminAdd("CN=wk-clash,"+r.ou, "user", map[string][]string{"sAMAccountName": {"wkclashuser"}})
	_, err = r.apply(r.applyFrom(p, pr, nil))
	wantRule(t, "different object at the name", err, "NameInUse")
	// A pre-existing identical object created before plan_observed_at is not adopted.
	r.adminAdd("CN=wk-clash2,"+r.ou, "group", map[string][]string{"sAMAccountName": {"wkclash2"}, "groupType": {"-2147483646"}})
	oc2 := &connectorv1.ObjectCreate{ObjectClass: ctGroup, RdnValue: "wk-clash2", GroupScope: connectorv1.GroupScope_GROUP_SCOPE_GLOBAL, GroupIsSecurity: true,
		Initial: []*connectorv1.AttributeEdit{ed(opSet, "sAMAccountName", "wkclash2")}}
	p2 := r.planReq(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, r.ouID, createChange(oc2))
	a2 := r.applyFrom(p2, &connectorv1.PlanResponse{Precondition: &connectorv1.TargetPrecondition{PlanObservedAt: timestamppb.New(time.Now().Add(time.Minute))}}, nil)
	_, err = r.apply(a2)
	wantRule(t, "identical object older than plan_observed_at", err, "NameInUse")
}

// CC-WK-03: password handling and the channel check.
func TestWKCreateUserPassword(t *testing.T) {
	r := newWKRig(t)
	const canary = "Wk-Canary-9f3!Qz81"
	mk := func(name string, enabled, secretFlag bool) *connectorv1.WriteChange {
		return createChange(&connectorv1.ObjectCreate{ObjectClass: ctUser, RdnValue: name, AccountEnabled: enabled, HasSecretInput: secretFlag,
			Initial: []*connectorv1.AttributeEdit{ed(opSet, "sAMAccountName", name)}})
	}
	// enabled without a password: refused at Plan
	_, err := r.plan(r.planReq(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, r.ouID, mk("wkenabled0", true, false)))
	wantRule(t, "enabled without password", err, "EnabledNeedsPassword")
	// has_secret_input true with no value
	p := r.planReq(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, r.ouID, mk("wkmismatch", false, true))
	pr, err := r.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.apply(r.applyFrom(p, pr, nil))
	wantRule(t, "flag without value", err, "SecretInputMismatch")
	// secret supplied but flag false
	p = r.planReq(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, r.ouID, mk("wkmismatch2", false, false))
	pr, _ = r.plan(p)
	_, err = r.apply(r.applyFrom(p, pr, []byte(canary)))
	wantRule(t, "value without flag", err, "SecretInputMismatch")
	// disabled without a password: created disabled
	if _, err := r.planApply(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, r.ouID, mk("wkdisabled0", false, false)); err != nil {
		t.Fatal(err)
	}
	// enabled with a password: the user can bind
	p = r.planReq(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, r.ouID, mk("wkenabled1", true, true))
	pr, err = r.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	a := r.applyFrom(p, pr, []byte(canary))
	var logs strings.Builder
	rec := r.h.rec.(*memRecorder)
	resp, err := r.apply(a)
	if err != nil {
		t.Fatalf("enabled with password: %v", err)
	}
	for _, ev := range rec.ev {
		logs.WriteString(fmt.Sprintf("%+v", ev))
	}
	logs.WriteString(fmt.Sprintf("%v", resp))
	if strings.Contains(logs.String(), canary) {
		t.Fatal("the password canary appears in a response or event")
	}
	u := r.entry("CN=wkenabled1,"+r.ou, "userAccountControl")
	if u.GetAttributeValue("userAccountControl") != "512" {
		t.Fatalf("uac %s", u.GetAttributeValue("userAccountControl"))
	}
	c, err := ldap.DialURL("ldaps://localhost:"+r.port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: r.pool, ServerName: "localhost"}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind("wkenabled1@lab.activediq.test", canary); err != nil {
		t.Fatalf("the created user cannot log on: %v", err)
	}
}

// CC-WK-04: a Tier-0 parent is refused before any directory write.
func TestWKCreateUnderTier0Parent(t *testing.T) {
	r := newWKRig(t)
	dcOU := r.guidOf("OU=Domain Controllers," + labDom)
	oc := &connectorv1.ObjectCreate{ObjectClass: ctGroup, RdnValue: "wk-t0", GroupScope: connectorv1.GroupScope_GROUP_SCOPE_GLOBAL,
		Initial: []*connectorv1.AttributeEdit{ed(opSet, "sAMAccountName", "wkt0")}}
	_, err := r.planApply(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, dcOU, createChange(oc))
	wantCode(t, "Domain Controllers OU parent", err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
	if r.exists("CN=wk-t0,OU=Domain Controllers," + labDom) {
		t.Fatal("an object was created under a Tier-0 parent")
	}
	// A parent with no statement in the context is refused too.
	p := r.planReq(connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, r.ouID, createChange(oc))
	p.Tier0 = r.tier0Ctx()
	_, err = r.plan(p)
	wantCode(t, "missing statement", err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
}

// CC-WK-05 / 06 / 07 / 08: update.
func TestWKUpdate(t *testing.T) {
	r := newWKRig(t)
	r.adminAdd("CN=wkupd,"+r.ou, "user", map[string][]string{"sAMAccountName": {"wkupd"}, "description": {"old"}, "otherTelephone": {"1", "2"}})
	id := r.guidOf("CN=wkupd," + r.ou)
	upd := connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE
	// SET (single), ADD/REMOVE_VALUE (multi), CLEAR
	if _, err := r.planApply(upd, id, updateChange(ed(opSet, "description", "new"), ed(opAdd, "otherTelephone", "3"))); err != nil {
		t.Fatalf("set/add: %v", err)
	}
	if _, err := r.planApply(upd, id, updateChange(ed(opRemove, "otherTelephone", "1"))); err != nil {
		t.Fatalf("set/add/remove: %v %v", err, connErr(t, err))
	}
	e := r.entry("CN=wkupd,"+r.ou, "description", "otherTelephone")
	if e.GetAttributeValue("description") != "new" || len(e.GetAttributeValues("otherTelephone")) != 2 {
		t.Fatalf("after: %v %v", e.GetAttributeValue("description"), e.GetAttributeValues("otherTelephone"))
	}
	if _, err := r.planApply(upd, id, updateChange(ed(opClear, "description"))); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if v := r.entry("CN=wkupd,"+r.ou, "description").GetAttributeValues("description"); len(v) != 0 {
		t.Fatalf("clear left %v", v)
	}
	// CC-WK-08: retried after success is ALREADY_APPLIED
	ch := updateChange(ed(opSet, "description", "again"))
	p := r.planReq(upd, id, ch)
	pr, err := r.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	a := r.applyFrom(p, pr, nil)
	if _, err := r.apply(a); err != nil {
		t.Fatal(err)
	}
	if resp, err := r.apply(a); err != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED {
		t.Fatalf("retry: %v %v", resp.GetOutcome(), err)
	}
	// CC-WK-06: a second writer between Plan and Apply
	p = r.planReq(upd, id, updateChange(ed(opSet, "description", "mine")))
	pr, err = r.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	mod := ldap.NewModifyRequest("CN=wkupd,"+r.ou, nil)
	mod.Replace("description", []string{"theirs"})
	if err := r.admin.Modify(mod); err != nil {
		t.Fatal(err)
	}
	_, err = r.apply(r.applyFrom(p, pr, nil))
	wantCode(t, "second writer", err, connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED)
	if v := r.entry("CN=wkupd,"+r.ou, "description").GetAttributeValue("description"); v != "theirs" {
		t.Fatalf("the second writer's value did not survive: %q", v)
	}
	// CC-WK-07: deny-listed attributes by name, case, OID, option; unknown; limits
	for _, name := range []string{"unicodePwd", "UNICODEPWD", "1.2.840.113556.1.4.90", "unicodePwd;binary", "userAccountControl", "member", "nTSecurityDescriptor",
		"objectClass", "name", "gPLink", "servicePrincipalName", "sAMAccountType", "nosuchattribute"} {
		_, err := r.plan(r.planReq(upd, id, updateChange(ed(opSet, name, "x"))))
		wantCode(t, name, err, connectorv1.ErrorCode_ERROR_CODE_ATTRIBUTE_NOT_ALLOWED)
	}
	many := make([]*connectorv1.AttributeEdit, 65)
	for i := range many {
		many[i] = ed(opSet, "description", "x")
	}
	_, err = r.plan(r.planReq(upd, id, updateChange(many...)))
	wantCode(t, "65 edits", err, connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED)
	_, err = r.plan(r.planReq(upd, id, updateChange(ed(opSet, "otherTelephone", make([]string, 1001)...))))
	wantCode(t, "1001 values", err, connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED)
}

// CC-WK-08 / CC-WRITE-27: `title` is a key in a designated dynamic rule; the twin telephoneNumber is not.
func TestWKUpdateRuleKey(t *testing.T) {
	r := newWKRigRule(t, true)
	r.adminAdd("CN=wkrule,"+r.ou, "user", map[string][]string{"sAMAccountName": {"wkrule"}})
	id := r.guidOf("CN=wkrule," + r.ou)
	upd := connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE
	_, err := r.plan(r.planReq(upd, id, updateChange(ed(opSet, "title", "x"))))
	wantCode(t, "title rule key", err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
	if _, err := r.planApply(upd, id, updateChange(ed(opSet, "telephoneNumber", "555"))); err != nil {
		t.Fatalf("twin: %v", err)
	}
}

// CC-WK-08: manager set and cleared; directReports appears on the manager.
func TestWKUpdateManager(t *testing.T) {
	r := newWKRig(t)
	r.adminAdd("CN=wkboss,"+r.ou, "user", map[string][]string{"sAMAccountName": {"wkboss"}})
	r.adminAdd("CN=wkemp,"+r.ou, "user", map[string][]string{"sAMAccountName": {"wkemp"}})
	boss, emp := r.guidOf("CN=wkboss,"+r.ou), r.guidOf("CN=wkemp,"+r.ou)
	upd := connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE
	setMgr := &connectorv1.AttributeEdit{Attribute: "manager", Op: opSet, Values: []*connectorv1.EditValue{{Value: &connectorv1.EditValue_ObjectRef{ObjectRef: toWire(boss)}}}}
	if _, err := r.planApply(upd, emp, updateChange(setMgr)); err != nil {
		t.Fatalf("set manager: %v", err)
	}
	if dr := r.entry("CN=wkboss,"+r.ou, "directReports").GetAttributeValues("directReports"); len(dr) != 1 || !strings.EqualFold(dr[0], "CN=wkemp,"+r.ou) {
		t.Fatalf("directReports %v", dr)
	}
	if _, err := r.planApply(upd, emp, updateChange(ed(opClear, "manager"))); err != nil {
		t.Fatalf("clear manager: %v", err)
	}
	if dr := r.entry("CN=wkboss,"+r.ou, "directReports").GetAttributeValues("directReports"); len(dr) != 0 {
		t.Fatalf("directReports after clear %v", dr)
	}
}

// CC-WK-09 / 10: delete.
func TestWKDelete(t *testing.T) {
	r := newWKRig(t)
	// Finding a deleted object by GUID (the retry check) needs read access to CN=Deleted Objects, which
	// samba-tool cannot grant; this test binds the connector as Administrator. The svc account's
	// behaviour is TestWKDeleteRetryWithoutDeletedObjectsRights.
	r.rebind("Administrator", r.env["LAB_ADMIN_PASSWORD"])
	del := connectorv1.WriteKind_WRITE_KIND_OBJECT_DELETE
	r.adminAdd("CN=wkleaf,"+r.ou, "user", map[string][]string{"sAMAccountName": {"wkleaf"}})
	id := r.guidOf("CN=wkleaf," + r.ou)
	p := r.planReq(del, id, deleteChange())
	pr, err := r.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	a := r.applyFrom(p, pr, nil)
	resp, err := r.apply(a)
	if err != nil || resp.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED {
		t.Fatalf("delete: %v %v", resp.GetOutcome(), err)
	}
	if r.exists("CN=wkleaf," + r.ou) {
		t.Fatal("still there")
	}
	// CC-WK-10: retried after success
	again, err := r.apply(a)
	if err != nil || again.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED {
		t.Fatalf("retry: %v %v %v", again.GetOutcome(), err, connErr(t, err))
	}
	// non-leaf OU
	r.adminAdd("OU=wkparent,"+r.ou, "organizationalUnit", nil)
	r.adminAdd("CN=wkchild,OU=wkparent,"+r.ou, "group", map[string][]string{"sAMAccountName": {"wkchild"}})
	pid := r.guidOf("OU=wkparent," + r.ou)
	_, err = r.planApply(del, pid, deleteChange())
	wantRule(t, "non-leaf", err, "NotLeaf")
	if !r.exists("OU=wkparent," + r.ou) {
		t.Fatal("a non-leaf OU was deleted")
	}
	// protected from accidental deletion: Deny Delete + DeleteTree for Everyone (Samba may or may not enforce; recorded)
	t.Log("protected-from-accidental-deletion is exercised by the Windows lab (Samba dsacl cannot set the inherited deny reliably)")
}

// CC-WK-28: a Tier-0 target is refused at CONNECTOR_SET before the kind's code, for each kind.
func TestWKTier0Targets(t *testing.T) {
	r := newWKRig(t)
	da := r.guidOf("CN=Domain Admins,CN=Users," + labDom)
	for _, k := range []struct {
		kind connectorv1.WriteKind
		ch   *connectorv1.WriteChange
	}{
		{connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE, updateChange(ed(opSet, "description", "x"))},
		{connectorv1.WriteKind_WRITE_KIND_OBJECT_DELETE, deleteChange()},
		{connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE, createChange(&connectorv1.ObjectCreate{ObjectClass: ctOU, RdnValue: "x"})},
	} {
		_, err := r.planApply(k.kind, da, k.ch)
		wantCode(t, k.kind.String(), err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
	}
	if v := r.entry("CN=Domain Admins,CN=Users,"+labDom, "description").GetAttributeValue("description"); strings.Contains(v, "x") && v == "x" {
		t.Fatal("Domain Admins was written")
	}
}

// CC-WK-29: arm mismatch, no arm, a second arm is not expressible (oneof), secret on a non-secret kind.
func TestWKArmAndSecretMismatch(t *testing.T) {
	r := newWKRig(t)
	id := r.ouID
	upd, del, cre := connectorv1.WriteKind_WRITE_KIND_OBJECT_UPDATE, connectorv1.WriteKind_WRITE_KIND_OBJECT_DELETE, connectorv1.WriteKind_WRITE_KIND_OBJECT_CREATE
	for name, p := range map[string]*connectorv1.PlanRequest{
		"update kind, delete arm": r.planReq(upd, id, deleteChange()),
		"delete kind, update arm": r.planReq(del, id, updateChange(ed(opSet, "description", "x"))),
		"create kind, no arm":     r.planReq(cre, id, nil),
	} {
		_, err := r.plan(p)
		wantRule(t, name, err, "WriteChangeArmMismatch")
	}
	p := r.planReq(upd, id, updateChange(ed(opSet, "description", "x")))
	a := r.applyFrom(p, &connectorv1.PlanResponse{}, []byte("secret"))
	_, err := r.apply(a)
	wantRule(t, "secret on update", err, "SecretInputMismatch")
}

// CC-WK-10 on Samba for the connector's own account: it cannot read CN=Deleted Objects, so the retry of
// a delete cannot be recognised and is refused fail-closed (never a second delete, never a false success).
func TestWKDeleteRetryWithoutDeletedObjectsRights(t *testing.T) {
	r := newWKRig(t)
	del := connectorv1.WriteKind_WRITE_KIND_OBJECT_DELETE
	r.adminAdd("CN=wkleaf2,"+r.ou, "user", map[string][]string{"sAMAccountName": {"wkleaf2"}})
	id := r.guidOf("CN=wkleaf2," + r.ou)
	p := r.planReq(del, id, deleteChange())
	pr, err := r.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	a := r.applyFrom(p, pr, nil)
	if _, err := r.apply(a); err != nil {
		t.Fatal(err)
	}
	_, err = r.apply(a)
	wantCode(t, "retry without Deleted Objects rights", err, connectorv1.ErrorCode_ERROR_CODE_TIER0_REFUSED)
}
