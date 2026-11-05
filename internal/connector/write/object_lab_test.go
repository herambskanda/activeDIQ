//go:build lab

package write

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// CC-WK-12..15 and the Samba half of CC-WK-18 on the Samba lab:
// `make lab-up && go test -tags lab ./internal/connector/write -run TestLabObject`.
// Restore on a Windows DC with the Recycle Bin (CC-WK-16, 17, 18-W) is a Windows-lab ticket.

type labObj struct {
	ctx   context.Context
	sess  *ad.Session
	admin *ldap.Conn
	h     *Handler
	dc    *connectorv1.DcIdentity
	dom   guidT
}

func newLabObj(t *testing.T) *labObj {
	t.Helper()
	env := labEnv(t)
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	port := env["LAB_LDAPS_PORT"]
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	sess, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + port}, RootCAs: pool, PageSize: 500,
		Credential: ad.Credential{BindName: "Administrator@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_ADMIN_PASSWORD"]))}})
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
	book, _ := NewGateBook(&memBaseline{}, time.Now)
	run := passRun(nil)
	run.CompletedAt = time.Now()
	book.Complete(connID, run)
	prov := NewADProvider(sess, nil, adIdentity(), &memPins{})
	prov.Dynamic = &stubGuard{} // no Entra snapshot in the lab: the dynamic-rule guard allows (its own tests: propwrite_test.go)
	dc, err := prov.BoundDC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(prov, book, WithRecorder(&memRecorder{}))
	if err != nil {
		t.Fatal(err)
	}
	dom := labGUID(t, ctx, sess, labDom)
	return &labObj{ctx: ctx, sess: sess, admin: admin, h: h, dc: dc, dom: dom}
}

func labGUID(t *testing.T, ctx context.Context, s *ad.Session, dnText string) guidT {
	t.Helper()
	ref, err := dn.ParseObjectRef(dnText)
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Read(ctx, ref, []string{"objectGUID"}, ad.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	g, err := e.GUID()
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (l *labObj) add(t *testing.T, dnText string, class []string, attrs map[string][]string) guidT {
	t.Helper()
	r := ldap.NewAddRequest(dnText, nil)
	r.Attribute("objectClass", class)
	for k, v := range attrs {
		r.Attribute(k, v)
	}
	if err := l.admin.Add(r); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.admin.Del(ldap.NewDelRequest(dnText, nil)) })
	return labGUID(t, l.ctx, l.sess, dnText)
}

func (l *labObj) ctx0(ids ...guidT) *connectorv1.Tier0Context {
	c := &connectorv1.Tier0Context{Tier0Revision: 1}
	for _, id := range ids {
		c.Statements = append(c.Statements, noLink(id, time.Now()))
	}
	return c
}

func (l *labObj) target(id guidT) *connectorv1.WriteTarget {
	return &connectorv1.WriteTarget{Object: toWire(id), NcGuid: toWire(l.dom)}
}

func (l *labObj) plan(kind connectorv1.WriteKind, target guidT, ch *connectorv1.WriteChange, ids ...guidT) (*connectorv1.PlanResponse, error) {
	q := planReq(target, l.ctx0(ids...))
	q.Kind, q.Change, q.Target = kind, ch, l.target(target)
	q.Dc = &connectorv1.DcSelection{PinnedDsaGuid: l.dc.GetDsaGuid()}
	return l.h.Plan(l.ctx, q)
}

func (l *labObj) apply(kind connectorv1.WriteKind, key string, attrs []step.Attr, target guidT, ch *connectorv1.WriteChange, pre *connectorv1.TargetPrecondition, ids ...guidT) (*connectorv1.ApplyResponse, error) {
	q := applyReq(target, l.ctx0(ids...))
	q.Kind, q.Change, q.Target = kind, ch, l.target(target)
	pre.Dc = l.dc
	q.Precondition = pre
	d := step.Compute(key, authority.TargetRef{Connection: connID, GUID: target.String(), NC: authority.NamingContextID(l.dom.String())}, attrs)
	q.PlanDigest = d[:]
	return l.h.Apply(l.ctx, q)
}

func (l *labObj) parentOf(t *testing.T, id guidT) guidT {
	t.Helper()
	st, err := l.sess.ObjectState(l.ctx, id, false)
	if err != nil {
		t.Fatal(err)
	}
	return st.Parent
}

func labUser(name string) (string, []string, map[string][]string) {
	return name, []string{"top", "person", "organizationalPerson", "user"}, map[string][]string{"sAMAccountName": {name[:min(len(name), 18)]}}
}

// CC-WK-12 and 13.
func TestLabObjectMove(t *testing.T) {
	l := newLabObj(t)
	sfx := fmt.Sprint(time.Now().UnixNano() % 1_000_000)
	ouA := l.add(t, "OU=wk12a"+sfx+","+labDom, []string{"top", "organizationalUnit"}, nil)
	ouB := l.add(t, "OU=wk12b"+sfx+","+labDom, []string{"top", "organizationalUnit"}, nil)
	n, cls, at := labUser("wk12u" + sfx)
	u := l.add(t, "CN="+n+",OU=wk12a"+sfx+","+labDom, cls, at)
	kind := connectorv1.WriteKind_WRITE_KIND_OBJECT_MOVE
	ch := moveChangeTo(ouB, l.dom)
	attrs := []step.Attr{{Name: client.AttrNewParent, Values: []string{ouB.String()}}, {Name: client.AttrNewParentNC, Values: []string{l.dom.String()}}}

	p, err := l.plan(kind, u, ch, u, ouA, ouB)
	if err != nil || p.GetNoOp() {
		t.Fatalf("plan: %v %v %v", p, err, labDetail(err))
	}
	if _, err := l.apply(kind, client.DigestObjectMove, attrs, u, ch, p.Precondition, u, ouA, ouB); err != nil {
		t.Fatal(err)
	}
	if got := l.parentOf(t, u); got != ouB {
		t.Fatalf("parent %s, want %s", got, ouB)
	}
	// Retried after success.
	p, err = l.plan(kind, u, ch, u, ouB, ouB)
	if err != nil || !p.GetNoOp() {
		t.Fatalf("replan: %v %v", p, err)
	}
	a, err := l.apply(kind, client.DigestObjectMove, attrs, u, ch, p.Precondition, u, ouB)
	if err != nil || a.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED {
		t.Fatalf("retry: %v %v", a, err)
	}

	// Into the Domain Controllers OU: refused before any write.
	dcOU := labGUID(t, l.ctx, l.sess, "OU=Domain Controllers,"+labDom)
	_, err = l.plan(kind, u, moveChangeTo(dcOU, l.dom), u, ouB, dcOU)
	wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
	// To another domain's OU.
	_, err = l.plan(kind, u, moveChangeTo(ouA, mk(77)), u, ouB, ouA)
	if connErr(t, err).GetRejectedInput().GetRuleId() != "CrossDomainMoveUnsupported" {
		t.Fatalf("cross domain: %v", err)
	}
	if got := l.parentOf(t, u); got != ouB {
		t.Fatal("a refused move wrote")
	}
	_ = tier0.C6
}

// CC-WK-14 and 15: rename keeps sAMAccountName, builds special-character RDNs with the DN type.
func TestLabObjectRename(t *testing.T) {
	l := newLabObj(t)
	sfx := fmt.Sprint(time.Now().UnixNano() % 1_000_000)
	n, cls, at := labUser("wk14u" + sfx)
	u := l.add(t, "CN="+n+","+labDom, cls, at)
	other := l.add(t, "CN=wk14other"+sfx+","+labDom, []string{"top", "group"}, nil)
	kind := connectorv1.WriteKind_WRITE_KIND_OBJECT_RENAME
	for _, name := range []string{"wk14 new" + sfx, `wk15,+"\<>;=` + sfx, "#wk15 lead" + sfx, " wk15 sp" + sfx, "wk15 tr" + sfx + " "} {
		ch := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectRename{ObjectRename: &connectorv1.ObjectRename{NewRdnValue: name}}}
		attrs := []step.Attr{{Name: client.AttrNewRDN, Values: []string{name}}}
		p, err := l.plan(kind, u, ch, u)
		if err != nil {
			t.Fatalf("%q plan: %v", name, err)
		}
		if _, err := l.apply(kind, client.DigestObjectRename, attrs, u, ch, p.Precondition, u); err != nil {
			t.Fatalf("%q apply: %v", name, err)
		}
		st, err := l.sess.ObjectState(l.ctx, u, false)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.DN.RDNs()[0].Value(); got != name {
			// AD trims unescaped trailing space only; an escaped one is kept.
			t.Errorf("stored RDN %q, want %q", got, name)
		}
		if sam := st.Entry; sam == nil {
			t.Fatal("no entry")
		}
		// Retried after success.
		p, err = l.plan(kind, u, ch, u)
		if err != nil || !p.GetNoOp() {
			t.Fatalf("%q replan: %v %v", name, p, err)
		}
	}
	// A name taken under the parent.
	ch := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectRename{ObjectRename: &connectorv1.ObjectRename{NewRdnValue: "wk14other" + sfx}}}
	p, err := l.plan(kind, u, ch, u)
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.apply(kind, client.DigestObjectRename, []step.Attr{{Name: client.AttrNewRDN, Values: []string{"wk14other" + sfx}}}, u, ch, p.Precondition, u)
	if connErr(t, err).GetRejectedInput().GetRuleId() != "NameInUse" {
		t.Fatalf("name in use: %v", err)
	}
	_ = other
	e, err := l.sess.Read(l.ctx, dn.GUIDRef(u), []string{"sAMAccountName", "userPrincipalName"}, ad.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Strings("sAMAccountName"); len(got) != 1 || got[0] != n[:min(len(n), 18)] {
		t.Errorf("sAMAccountName changed: %v", got)
	}
}

// CC-WK-18 on Samba: whether the Recycle Bin is reported decides restore; the outcome is recorded in
// the ticket note and contract §8.10.7. Without it the restore is CAPABILITY_UNSUPPORTED.
func TestLabObjectRestoreSamba(t *testing.T) {
	l := newLabObj(t)
	on, err := SessionObjects{S: l.sess}.RecycleBin(l.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Samba Recycle Bin feature reported enabled: %v", on)
	sfx := fmt.Sprint(time.Now().UnixNano() % 1_000_000)
	n, cls, at := labUser("wk18u" + sfx)
	u := l.add(t, "CN="+n+","+labDom, cls, at)
	ou := l.add(t, "OU=wk18"+sfx+","+labDom, []string{"top", "organizationalUnit"}, nil)
	ch := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectRestore{ObjectRestore: &connectorv1.ObjectRestore{
		NewParent: l.target(ou), RdnValue: n}}}
	_, err = l.plan(connectorv1.WriteKind_WRITE_KIND_OBJECT_RESTORE, u, ch, u, ou)
	if on {
		// A live object that is not at the planned parent is not a deleted object.
		if connErr(t, err).GetRejectedInput().GetRuleId() != "NotDeleted" {
			t.Fatalf("live object: %v", err)
		}
		return
	}
	if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("got %s, want CAPABILITY_UNSUPPORTED without the Recycle Bin", c)
	}
}

func labDetail(err error) string {
	if err == nil {
		return ""
	}
	if st, ok := status.FromError(err); ok {
		for _, d := range st.Details() {
			if ce, ok := d.(*connectorv1.ConnectorError); ok {
				return ce.String()
			}
		}
	}
	return ""
}
