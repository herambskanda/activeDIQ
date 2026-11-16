//go:build lab

package read_test

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/wirevalue"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

type oneRightCat map[guid.GUID]sd.RightKind

func (m oneRightCat) Kind(g guid.GUID) (sd.RightKind, bool) { k, ok := m[g]; return k, ok }

// TestLabPasswordChangeVerdict (T-1551, AC3) asks the real Read handler, over the connector's own
// Samba session, for the Cannot Change Password verdict of users with both, one and no deny ACEs
// (written through the real DACL write path) and checks each equals what sd.ClassifyPasswordChange
// says about the descriptor the administrator reads independently. A user that does not exist reads
// NOT_CONFIRMED with a code and fails nothing. The DACL-only SD_FLAGS control on the wire is asserted by
// ad.TestReadPasswordChangeSendsTheSDFlagsControl; Samba proves the LDAP mechanics and the decode of what
// it stores, not Windows ACL ordering (windows-lab ticket).
//
//	make lab-up && go test -tags lab ./internal/connector/read -run TestLabPasswordChangeVerdict
func TestLabPasswordChangeVerdict(t *testing.T) {
	l := newSearchLab(t)
	env := labEnv(t)
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	// A second session, bound as the administrator, writes the deny ACEs; the connector's own (service)
	// session reads them back.
	admSess, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + env["LAB_LDAPS_PORT"]}, RootCAs: pool, PageSize: searchPage, Schema: ad.DefaultSchema(),
		Credential: ad.Credential{BindName: "Administrator@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_ADMIN_PASSWORD"]))}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admSess.Close() })

	ou := "OU=pwchange-" + l.stamp + "," + labDom
	l.add(t, ou, map[string][]string{"objectClass": {"organizationalUnit"}})
	t.Cleanup(func() { l.delTree(ou) })

	adminSID := l.sidOf(t, "CN=Administrator,CN=Users,"+labDom)
	dom, _ := adminSID.DomainSID()
	da, _ := sid.Parse(dom.String() + "-512")
	everyone, _ := sid.Parse("S-1-1-0")
	self, _ := sid.Parse("S-1-5-10")
	cp, _ := guid.Parse("ab721a53-1e2f-11d0-9819-00aa0040529b")
	cat := oneRightCat{cp: sd.ControlAccess}

	type user struct {
		name string
		dn   string
		ref  dn.ObjectRef
		g    guid.GUID
		deny []sid.SID
	}
	mk := func(name string, deny ...sid.SID) *user {
		d := "CN=" + name + "," + ou
		l.add(t, d, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
			"sAMAccountName": {name + l.stamp}, "userAccountControl": {"514"}})
		pd, err := dn.Parse(d, dn.Strict)
		if err != nil {
			t.Fatal(err)
		}
		g := l.rawGUID(t, d)
		return &user{name: name, dn: d, ref: dn.DNRef(pd), g: g, deny: deny}
	}
	users := []*user{mk("pwboth", everyone, self), mk("pwone", self), mk("pwnone")}
	for _, u := range users {
		if len(u.deny) == 0 {
			continue
		}
		_, base, err := admSess.ReadDACL(ctx, u.ref)
		if err != nil {
			t.Fatal(err)
		}
		var add []sd.NewACE
		for _, tr := range u.deny {
			add = append(add, sd.NewACE{Deny: true, Trustee: tr, Mask: sd.MaskControlAccess, ObjectType: &cp})
		}
		w, _, err := sd.PlanDACL(base, sd.ACEDiff{Add: add}, cat, sd.ObjectCtx{ObjectGUID: u.g, Connector: sd.PrincipalFromSIDs(adminSID, da)}, sd.PlanOpts{})
		if err != nil {
			t.Fatalf("plan %s: %v", u.name, err)
		}
		if err := admSess.WriteDACL(ctx, u.ref, w, labReplaceSD); err != nil {
			t.Fatalf("write %s: %v", u.name, err)
		}
	}

	verdict := func(g *connectorv1.Guid) *connectorv1.PasswordChangeVerdict {
		t.Helper()
		r := &connectorv1.ReadRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: l.ident},
			Guid: g, NcGuid: l.guid(t, labDom), Attributes: []string{"objectClass"}, IncludePasswordChange: true}
		ms, err := collect(t, l.client, r)
		if err != nil || len(ms) < 2 {
			t.Fatalf("Read: %v (%d messages)", err, len(ms))
		}
		return ms[0].GetHeader().GetPasswordChange()
	}
	wire := map[sd.PasswordChange]connectorv1.PasswordChangeState{
		sd.PasswordChangeBlocked:       connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_BLOCKED,
		sd.PasswordChangeBlockedOneACE: connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_BLOCKED_ONE_ACE,
		sd.PasswordChangeNoDenyACE:     connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_NO_DENY_ACE,
	}
	for _, u := range users {
		// The expectation: the descriptor read independently by the administrator session, classified by
		// the sd primitive itself.
		_, d, err := admSess.ReadDACL(ctx, u.ref)
		if err != nil {
			t.Fatal(err)
		}
		want, err := d.PasswordChange()
		if err != nil {
			t.Fatalf("%s: %v", u.name, err)
		}
		v := verdict(wirevalue.GUIDToWire(u.g))
		if v.GetState() != wire[want] || !guidEq(v.GetObjectGuid(), u.g) || v.GetErrorCode() != connectorv1.ErrorCode_ERROR_CODE_UNSPECIFIED {
			t.Errorf("%s: verdict %v, want %v", u.name, v, wire[want])
		}
	}
	// The three differ, so a constant answer cannot pass.
	if a, b, c := verdict(wirevalue.GUIDToWire(users[0].g)).GetState(), verdict(wirevalue.GUIDToWire(users[1].g)).GetState(), verdict(wirevalue.GUIDToWire(users[2].g)).GetState(); a == b || b == c || a == c {
		t.Fatalf("states not distinct: %v %v %v", a, b, c)
	}
	// A user that is gone is NOT_CONFIRMED... or OBJECT_NOT_FOUND from the base read: never a state.
	gone := &connectorv1.Guid{Value: []byte("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")}
	r := &connectorv1.ReadRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: l.ident},
		Guid: gone, Attributes: []string{"objectClass"}, IncludePasswordChange: true}
	if ms, err := collect(t, l.client, r); err == nil {
		for _, m := range ms {
			if p := m.GetHeader().GetPasswordChange(); p != nil && p.GetState() != connectorv1.PasswordChangeState_PASSWORD_CHANGE_STATE_NOT_CONFIRMED {
				t.Fatalf("a missing object has state %v", p)
			}
		}
	}
	_ = ldap.ScopeBaseObject
}

func guidEq(w *connectorv1.Guid, g guid.GUID) bool {
	return string(w.GetValue()) == string(wirevalue.GUIDToWire(g).GetValue())
}

func (l *searchLab) sidOf(t *testing.T, d string) sid.SID {
	t.Helper()
	res, err := l.adm.Search(ldap.NewSearchRequest(d, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectSid"}, nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("sid of %s: %v", d, err)
	}
	v, err := sid.FromBytes(res.Entries[0].GetRawAttributeValue("objectSid"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// rawGUID is the objectGUID as the directory stores it (mixed-endian bytes decoded by the guid codec).
func (l *searchLab) rawGUID(t *testing.T, d string) guid.GUID {
	t.Helper()
	res, err := l.adm.Search(ldap.NewSearchRequest(d, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("guid of %s: %v", d, err)
	}
	g, err := guid.FromBytes(res.Entries[0].GetRawAttributeValue("objectGUID"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// labReplaceSD is the lab's own single replace of nTSecurityDescriptor: the operation bodies in
// connector/write/ops are importable only by the guard's package.
func labReplaceSD(m ad.Modifier, dn string, value []byte, controls []ldap.Control) error {
	req := ldap.NewModifyRequest(dn, controls)
	req.Replace("nTSecurityDescriptor", []string{string(value)})
	return m.Modify(req)
}
