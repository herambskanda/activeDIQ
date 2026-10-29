//go:build lab && windowslab

// Windows Server DC proof for the T-0092 read paths (T-0210): transitive tokenGroups on a base
// Read, the effective-rights attributes, the critical SD-flags control with no SACL returned, and
// the LDAPS/signing policy outcome. Same bodies as the Samba lab (lab_test.go) but against dc1.
package ad

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

func winSession(t *testing.T) *Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := Open(ctx, winConfig(t, winEnv(t)["WIN_LAB_SVC_PASSWORD"], true))
	if err != nil {
		t.Fatalf("open over LDAPS: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func winFindOne(t *testing.T, s *Session, attr, value string) *Entry {
	t.Helper()
	a, err := ldapfilter.ParseAttrName(attr, s.schema)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := dn.Parse(winBase, dn.Strict)
	var got []*Entry
	err = s.Search(context.Background(), SearchRequest{
		Base: dn.DNRef(root), Scope: ScopeSubtree,
		Filter:     ldapfilter.Eq(a, ldapfilter.String(value)),
		Attributes: []string{"objectGUID", "distinguishedName"},
	}, func(e *Entry) error { got = append(got, e); return nil })
	if err != nil || len(got) != 1 {
		t.Fatalf("find %s=%q: %d entries, err %v", attr, value, len(got), err)
	}
	return got[0]
}

// Transitive tokenGroups on a base Read; Domain Users (RID 513) is always in the token.
func TestWindowsLabReadOwnTokenGroups(t *testing.T) {
	s := winSession(t)
	self := winFindOne(t, s, "sAMAccountName", "svc-activediq")
	g, err := self.GUID()
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Read(context.Background(), dn.GUIDRef(g), []string{"objectSid", "tokenGroups"}, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	toks, err := e.SIDs("tokenGroups")
	if err != nil || len(toks) == 0 {
		t.Fatalf("tokenGroups = %v, %v", toks, err)
	}
	me, _ := e.SIDs("objectSid")
	dom, _ := me[0].DomainSID()
	var domainUsers bool
	for _, x := range toks {
		if rid, ok := x.RID(); ok && rid == 513 {
			if d, _ := x.DomainSID(); d == dom {
				domainUsers = true
			}
		}
	}
	if !domainUsers {
		t.Errorf("Domain Users (RID 513) missing from %d token groups", len(toks))
	}
	d, _ := dn.Parse(self.DN, dn.Strict)
	e2, err := s.Read(context.Background(), dn.DNRef(d), []string{"tokenGroups"}, ReadOptions{})
	if err != nil || len(e2.Raw("tokenGroups")) != len(toks) {
		t.Errorf("read by DN: %v, %d values", err, len(e2.Raw("tokenGroups")))
	}
	root, _ := dn.Parse(winBase, dn.Strict)
	cn, _ := ldapfilter.ParseAttrName("cn", s.schema)
	err = s.Search(context.Background(), SearchRequest{Base: dn.DNRef(root), Scope: ScopeBase, Filter: ldapfilter.Present(cn), Attributes: []string{"tokenGroups"}}, func(*Entry) error { return nil })
	if CodeOf(err) != CodeAttributeNotAllowed {
		t.Errorf("search for tokenGroups: %v", err)
	}
}

// allowedAttributesEffective, allowedChildClassesEffective, sDRightsEffective as dc1 computes them.
func TestWindowsLabReadEffectiveRights(t *testing.T) {
	s := winSession(t)
	ctx := context.Background()
	attrs := []string{"allowedAttributesEffective", "allowedChildClassesEffective", "sDRightsEffective"}
	managed := winFindOne(t, s, "ou", "Managed")
	mg, _ := managed.GUID()
	m, err := s.Read(ctx, dn.GUIDRef(mg), attrs, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Managed: %d writable attrs, child classes %v, sDRightsEffective present=%v", len(m.Strings("allowedAttributesEffective")), m.Strings("allowedChildClassesEffective"), m.Has("sDRightsEffective"))
	root, _ := dn.Parse(winBase, dn.Strict)
	r, err := s.Read(ctx, dn.DNRef(root), attrs, ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(r.Strings("allowedChildClassesEffective")); n != 0 {
		t.Errorf("connector identity can create %d child classes at the domain root; it must not", n)
	}
	if len(m.Strings("allowedChildClassesEffective")) == 0 {
		t.Error("connector identity sees no creatable child class in OU=Managed, where it is delegated")
	}
	if v, ok, err := m.Int32("sDRightsEffective"); err != nil || !ok || v&8 != 0 {
		t.Errorf("sDRightsEffective = %d ok=%v err=%v; the SACL bit must not be granted", v, ok, err)
	}
}

// The critical SD-flags control (7) is honoured: no SACL on any SD read, for several object kinds.
func TestWindowsLabReadSecurityDescriptorNoSACL(t *testing.T) {
	s := winSession(t)
	ctx := context.Background()
	root, _ := dn.Parse(winBase, dn.Strict)
	targets := map[string]dn.ObjectRef{"domain root": dn.DNRef(root)}
	for _, o := range []struct{ attr, val string }{{"ou", "Managed"}, {"sAMAccountName", "svc-activediq"}, {"cn", "Domain Admins"}} {
		e := winFindOne(t, s, o.attr, o.val)
		g, _ := e.GUID()
		targets[o.val] = dn.GUIDRef(g)
	}
	for name, ref := range targets {
		e, err := s.Read(ctx, ref, []string{"nTSecurityDescriptor"}, ReadOptions{})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		sd := e.Raw("nTSecurityDescriptor")
		if len(sd) != 1 || len(sd[0]) < 20 {
			t.Errorf("%s: nTSecurityDescriptor = %d values", name, len(sd))
			continue
		}
		if sd[0][0] != 1 || sd[0][2]&0x10 != 0 || sd[0][12]|sd[0][13]|sd[0][14]|sd[0][15] != 0 {
			t.Errorf("%s: descriptor header % x: SE_SACL_PRESENT or offsetSacl set", name, sd[0][:20])
		}
		if sd[0][16]|sd[0][17]|sd[0][18]|sd[0][19] == 0 {
			t.Errorf("%s: offsetDacl is 0: the DACL part was not returned", name)
		}
	}
}

// AC2: LDAPS simple bind under the lab's signing / channel-binding policy. A simple bind over
// TLS is not subject to channel binding (that gates SASL/NTLM/Kerberos binds), so it must succeed;
// the same bind in the clear on 389 must be refused when LDAP signing is required
// (result 8 strongerAuthRequired). The outcome is logged for the run record either way.
func TestWindowsLabLDAPSSimpleBindUnderSigningPolicy(t *testing.T) {
	cfg := winConfig(t, winEnv(t)["WIN_LAB_SVC_PASSWORD"], true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("LDAPS simple bind failed under the lab policy: %v (code %v)", err, CodeOf(err))
	}
	s.Close()
	t.Log("LDAPS simple bind: success")

	host, _, _ := net.SplitHostPort(cfg.Servers[0])
	conn, err := ldap.DialURL("ldap://" + net.JoinHostPort(host, "389"))
	if err != nil {
		t.Fatalf("dial 389: %v", err)
	}
	defer conn.Close()
	err = conn.Bind(winBind, winEnv(t)["WIN_LAB_SVC_PASSWORD"])
	var le *ldap.Error
	if !errors.As(err, &le) {
		t.Fatalf("plaintext simple bind on 389 was not refused (err=%v): LDAP signing is not required on dc1", err)
	}
	t.Logf("plaintext simple bind on 389: result %d (%s)", le.ResultCode, le.Err)
	if le.ResultCode != ldap.LDAPResultStrongAuthRequired {
		t.Errorf("plaintext simple bind result = %d, want 8 strongerAuthRequired", le.ResultCode)
	}
	// Channel binding evidence: TLS 1.2+ negotiated, which tls-server-end-point binding rides on.
	tc, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", cfg.Servers[0], &tls.Config{ServerName: cfg.ServerName, RootCAs: cfg.RootCAs})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	if v := tc.ConnectionState().Version; v < tls.VersionTLS12 {
		t.Errorf("TLS version %x < 1.2", v)
	}
}
