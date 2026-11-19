//go:build lab

package read_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// T-2343 AC1-AC4 on Samba AD: msDS-ReplAttributeMetaData time of mail/mobile/otherMobile, and the exact
// sign-in-name resolver. Samba 4.22 does NOT serve the constructed msDS-ReplAttributeMetaData over LDAP
// (only replPropertyMetaData), so the metadata test skips with a reason when the DC lacks it; the
// decode is proven offline and the Windows DC behaviour is T-2346's.
//
//	make lab-up && go test -tags lab ./internal/connector/read -run TestLabAttrChange
func TestLabAttrChangeTimes(t *testing.T) {
	l := newSearchLab(t)
	ou := "OU=attrchg-" + l.stamp + "," + labDom
	l.add(t, ou, map[string][]string{"objectClass": {"organizationalUnit"}})
	t.Cleanup(func() { l.delTree(ou) })
	udn := "CN=Chg\\, " + l.stamp + "," + ou
	l.add(t, udn, map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"chg" + l.stamp}, "mail": {"a@x.test"}, "mobile": {"+1 555 0100"}})
	time.Sleep(2 * time.Second)
	mod := ldap.NewModifyRequest(udn, nil)
	mod.Replace("mail", []string{"b@x.test"})
	mod.Add("otherMobile", []string{"+1 555 0101"})
	if err := l.adm.Modify(mod); err != nil {
		t.Fatal(err)
	}
	if !servesAttrMetaData(t, l, udn) {
		t.Skip("this DC does not serve msDS-ReplAttributeMetaData over LDAP (Samba); Windows lab: T-2346")
	}
	g, err := guid.FromBytes(guidBytes(t, l, udn))
	if err != nil {
		t.Fatal(err)
	}
	got, err := l.src.AttrChangeTimes(context.Background(), g, []string{"mail", "mobile", "otherMobile", "telephoneNumber"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, n := range []string{"mail", "mobile", "otherMobile"} {
		if !got[n].Known || now.Sub(got[n].At) > time.Minute || got[n].At.After(now.Add(time.Minute)) {
			t.Errorf("%s = %+v (now %v)", n, got[n], now)
		}
	}
	if !got["mail"].At.After(got["mobile"].At) {
		t.Errorf("mail (changed later) %v must be after mobile %v: independent times", got["mail"].At, got["mobile"].At)
	}
	if got["telephoneNumber"].Known {
		t.Errorf("never-set attribute must be unknown: %+v", got["telephoneNumber"])
	}
}

func TestLabResolveSignInName(t *testing.T) {
	l := newSearchLab(t)
	ou := "OU=signin-" + l.stamp + "," + labDom
	l.add(t, ou, map[string][]string{"objectClass": {"organizationalUnit"}})
	t.Cleanup(func() { l.delTree(ou) })
	mk := func(cn, sam, upn, uac string) {
		attrs := map[string][]string{"objectClass": {"user"}, "sAMAccountName": {sam}, "userPrincipalName": {upn}}
		l.add(t, "CN="+cn+","+ou, attrs)
		if uac != "" {
			m := ldap.NewModifyRequest("CN="+cn+","+ou, nil)
			m.Replace("userAccountControl", []string{uac})
			if err := l.adm.Modify(m); err != nil {
				t.Fatal(err)
			}
		}
	}
	s := l.stamp
	mk("ok"+s, "ok"+s, "ok"+s+"@lab.activediq.test", "512")
	mk("off"+s, "off"+s, "off"+s+"@lab.activediq.test", "514")
	// Ambiguity (two matches) cannot be built on Samba, which refuses a UPN prefix equal to another
	// sAMAccountName; it is unit-tested through the search seam (TestUniqueSignIn).
	ctx := context.Background()

	u, err := l.src.ResolveSignInName(ctx, "OK"+s)
	if err != nil || u.SAMAccountName != "ok"+s {
		t.Fatalf("sAMAccountName (any case): %+v %v", u, err)
	}
	if u2, err := l.src.ResolveSignInName(ctx, "ok"+s+"@lab.activediq.test"); err != nil || u2.GUID != u.GUID {
		t.Fatalf("UPN: %+v %v", u2, err)
	}
	if u.Disabled || u.Expired {
		t.Errorf("flags of an enabled user: %+v", u)
	}
	if off, err := l.src.ResolveSignInName(ctx, "off"+s); err != nil || !off.Disabled {
		t.Errorf("disabled: %+v %v", off, err)
	}
	for _, bad := range []string{"ok*", "*", "nobody" + s, "ok" + s + ")(objectClass=*"} {
		if _, err := l.src.ResolveSignInName(ctx, bad); ad.CodeOf(err) != ad.CodeObjectNotFound {
			t.Errorf("%q: err = %v, want not found", bad, err)
		}
	}
}

func guidBytes(t *testing.T, l *searchLab, dn string) []byte {
	t.Helper()
	r, err := l.adm.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("guid of %s: %v", dn, err)
	}
	return r.Entries[0].GetRawAttributeValue("objectGUID")
}

func servesAttrMetaData(t *testing.T, l *searchLab, dn string) bool {
	t.Helper()
	r, err := l.adm.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"msDS-ReplAttributeMetaData"}, nil))
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("metadata probe of %s: %v", dn, err)
	}
	return len(r.Entries[0].GetRawAttributeValues("msDS-ReplAttributeMetaData")) > 0
}
