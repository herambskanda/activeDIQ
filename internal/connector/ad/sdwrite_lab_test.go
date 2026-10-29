//go:build lab

package ad

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// TestLabWriteDACL (T-0743) runs Session.WriteDACL against Samba: a valid plan lands one ACE and the DACL
// read back through the same session holds it; replaying the same plan is sd.stale_base and changes
// nothing; the zero write is refused. Samba proves the LDAP mechanics (control, replace, VerifyBase);
// it does not prove Windows re-sorting or SDProp (windows-lab tests, T-0606).
func TestLabWriteDACL(t *testing.T) {
	adm, cfg := labAdmin(t)
	env := labEnv(t)
	cfg.Credential = Credential{BindName: "Administrator@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_ADMIN_PASSWORD"]))}
	s := labOpen(t, cfg)

	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	grp := "CN=t0743g" + stamp + "," + labBase
	trusteeDN := "CN=t0743t" + stamp + "," + labBase
	for i, d := range []string{grp, trusteeDN} {
		adminAdd(t, adm, d, map[string][]string{"objectClass": {"top", "group"}, "sAMAccountName": {"t0743" + stamp + strconv.Itoa(i)}, "groupType": {"-2147483646"}})
		d := d
		t.Cleanup(func() { _ = adm.Del(ldap.NewDelRequest(d, nil)) })
	}
	trustee := adminSIDOf(t, adm, trusteeDN)
	adminSID := adminSIDOf(t, adm, "CN=Administrator,CN=Users,"+labBase)
	dom, _ := adminSID.DomainSID()
	da, _ := sid.Parse(dom.String() + "-512")
	g := adminGUID(t, adm, grp)
	gd, err := dn.Parse(grp, dn.Strict)
	if err != nil {
		t.Fatal(err)
	}
	ref := dn.DNRef(gd)

	readDACL := func() sd.SD {
		e, err := s.Read(context.Background(), ref, []string{"nTSecurityDescriptor"}, ReadOptions{SD: mustFlags(t, SDDACL)})
		if err != nil {
			t.Fatal(err)
		}
		v, err := sd.Decode(sd.Raw(e.Raw("nTSecurityDescriptor")[0]))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := readDACL()
	w, _, err := sd.PlanDACL(before, sd.ACEDiff{Add: []sd.NewACE{{Trustee: trustee, Mask: sd.MaskReadProp}}}, nil,
		sd.ObjectCtx{ObjectGUID: g, Connector: sd.PrincipalFromSIDs(adminSID, da)}, sd.PlanOpts{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	ctx := context.Background()
	if err := s.WriteDACL(ctx, ref, sd.DACLWrite{}); CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("zero write: %v", err)
	}
	if err := s.WriteDACL(ctx, ref, w); err != nil {
		t.Fatalf("WriteDACL: %v", err)
	}
	after := readDACL()
	if _, err := w.VerifyAfter(after); err != nil {
		t.Fatalf("read-back differs from plan: %v", err)
	}
	if len(after.DACL.ACEs) != len(before.DACL.ACEs)+1 {
		t.Fatalf("ACE count %d -> %d", len(before.DACL.ACEs), len(after.DACL.ACEs))
	}
	// The base moved: the same plan is stale and nothing is sent.
	err = s.WriteDACL(ctx, ref, w)
	if codec.Code(err) != sd.ErrStaleBase {
		t.Fatalf("replay: want %s, got %v", sd.ErrStaleBase, err)
	}
	if got := readDACL(); sd.DigestDACL(got) != sd.DigestDACL(after) {
		t.Fatal("stale write changed the DACL")
	}
}

func mustFlags(t *testing.T, p ...SDPart) SDFlags {
	t.Helper()
	f, err := NewSDFlags(p...)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func adminSIDOf(t *testing.T, adm *ldap.Conn, d string) sid.SID {
	t.Helper()
	res, err := adm.Search(ldap.NewSearchRequest(d, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectSid"}, nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("sid of %s: %v", d, err)
	}
	v, err := sid.FromBytes(res.Entries[0].GetRawAttributeValue("objectSid"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}
