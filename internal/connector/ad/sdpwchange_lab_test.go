//go:build lab

package ad

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

type oneRight map[guid.GUID]sd.RightKind

func (m oneRight) Kind(g guid.GUID) (sd.RightKind, bool) { k, ok := m[g]; return k, ok }

// TestLabReadPasswordChange (T-1019, AC1) reads real nTSecurityDescriptors from Samba: a user given the two
// Cannot Change Password deny ACEs reads Blocked, a user with one reads Blocked (one deny ACE only),
// and a fresh user, whose default DACL has the allow ACEs for Everyone and SELF, reads No deny ACE. The
// userAccountControl bit is not consulted anywhere. The deny ACEs are written through the real DACL
// write path (PlanDACL + WriteDACL), so the bytes read back are what Samba stored. Samba proves the LDAP
// mechanics and the decode of the bytes it stores; it does not prove the Windows tools' ACE shape or
// Windows ACL ordering (windows-lab test, follow-up).
func TestLabReadPasswordChange(t *testing.T) {
	adm, cfg := labAdmin(t)
	env := labEnv(t)
	cfg.Credential = Credential{BindName: "Administrator@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_ADMIN_PASSWORD"]))}
	s := labOpen(t, cfg)
	ctx := context.Background()

	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	adminSID := adminSIDOf(t, adm, "CN=Administrator,CN=Users,"+labBase)
	dom, _ := adminSID.DomainSID()
	da, _ := sid.Parse(dom.String() + "-512")
	everyone, _ := sid.Parse("S-1-1-0")
	self, _ := sid.Parse("S-1-5-10")
	cp, _ := guid.Parse("ab721a53-1e2f-11d0-9819-00aa0040529b")
	cat := oneRight{cp: sd.ControlAccess}

	mkUser := func(name string, uac string) (dn.ObjectRef, guid.GUID) {
		d := "CN=" + name + stamp + "," + labBase
		adminAdd(t, adm, d, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
			"sAMAccountName": {name + stamp}, "userAccountControl": {uac}})
		t.Cleanup(func() { _ = adm.Del(ldap.NewDelRequest(d, nil)) })
		pd, err := dn.Parse(d, dn.Strict)
		if err != nil {
			t.Fatal(err)
		}
		return dn.DNRef(pd), adminGUID(t, adm, d)
	}
	deny := func(ref dn.ObjectRef, g guid.GUID, trustees ...sid.SID) {
		t.Helper()
		_, base, err := s.ReadDACL(ctx, ref)
		if err != nil {
			t.Fatal(err)
		}
		var add []sd.NewACE
		for _, tr := range trustees {
			add = append(add, sd.NewACE{Deny: true, Trustee: tr, Mask: sd.MaskControlAccess, ObjectType: &cp})
		}
		w, _, err := sd.PlanDACL(base, sd.ACEDiff{Add: add}, cat,
			sd.ObjectCtx{ObjectGUID: g, Connector: sd.PrincipalFromSIDs(adminSID, da)}, sd.PlanOpts{})
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		if err := s.WriteDACL(ctx, ref, w, labReplaceSD); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// 514 = NORMAL_ACCOUNT | ACCOUNTDISABLE (no password needed). The bit 0x40 (PASSWD_CANT_CHANGE,
	// which AD ignores) is set on the "bit only" user to prove the bit is not what is read.
	bothRef, bothG := mkUser("t1019both", "514")
	oneRef, oneG := mkUser("t1019one", "514")
	noneRef, noneG := mkUser("t1019none", "514")
	bitRef, bitG := mkUser("t1019bit", strconv.Itoa(514|0x40))
	deny(bothRef, bothG, everyone, self)
	deny(oneRef, oneG, self)

	for _, c := range []struct {
		name string
		ref  dn.ObjectRef
		g    guid.GUID
		want sd.PasswordChange
	}{
		{"both denies", bothRef, bothG, sd.PasswordChangeBlocked},
		{"one deny", oneRef, oneG, sd.PasswordChangeBlockedOneACE},
		{"default DACL", noneRef, noneG, sd.PasswordChangeNoDenyACE},
		{"UAC bit only", bitRef, bitG, sd.PasswordChangeNoDenyACE},
	} {
		g, got, err := s.ReadPasswordChange(ctx, c.ref)
		if err != nil || got != c.want || g != c.g {
			t.Errorf("%s: state=%v guid-match=%v err=%v, want %v", c.name, got, g == c.g, err, c.want)
		}
	}

	// AC2 against a real directory: an object that does not exist is a typed error, not a state.
	gone, err := dn.Parse("CN=t1019gone"+stamp+","+labBase, dn.Strict)
	if err != nil {
		t.Fatal(err)
	}
	if _, got, err := s.ReadPasswordChange(ctx, dn.DNRef(gone)); err == nil || got != sd.PasswordChangeNotConfirmed {
		t.Fatalf("missing object: state=%v err=%v", got, err)
	}
}
