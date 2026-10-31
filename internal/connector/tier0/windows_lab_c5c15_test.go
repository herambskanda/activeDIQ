//go:build lab && windowslab

package tier0

// T-0226: Windows-lab verification of the AD tier0 classifier (C5, C8, C9, C11, C12, C15).
// Run: `make lab-test-connector-windows` style env (WIN_LAB_MODE=external WIN_LAB_DC_ADDR=… WIN_LAB_TLS_NAME=…) then
//   go test -count=1 -tags 'lab windowslab' ./internal/connector/tier0 -run TestWindowsLab -v
// Fixtures are created as Administrator under a throwaway OU and removed afterwards; classification runs as the
// delegated svc-activediq account (the identity the product uses). Nothing is skipped when the lab is missing.
// Gaps that this lab cannot cover (single DC, no RODC, single domain) are listed in the runbook, not faked here.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// wConf is the forest Configuration NC; the domain head is the shared winDom (win_lab_helper_test.go).
const wConf = "CN=Configuration," + winDom

func wClassify(t *testing.T, ctx context.Context, c *ADClassifier, dnStr string) ADResult {
	t.Helper()
	ref, err := dn.ParseObjectRef(dnStr)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Classify(ctx, ref, ADInput{CorrelationKnown: true})
	if err != nil {
		t.Fatalf("classify %s: %v", dnStr, err)
	}
	return r
}

func wWant(t *testing.T, ctx context.Context, c *ADClassifier, dnStr string, want Basis) {
	t.Helper()
	if r := wClassify(t, ctx, c, dnStr); !r.Tier0 || r.Unknown || !has(r, want) {
		t.Errorf("%s: want tier0 with %v, got %+v", dnStr, want, r)
	}
}

func wWantPlain(t *testing.T, ctx context.Context, c *ADClassifier, dnStr string) {
	t.Helper()
	if r := wClassify(t, ctx, c, dnStr); r.Tier0 || r.Unknown {
		t.Errorf("%s: plain object classified tier0: %+v", dnStr, r)
	}
}

func wSearch(t *testing.T, c *ldap.Conn, base string, scope int, filter string, attrs ...string) []*ldap.Entry {
	t.Helper()
	r, err := c.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil))
	if err != nil {
		t.Fatalf("search %s %s: %v", base, filter, err)
	}
	return r.Entries
}

func wAddUser(t *testing.T, c *ldap.Conn, parent, name string) (dnStr string, sidRaw []byte) {
	t.Helper()
	dnStr = "CN=" + name + "," + parent
	a := ldap.NewAddRequest(dnStr, nil)
	a.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	a.Attribute("sAMAccountName", []string{name})
	a.Attribute("userAccountControl", []string{"514"}) // disabled: no password needed
	if err := c.Add(a); err != nil {
		t.Fatalf("add %s: %v", dnStr, err)
	}
	t.Cleanup(func() { _ = c.Del(ldap.NewDelRequest(dnStr, nil)) })
	es := wSearch(t, c, dnStr, ldap.ScopeBaseObject, "(objectClass=*)", "objectSid")
	if len(es) != 1 {
		t.Fatalf("no entry for %s", dnStr)
	}
	return dnStr, es[0].GetRawAttributeValue("objectSid")
}

func guidBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		t.Fatalf("bad guid %q", s)
	}
	// text → mixed-endian wire form
	out := make([]byte, 16)
	out[0], out[1], out[2], out[3] = b[3], b[2], b[1], b[0]
	out[4], out[5] = b[5], b[4]
	out[6], out[7] = b[7], b[6]
	copy(out[8:], b[8:])
	return out
}

// aceObject builds an ACCESS_ALLOWED_OBJECT_ACE (control access on a right GUID) for sid.
func aceObject(right, sidRaw []byte, mask uint32) []byte {
	size := 4 + 4 + 4 + 16 + len(sidRaw)
	a := make([]byte, 0, size)
	a = append(a, 0x05, 0)
	a = binary.LittleEndian.AppendUint16(a, uint16(size))
	a = binary.LittleEndian.AppendUint32(a, mask)
	a = binary.LittleEndian.AppendUint32(a, 1) // ACE_OBJECT_TYPE_PRESENT
	a = append(a, right...)
	return append(a, sidRaw...)
}

// aceAllow builds an ACCESS_ALLOWED_ACE.
func aceAllow(sidRaw []byte, mask uint32) []byte {
	size := 8 + len(sidRaw)
	a := []byte{0, 0}
	a = binary.LittleEndian.AppendUint16(a, uint16(size))
	a = binary.LittleEndian.AppendUint32(a, mask)
	return append(a, sidRaw...)
}

// lSDWithDACL builds a self-relative SD holding only a DACL of the given ACEs.
func lSDWithDACL(aces ...[]byte) []byte {
	acl := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	for _, a := range aces {
		acl = append(acl, a...)
	}
	binary.LittleEndian.PutUint16(acl[2:], uint16(len(acl)))
	binary.LittleEndian.PutUint16(acl[4:], uint16(len(aces)))
	// Owner BUILTIN\Administrators: AD rejects an SD attribute value without an owner.
	owner := []byte{1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0}
	h := make([]byte, 20)
	h[0] = 1
	binary.LittleEndian.PutUint16(h[2:], 0x8004) // SE_DACL_PRESENT | SE_SELF_RELATIVE
	binary.LittleEndian.PutUint32(h[4:], 20)
	binary.LittleEndian.PutUint32(h[16:], uint32(20+len(owner)))
	return append(append(h, owner...), acl...)
}

// daclControl is the SD_FLAGS control (DACL only) so reads and writes touch just the DACL.
func daclControl() ldap.Control {
	return ldap.NewControlString("1.2.840.113556.1.4.801", true, "\x30\x03\x02\x01\x04")
}

// lAppendACE appends ace to the DACL of obj and returns the original SD for restoring.
func lAppendACE(t *testing.T, c *ldap.Conn, obj string, ace []byte) {
	t.Helper()
	r, err := c.Search(ldap.NewSearchRequest(obj, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"nTSecurityDescriptor"}, []ldap.Control{daclControl()}))
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("read DACL %s: %v", obj, err)
	}
	orig := r.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	daclOff := int(binary.LittleEndian.Uint32(orig[16:]))
	if len(orig) < 28 || daclOff != 20 || daclOff+int(binary.LittleEndian.Uint16(orig[daclOff+2:])) != len(orig) {
		t.Fatalf("unexpected SD layout for %s (len %d, dacl %d)", obj, len(orig), daclOff)
	}
	nsd := append(append([]byte{}, orig...), ace...)
	binary.LittleEndian.PutUint16(nsd[daclOff+2:], uint16(len(nsd)-daclOff))
	binary.LittleEndian.PutUint16(nsd[daclOff+4:], binary.LittleEndian.Uint16(nsd[daclOff+4:])+1)
	put := func(sd []byte) error {
		m := ldap.NewModifyRequest(obj, []ldap.Control{daclControl()})
		m.Replace("nTSecurityDescriptor", []string{string(sd)})
		return c.Modify(m)
	}
	if err := put(nsd); err != nil {
		t.Fatalf("write DACL %s: %v", obj, err)
	}
	t.Cleanup(func() {
		if err := put(orig); err != nil {
			t.Errorf("RESTORE DACL of %s FAILED, lab needs `qm rollback`: %v", obj, err)
		}
	})
}

func wFixtureOU(t *testing.T, c *ldap.Conn) string {
	t.Helper()
	ou := fmt.Sprintf("OU=t0226-%d,%s", time.Now().UnixNano()%1_000_000, winDom)
	a := ldap.NewAddRequest(ou, nil)
	a.Attribute("objectClass", []string{"top", "organizationalUnit"})
	if err := c.Add(a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Del(ldap.NewDelRequest(ou, nil)); err != nil {
			t.Errorf("cleanup %s: %v", ou, err)
		}
	})
	return ou
}

// Anchors that exist in any Windows forest: DC computer (C5), its site (C15), and plain-object negatives.
func TestWindowsLabC5C15(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	l := newWinLab(t)
	adm, c := l.admin, l.cls
	dcs := wSearch(t, adm, "OU=Domain Controllers,"+winDom, ldap.ScopeSingleLevel, "(objectClass=computer)", "distinguishedName")
	if len(dcs) == 0 {
		t.Fatal("no DC computer in OU=Domain Controllers")
	}
	for _, e := range dcs {
		wWant(t, ctx, c, e.DN, C5)
	}
	wWant(t, ctx, c, "CN=Default-First-Site-Name,CN=Sites,"+wConf, C15)
	ou := wFixtureOU(t, adm)
	u, _ := wAddUser(t, adm, ou, "t0226-plain")
	wWantPlain(t, ctx, c, u)
}

// C8 on a real forest: the KDS root-key container and keys under it, the CN=System sensitive objects.
func TestWindowsLabC8(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	l := newWinLab(t)
	adm, c := l.admin, l.cls
	kds := "CN=Group Key Distribution Service,CN=Services," + wConf
	if len(wSearch(t, adm, kds, ldap.ScopeBaseObject, "(objectClass=*)", "cn")) != 1 {
		t.Fatal("KDS container absent")
	}
	wWant(t, ctx, c, kds, C8)
	// A child of the KDS container stands in for a root key (creating a real one needs Add-KdsRootKey).
	child := "CN=t0226-rootkeys," + kds
	a := ldap.NewAddRequest(child, nil)
	a.Attribute("objectClass", []string{"top", "container"})
	if err := adm.Add(a); err != nil {
		t.Fatalf("add under KDS container: %v", err)
	}
	t.Cleanup(func() { _ = adm.Del(ldap.NewDelRequest(child, nil)) })
	wWant(t, ctx, c, child, C8)
	for _, rel := range []string{"CN=System," + winDom, "CN=RID Manager$,CN=System," + winDom,
		"CN=Directory Service,CN=Windows NT,CN=Services," + wConf} {
		wWant(t, ctx, c, rel, C8)
	}
	// The Password Settings Container's default ACL hides it from the delegated service account (no readable
	// objectGUID): the classifier must fail closed (an error / Unknown), never answer "plain".
	psc, perr := dn.ParseObjectRef("CN=Password Settings Container,CN=System," + winDom)
	if perr != nil {
		t.Fatal(perr)
	}
	if r, err := c.Classify(ctx, psc, ADInput{CorrelationKnown: true}); err == nil && !(r.Tier0 && has(r, C8)) {
		t.Errorf("Password Settings Container neither C8 nor fail-closed: %+v", r)
	} else if err != nil && !r.Tier0 {
		t.Errorf("error without fail-closed tier0: %+v %v", r, err)
	}
	// Negatives: a neighbouring CN=System container that is not in the list, and a user.
	wWantPlain(t, ctx, c, "CN=Policies,CN=System,"+winDom+"")
}

// C11: a principal with Get-Changes + Get-Changes-All on the live domain-root DACL; one with only Get-Changes is not.
func TestWindowsLabC11(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	l := newWinLab(t)
	adm := l.admin
	ou := wFixtureOU(t, adm)
	both, bothSID := wAddUser(t, adm, ou, "t0226-dcsync")
	half, halfSID := wAddUser(t, adm, ou, "t0226-halfsync")
	getChanges := guidBytes(t, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
	getAll := guidBytes(t, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
	lAppendACE(t, adm, winDom, aceObject(getChanges, bothSID, 0x100))
	lAppendACE(t, adm, winDom, aceObject(getAll, bothSID, 0x100))
	lAppendACE(t, adm, winDom, aceObject(getChanges, halfSID, 0x100))
	c := l.cls
	wWant(t, ctx, c, both, C11)
	wWantPlain(t, ctx, c, half)
}

// C12: RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) on a DC marks the trustee; a bystander is not marked.
func TestWindowsLabC12(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	l := newWinLab(t)
	adm := l.admin
	ou := wFixtureOU(t, adm)
	trustee, tSID := wAddUser(t, adm, ou, "t0226-rbcd")
	bystander, _ := wAddUser(t, adm, ou, "t0226-bystander")
	dcs := wSearch(t, adm, "OU=Domain Controllers,"+winDom, ldap.ScopeSingleLevel, "(objectClass=computer)", "distinguishedName")
	if len(dcs) == 0 {
		t.Fatal("no DC")
	}
	dc := dcs[0].DN
	m := ldap.NewModifyRequest(dc, nil)
	m.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(lSDWithDACL(aceAllow(tSID, 0xF01FF)))})
	if err := adm.Modify(m); err != nil {
		t.Fatalf("set RBCD on %s: %v", dc, err)
	}
	t.Cleanup(func() {
		r := ldap.NewModifyRequest(dc, nil)
		r.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", nil)
		if err := adm.Modify(r); err != nil {
			t.Errorf("RESTORE RBCD on %s FAILED: %v", dc, err)
		}
	})
	c := l.cls
	wWant(t, ctx, c, trustee, C12)
	wWantPlain(t, ctx, c, bystander)
}

// C9: a GPO linked at the Domain Controllers OU (a tier0 start of authority) is tier0; an unlinked GPO is not.
func TestWindowsLabC9(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	l := newWinLab(t)
	adm := l.admin
	pol := "CN=Policies,CN=System," + winDom
	mk := func(id string) string {
		d := "CN={" + id + "}," + pol
		a := ldap.NewAddRequest(d, nil)
		a.Attribute("objectClass", []string{"top", "container", "groupPolicyContainer"})
		a.Attribute("displayName", []string{"t0226 " + id})
		a.Attribute("flags", []string{"0"})
		a.Attribute("versionNumber", []string{"0"})
		a.Attribute("gPCFileSysPath", []string{`\\win.activediq.test\SysVol\win.activediq.test\Policies\{` + id + `}`})
		a.Attribute("gPCFunctionalityVersion", []string{"2"})
		if err := adm.Add(a); err != nil {
			t.Fatalf("add GPO %s: %v", id, err)
		}
		t.Cleanup(func() { _ = adm.Del(ldap.NewDelRequest(d, nil)) })
		return d
	}
	n := time.Now().UnixNano() % 1_000_000_000
	linked := mk(fmt.Sprintf("0226A%03d-0000-4000-8000-%012d", n%1000, n))
	unlinked := mk(fmt.Sprintf("0226B%03d-0000-4000-8000-%012d", n%1000, n))

	dcOU := "OU=Domain Controllers," + winDom
	es := wSearch(t, adm, dcOU, ldap.ScopeBaseObject, "(objectClass=*)", "gPLink")
	orig := es[0].GetAttributeValue("gPLink")
	link := "[LDAP://" + linked + ";0]"
	m := ldap.NewModifyRequest(dcOU, nil)
	m.Replace("gPLink", []string{orig + link})
	if err := adm.Modify(m); err != nil {
		t.Fatalf("link GPO: %v", err)
	}
	t.Cleanup(func() {
		r := ldap.NewModifyRequest(dcOU, nil)
		if orig == "" {
			r.Replace("gPLink", nil)
		} else {
			r.Replace("gPLink", []string{orig})
		}
		if err := adm.Modify(r); err != nil {
			t.Errorf("RESTORE gPLink on %s FAILED: %v", dcOU, err)
		}
	})
	c := l.cls
	wWant(t, ctx, c, linked, C9)
	wWantPlain(t, ctx, c, unlinked)
}
