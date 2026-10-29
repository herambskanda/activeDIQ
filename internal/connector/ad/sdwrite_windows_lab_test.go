//go:build lab && windowslab

// Windows-lab verification of the assumptions the SD write half (internal/directory/sd, T-0583) makes and
// Samba cannot prove (T-0606): SDProp reverts a DACL write on a protected object (SD-E11); clearing PD
// makes the DC recompute inherited ACEs (RestoreInheritance) and BlockKeep/BlockRemove behave as the plan
// says; the INHERITED marker survives a DACL write; a DACL-only SD_FLAGS write needs no SeSecurityPrivilege
// and leaves owner/group/SACL alone; whether an inherit-only OWNER RIGHTS / owner ACE strips the owner's
// implicit WRITE_DAC (planner SD-W26/W27 fail closed until this is known).
//
// Every test builds its objects under OU=Managed, writes with the product's own planners
// (sd.PlanDACL / sd.PlanInheritance) over verified LDAPS, reads back with the DACL-only SD_FLAGS control,
// and prints `RESULT …` lines that the results log quotes. Run: make lab-test-connector-windows
// (filter ^TestWindowsLab includes TestWindowsLabSDWrite*). Results: windows-lab-runs/sdwrite-assumptions-*.md.
package ad

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

const (
	sdvManaged = "OU=Managed," + winBase
	sdvWait    = 90 * time.Second
)

type sdvLab struct {
	admin, svc       *ldap.Conn
	adminSID, svcSID sid.SID
	dnSuffix         string
}

func sdvDial(t *testing.T) *sdvLab {
	t.Helper()
	host := os.Getenv("WIN_LAB_DC_ADDR")
	if host == "" {
		host = "192.168.77.10"
	}
	pem, err := os.ReadFile(winLabPath("WIN_LAB_CA", ".win-lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad windows lab CA")
	}
	env := winEnv(t)
	dial := func(who, pw string) *ldap.Conn {
		c, err := ldap.DialURL("ldaps://"+host+":636", ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: winTLSName(), MinVersion: tls.VersionTLS12}))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		if err := c.Bind(who, pw); err != nil {
			t.Fatalf("bind %s: %v", who, err)
		}
		return c
	}
	l := &sdvLab{admin: dial("Administrator@win.activediq.test", env["WIN_LAB_ADMIN_PASSWORD"]), svc: dial(winBind, env["WIN_LAB_SVC_PASSWORD"])}
	l.adminSID = l.objectSID(t, "CN=Administrator,CN=Users,"+winBase)
	l.svcSID = l.objectSID(t, l.findDN(t, "svc-activediq"))
	return l
}

// findDN resolves a sAMAccountName to its DN (the lab does not fix where the service account lives).
func (l *sdvLab) findDN(t *testing.T, sam string) string {
	t.Helper()
	r, err := l.admin.Search(ldap.NewSearchRequest(winBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(sAMAccountName="+ldap.EscapeFilter(sam)+")", []string{"distinguishedName"}, nil))
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("find %s: %v (%v)", sam, err, r)
	}
	return r.Entries[0].DN
}

func (l *sdvLab) objectSID(t *testing.T, dn string) sid.SID {
	t.Helper()
	r, err := l.admin.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectSid"}, nil))
	if err != nil {
		t.Fatalf("objectSid %s: %v", dn, err)
	}
	s, err := sid.FromBytes(r.Entries[0].GetRawAttributeValue("objectSid"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (l *sdvLab) objectGUID(t *testing.T, dn string) guid.GUID {
	t.Helper()
	r, err := l.admin.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
	if err != nil {
		t.Fatalf("objectGUID %s: %v", dn, err)
	}
	g, err := guid.FromBytes(r.Entries[0].GetRawAttributeValue("objectGUID"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// adminPrincipal is the token the planner reasons about for the Administrator connector.
func (l *sdvLab) adminPrincipal(t *testing.T) sd.Principal {
	t.Helper()
	dom, ok := l.adminSID.DomainSID()
	if !ok {
		t.Fatal("administrator SID has no domain part")
	}
	da, err := sid.Parse(dom.String() + "-512")
	if err != nil {
		t.Fatal(err)
	}
	return sd.PrincipalFromSIDs(l.adminSID, da)
}

// flagsCtl is the SD_FLAGS control value for the given SECURITY_INFORMATION bits (1 owner, 2 group, 4 DACL, 8 SACL).
func flagsCtl(bits byte) ldap.Control {
	return ldap.NewControlString(sd.SDFlagsOID, true, string([]byte{0x30, 0x03, 0x02, 0x01, bits}))
}

// readRaw reads nTSecurityDescriptor of dn with SD_FLAGS bits as conn.
func readRaw(conn *ldap.Conn, dn string, bits byte) ([]byte, error) {
	r, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"nTSecurityDescriptor"}, []ldap.Control{flagsCtl(bits)}))
	if err != nil {
		return nil, err
	}
	if len(r.Entries) != 1 {
		return nil, fmt.Errorf("%d entries", len(r.Entries))
	}
	return r.Entries[0].GetRawAttributeValue("nTSecurityDescriptor"), nil
}

func (l *sdvLab) readSD(t *testing.T, dn string, bits byte) sd.SD {
	t.Helper()
	b, err := readRaw(l.admin, dn, bits)
	if err != nil {
		t.Fatalf("read SD %s (flags %d): %v", dn, bits, err)
	}
	s, err := sd.Decode(sd.Raw(b))
	if err != nil {
		t.Fatalf("decode SD %s: %v (%x)", dn, err, b)
	}
	return s
}

func sdvCode(err error) int {
	var le *ldap.Error
	if errors.As(err, &le) {
		return int(le.ResultCode)
	}
	return -1
}

// send writes a planned DACL as conn, exactly as the product would: planner value, planner control.
func send(conn *ldap.Conn, dn string, w sd.DACLWrite) error {
	c := w.Control()
	m := ldap.NewModifyRequest(dn, []ldap.Control{ldap.NewControlString(c.OID, c.Critical, string(c.Value))})
	m.Replace("nTSecurityDescriptor", []string{string(w.Value())})
	return conn.Modify(m)
}

func (l *sdvLab) add(t *testing.T, dn string, conn *ldap.Conn, class []string, attrs map[string][]string) {
	t.Helper()
	// Cleanup always runs as admin: objects the service account created are later locked down (PD, no inherited
	// ACEs) and it can no longer delete them.
	_ = l.admin.Del(ldap.NewDelRequest(dn, nil)) // leftovers of a crashed run
	a := ldap.NewAddRequest(dn, nil)
	a.Attribute("objectClass", class)
	for k, v := range attrs {
		a.Attribute(k, v)
	}
	if err := conn.Add(a); err != nil {
		t.Fatalf("create %s: %v", dn, err)
	}
	t.Cleanup(func() { _ = l.admin.Del(ldap.NewDelRequest(dn, nil)) })
}

func (l *sdvLab) user(t *testing.T, dn, sam string, conn *ldap.Conn) {
	t.Helper()
	l.add(t, dn, conn, []string{"top", "person", "organizationalPerson", "user"}, map[string][]string{"sAMAccountName": {sam}})
}

func (l *sdvLab) ou(t *testing.T, dn string) {
	t.Helper()
	l.add(t, dn, l.admin, []string{"top", "organizationalUnit"}, nil)
}

// grp creates a security group used only as an ACE trustee and returns its SID.
func (l *sdvLab) grp(t *testing.T, name string) sid.SID {
	t.Helper()
	dn := "CN=" + name + ",OU=Managed," + winBase
	l.add(t, dn, l.admin, []string{"top", "group"}, map[string][]string{"sAMAccountName": {name}, "groupType": {"-2147483646"}})
	return l.objectSID(t, dn)
}

// planAdd plans one allow ACE onto dn (read fresh as admin).
func (l *sdvLab) planAdd(t *testing.T, dn string, trustee sid.SID, mask uint32, flags uint8, protected bool) sd.DACLWrite {
	t.Helper()
	w, _, err := sd.PlanDACL(l.readSD(t, dn, 4), sd.ACEDiff{Add: []sd.NewACE{{Trustee: trustee, Mask: mask, Flags: flags}}}, nil,
		sd.ObjectCtx{ObjectGUID: l.objectGUID(t, dn), ProtectedBySDProp: protected, Connector: l.adminPrincipal(t)}, sd.PlanOpts{})
	if err != nil {
		t.Fatalf("PlanDACL %s: %v", dn, err)
	}
	return w
}

func (l *sdvLab) planInh(t *testing.T, dn string, op sd.InheritanceOp) sd.DACLWrite {
	t.Helper()
	w, _, err := sd.PlanInheritance(l.readSD(t, dn, 4), op, sd.ObjectCtx{ObjectGUID: l.objectGUID(t, dn), Connector: l.adminPrincipal(t)})
	if err != nil {
		t.Fatalf("PlanInheritance %s: %v", dn, err)
	}
	return w
}

// eventually polls cond until it holds or the deadline passes (a condition wait, not a sleep).
func eventually(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s", d, what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// has reports whether the DACL holds an allow ACE for trustee with the given inherited state.
func has(s sd.SD, trustee sid.SID, inherited bool) int {
	n := 0
	for _, a := range s.DACL.ACEs {
		if a.Kind != sd.Opaque && a.Trustee == trustee && a.Inherited() == inherited {
			n++
		}
	}
	return n
}

func summary(s sd.SD) string {
	var p []string
	for _, a := range s.DACL.ACEs {
		p = append(p, fmt.Sprintf("%02x/%02x/%08x/%s", a.Type, a.Flags, a.Mask, a.Trustee))
	}
	return fmt.Sprintf("ctl=%#04x n=%d [%s]", uint16(s.Control), len(p), strings.Join(p, " "))
}

// explicitSet is the sorted multiset of (type,mask,trustee) of the non-inherited ACEs, ignoring flag bits that
// legitimately change (INHERITED).
func shapeSet(s sd.SD, inherited bool) []string {
	var out []string
	for _, a := range s.DACL.ACEs {
		if a.Inherited() == inherited {
			out = append(out, fmt.Sprintf("%02x/%08x/%s", a.Type, a.Mask, a.Trustee))
		}
	}
	sort.Strings(out)
	return out
}

// orderOf is the ordered (type,mask,trustee) list of a DACL, flags ignored.
func orderOf(s sd.SD) []string {
	var out []string
	for _, a := range s.DACL.ACEs {
		out = append(out, fmt.Sprintf("%02x/%08x/%s", a.Type, a.Mask, a.Trustee))
	}
	return out
}

// plannedSD decodes the DACL-only value of a plan (what the connector will send).
func plannedSD(t *testing.T, w sd.DACLWrite) sd.SD {
	t.Helper()
	s, err := sd.Decode(w.Value())
	if err != nil {
		t.Fatalf("decode planned value: %v", err)
	}
	return s
}

// firstDiff names the first index where two ordered lists differ ("" when equal).
func firstDiff(a, b []string) string {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return fmt.Sprintf("first difference at ACE %d: planned %s, stored %s", i, a[i], b[i])
		}
	}
	if len(a) != len(b) {
		return fmt.Sprintf("length planned %d, stored %d", len(a), len(b))
	}
	return ""
}

// verifyAfter asserts SD-R10 on a DC read-back: the product's VerifyAfter must accept the DC's canonical
// re-ordering (T-0627) and the order difference, if any, is logged.
func verifyAfter(t *testing.T, what string, w sd.DACLWrite, stored sd.SD) {
	t.Helper()
	v, err := w.VerifyAfter(stored)
	if err != nil {
		t.Errorf("%s: VerifyAfter rejected the DC's stored DACL: %v (planned %v, stored %v)", what, err, orderOf(plannedSD(t, w)), orderOf(stored))
		return
	}
	t.Logf("RESULT %s: VerifyAfter accepted; DC re-ordered=%v %s", what, v.Reordered, firstDiff(orderOf(plannedSD(t, w)), orderOf(stored)))
}

func eq(a, b []string) bool { return strings.Join(a, "|") == strings.Join(b, "|") }

const sdvInherit = sd.FlagObjectInherit | sd.FlagContainerInherit

// AC2 + marker: PD-clear recompute, BlockKeep/BlockRemove, INHERITED marker survives a DACL write.
func TestWindowsLabSDWriteInheritance(t *testing.T) {
	l := sdvDial(t)
	t1 := l.grp(t, "sdv-inh-t1")
	t2 := l.grp(t, "sdv-inh-t2")
	t3 := l.grp(t, "sdv-inh-t3")
	parent := "OU=sdv-inh," + sdvManaged
	l.ou(t, parent)
	if err := send(l.admin, parent, l.planAdd(t, parent, t1, sd.MaskReadProp, sdvInherit, false)); err != nil {
		t.Fatalf("parent ACE t1: %v", err)
	}
	user := func(n string) string {
		dn := "CN=" + n + "," + parent
		l.user(t, dn, n, l.admin)
		return dn
	}

	// Baseline: a child created below an inheritable ACE holds it with the INHERITED marker.
	c1 := user("sdv-inh-c1")
	b := l.readSD(t, c1, 4)
	t.Logf("RESULT child created under parent ACE: %s", summary(b))
	if has(b, t1, true) != 1 {
		t.Fatalf("child lacks the INHERITED copy of the parent's ACE: %s", summary(b))
	}
	if b.Control.Protected() {
		t.Fatalf("new child unexpectedly PD")
	}
	t.Logf("RESULT new child control has DI (auto-inherited) = %v", b.Control.AutoInherited())

	// INHERITED marker: an explicit ACE added by the product's PlanDACL leaves the inherited ACEs inherited.
	addPlan := l.planAdd(t, c1, t3, sd.MaskReadProp, 0, false)
	if err := send(l.admin, c1, addPlan); err != nil {
		t.Fatalf("explicit add on child: %v", err)
	}
	a := l.readSD(t, c1, 4)
	verifyAfter(t, "explicit add", addPlan, a)
	t.Logf("RESULT after explicit add (marker): %s", summary(a))
	if has(a, t1, true) != 1 || has(a, t1, false) != 0 {
		t.Errorf("INHERITED marker lost or duplicated by a DACL write: %s", summary(a))
	}
	if has(a, t3, false) != 1 {
		t.Errorf("explicit ACE missing after write: %s", summary(a))
	}
	if a.Control.AutoInherited() != b.Control.AutoInherited() {
		t.Errorf("DI changed across a write (before %v after %v)", b.Control.AutoInherited(), a.Control.AutoInherited())
	}

	// Same write with DI cleared by the client: record whether the DC keeps INHERITED markers (SD-R7).
	c2 := user("sdv-inh-c2")
	w := l.planAdd(t, c2, t3, sd.MaskReadProp, 0, false)
	raw := w.Value()
	noDI := append([]byte(nil), raw...)
	noDI[3] &^= 0x04 // control high byte 0x0400 DI
	if bytes.Equal(noDI, raw) {
		t.Log("plan did not carry DI; the DI-less variant equals the plan")
	}
	m := ldap.NewModifyRequest(c2, []ldap.Control{flagsCtl(4)})
	m.Replace("nTSecurityDescriptor", []string{string(noDI)})
	if err := l.admin.Modify(m); err != nil {
		t.Logf("RESULT DACL without DI refused: code %d %v", sdvCode(err), err)
	} else {
		n := l.readSD(t, c2, 4)
		t.Logf("RESULT DACL written without DI: inherited t1 copies=%d explicit t1 copies=%d; %s", has(n, t1, true), has(n, t1, false), summary(n))
	}

	// BlockKeepInherited: PD set, inherited ACEs become explicit copies, nothing else changes.
	c3 := user("sdv-inh-c3")
	pre := l.readSD(t, c3, 4)
	keepPlan := l.planInh(t, c3, sd.BlockKeepInherited)
	if err := send(l.admin, c3, keepPlan); err != nil {
		t.Fatalf("BlockKeepInherited write: %v", err)
	}
	k := l.readSD(t, c3, 4)
	// SD-W10 records the plan order; the DC re-sorts (T-0627), so verify as the DC canonicalises.
	verifyAfter(t, "BlockKeepInherited", keepPlan, k)
	t.Logf("RESULT BlockKeepInherited before: %s\nRESULT BlockKeepInherited after:  %s", summary(pre), summary(k))
	if !k.Control.Protected() {
		t.Error("BlockKeepInherited: PD not set")
	}
	if has(k, t1, true) != 0 || has(k, t1, false) != 1 {
		t.Errorf("BlockKeepInherited: inherited ACE not turned into one explicit copy: %s", summary(k))
	}
	want := append(shapeSet(pre, false), shapeSet(pre, true)...)
	sort.Strings(want)
	if !eq(shapeSet(k, false), want) || len(shapeSet(k, true)) != 0 {
		t.Errorf("BlockKeepInherited: ACE multiset changed.\n want %v\n got  %v", want, shapeSet(k, false))
	}

	// BlockRemoveInherited: PD set, inherited ACEs gone, explicit ones kept.
	c4 := user("sdv-inh-c4")
	pre = l.readSD(t, c4, 4)
	rmPlan := l.planInh(t, c4, sd.BlockRemoveInherited)
	if err := send(l.admin, c4, rmPlan); err != nil {
		t.Fatalf("BlockRemoveInherited write: %v", err)
	}
	r := l.readSD(t, c4, 4)
	if d := firstDiff(orderOf(plannedSD(t, rmPlan)), orderOf(r)); d != "" {
		t.Errorf("RESULT BlockRemoveInherited: the DC re-ordered the DACL: %s", d)
	}
	t.Logf("RESULT BlockRemoveInherited before: %s\nRESULT BlockRemoveInherited after:  %s", summary(pre), summary(r))
	if !r.Control.Protected() || len(shapeSet(r, true)) != 0 || !eq(shapeSet(r, false), shapeSet(pre, false)) {
		t.Errorf("BlockRemoveInherited: expected PD, no inherited ACEs, explicit ACEs unchanged")
	}

	// PD-clear recompute. c3 is PD with an explicit copy of t1. Add t2 to the parent: a PD child must not
	// receive it; a canary (unprotected sibling) proves propagation ran.
	if err := send(l.admin, parent, l.planAdd(t, parent, t2, sd.MaskReadProp, sdvInherit, false)); err != nil {
		t.Fatalf("parent ACE t2: %v", err)
	}
	eventually(t, "unprotected sibling c1 receives the parent's new ACE", sdvWait, func() bool {
		return has(l.readSD(t, c1, 4), t2, true) == 1
	})
	if g := l.readSD(t, c3, 4); has(g, t2, true)+has(g, t2, false) != 0 {
		t.Fatalf("PD child received the parent's ACE: %s", summary(g))
	}
	if err := send(l.admin, c3, l.planInh(t, c3, sd.RestoreInheritance)); err != nil {
		t.Fatalf("RestoreInheritance write: %v", err)
	}
	var got sd.SD
	eventually(t, "RestoreInheritance: DC recomputes the inherited ACE for t2", sdvWait, func() bool {
		got = l.readSD(t, c3, 4)
		return has(got, t2, true) == 1
	})
	t.Logf("RESULT RestoreInheritance after: %s", summary(got))
	if got.Control.Protected() {
		t.Error("RestoreInheritance: PD still set")
	}
	if has(got, t1, true) != 1 {
		t.Errorf("RestoreInheritance: no inherited copy of t1: %s", summary(got))
	}
	t.Logf("RESULT RestoreInheritance leaves the earlier explicit copy of t1: explicit t1 count = %d (the plan writes the old copies back unchanged, so a duplicate is the DC's doing if > 0)", has(got, t1, false))
}

// AC3: a DACL-only write by an identity without SeSecurityPrivilege succeeds and leaves owner/group/SACL alone.
func TestWindowsLabSDWriteDACLOnlyNoSecurityPrivilege(t *testing.T) {
	l := sdvDial(t)
	g := l.grp(t, "sdv-flags-t1")
	dn := "CN=sdv-flags-u1,OU=Managed," + winBase
	l.user(t, dn, "sdv-flags-u1", l.svc)

	// The premise: the service account does not hold SeSecurityPrivilege, so it cannot read a SACL.
	if b, err := readRaw(l.svc, dn, 8); err == nil {
		if s, derr := sd.Decode(sd.Raw(b)); derr == nil && len(s.SACL.ACEs) > 0 {
			t.Fatalf("service account can read the SACL: the lab identity holds SeSecurityPrivilege, the premise fails")
		}
		t.Logf("RESULT service account SACL read (flags 8): ok, no SACL returned")
	} else {
		t.Logf("RESULT service account SACL read (flags 8): refused code %d %v", sdvCode(err), err)
	}

	// A SACL on the object (admin holds the privilege) makes "SACL unchanged" a real assertion.
	sacl := mustRaw(t, l.admin, dn, 15)
	before, err := sd.Decode(sd.Raw(sacl))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RESULT before: owner=%s group=%s sacl aces=%d", before.Owner, before.Group, len(before.SACL.ACEs))

	w, _, err := sd.PlanDACL(l.readSD(t, dn, 4), sd.ACEDiff{Add: []sd.NewACE{{Trustee: g, Mask: sd.MaskReadProp}}}, nil,
		sd.ObjectCtx{ObjectGUID: l.objectGUID(t, dn), Connector: sd.PrincipalFromSIDs(l.svcSID)}, sd.PlanOpts{})
	if err != nil {
		t.Fatalf("plan as service account: %v", err)
	}
	v := w.Value()
	if !bytes.Equal(v[4:16], make([]byte, 12)) { // owner, group, SACL offsets
		t.Fatalf("plan value has owner/group/SACL offsets set: %x", v[:20])
	}
	if err := send(l.svc, dn, w); err != nil {
		t.Fatalf("DACL-only write as the service account (no SeSecurityPrivilege) failed: code %d %v", sdvCode(err), err)
	}
	t.Log("RESULT DACL-only SD_FLAGS write (offsets zero) as a non-privileged identity: success")

	after, err := sd.Decode(sd.Raw(mustRaw(t, l.admin, dn, 15)))
	if err != nil {
		t.Fatal(err)
	}
	if after.Owner != before.Owner || after.Group != before.Group {
		t.Errorf("owner/group changed: %s/%s -> %s/%s", before.Owner, before.Group, after.Owner, after.Group)
	}
	if len(after.SACL.ACEs) != len(before.SACL.ACEs) {
		t.Errorf("SACL changed: %d -> %d ACEs", len(before.SACL.ACEs), len(after.SACL.ACEs))
	}
	for i := range before.SACL.ACEs {
		if i < len(after.SACL.ACEs) && !bytes.Equal(before.SACL.ACEs[i].Raw, after.SACL.ACEs[i].Raw) {
			t.Errorf("SACL ACE %d changed", i)
		}
	}
	if has(after, g, false) != 1 {
		t.Errorf("DACL change not applied: %s", summary(after))
	}

	// Observation only: the same bytes under SD_FLAGS=15 (SACL requested) without the privilege.
	m := ldap.NewModifyRequest(dn, []ldap.Control{flagsCtl(15)})
	m.Replace("nTSecurityDescriptor", []string{string(v)})
	err = l.svc.Modify(m)
	t.Logf("RESULT same value under SD_FLAGS=15 as non-privileged identity: code %d err=%v", sdvCode(err), err)
}

func mustRaw(t *testing.T, conn *ldap.Conn, dn string, bits byte) []byte {
	t.Helper()
	b, err := readRaw(conn, dn, bits)
	if err != nil {
		t.Fatalf("read %s flags %d: %v", dn, bits, err)
	}
	return b
}

// AC1: SDProp reverts a DACL write (and a PD-clear) on a protected object, as SD-E11 assumes.
func TestWindowsLabSDWriteSDPropRevert(t *testing.T) {
	l := sdvDial(t)
	g := l.grp(t, "sdv-prop-t1")
	dn := "CN=sdv-prop-u1,OU=Managed," + winBase
	l.user(t, dn, "sdv-prop-u1", l.admin)
	ao := "CN=Account Operators,CN=Builtin," + winBase
	mod := ldap.NewModifyRequest(ao, nil)
	mod.Add("member", []string{dn})
	if err := l.admin.Modify(mod); err != nil {
		t.Fatalf("add to Account Operators: %v", err)
	}
	t.Cleanup(func() {
		m := ldap.NewModifyRequest(ao, nil)
		m.Delete("member", []string{dn})
		_ = l.admin.Modify(m)
	})
	runSDProp := func() {
		m := ldap.NewModifyRequest("", nil)
		m.Replace("runProtectAdminGroupsTask", []string{"1"})
		if err := l.admin.Modify(m); err != nil {
			t.Fatalf("trigger SDProp (rootDSE runProtectAdminGroupsTask): %v", err)
		}
	}
	adminCount := func() string {
		r, err := l.admin.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"adminCount"}, nil))
		if err != nil || len(r.Entries) != 1 {
			return ""
		}
		return r.Entries[0].GetAttributeValue("adminCount")
	}
	runSDProp()
	eventually(t, "SDProp protects the new Account Operators member (adminCount=1, PD set)", sdvWait, func() bool {
		return adminCount() == "1" && l.readSD(t, dn, 4).Control.Protected()
	})
	prot := l.readSD(t, dn, 4)
	t.Logf("RESULT protected object after first SDProp: %s", summary(prot))

	// The product side of SD-E11: a caller that knows the object is protected gets sd.sdprop_will_revert.
	_, _, perr := sd.PlanDACL(prot, sd.ACEDiff{Add: []sd.NewACE{{Trustee: g, Mask: sd.MaskReadProp}}}, nil,
		sd.ObjectCtx{ObjectGUID: l.objectGUID(t, dn), ProtectedBySDProp: true, Connector: l.adminPrincipal(t)}, sd.PlanOpts{})
	if codec.Code(perr) != sd.ErrSDPropWillRevert {
		t.Fatalf("planner on a protected object: %v, want %s", perr, sd.ErrSDPropWillRevert)
	}

	// The DC itself accepts the write (that is why the planner must refuse); SDProp then reverts it.
	if err := send(l.admin, dn, l.planAdd(t, dn, g, sd.MaskReadProp, 0, false)); err != nil {
		t.Fatalf("DC refused the DACL write on a protected object (the planner's refusal would then be redundant): %v", err)
	}
	if has(l.readSD(t, dn, 4), g, false) != 1 {
		t.Fatal("write on protected object did not take effect before SDProp")
	}
	runSDProp()
	eventually(t, "SDProp reverts the DACL write", sdvWait, func() bool {
		return has(l.readSD(t, dn, 4), g, false) == 0
	})
	t.Logf("RESULT DACL write reverted by SDProp: %s", summary(l.readSD(t, dn, 4)))

	// PD-clear (RestoreInheritance) on a protected object is also undone.
	if err := send(l.admin, dn, l.planInh(t, dn, sd.RestoreInheritance)); err != nil {
		t.Fatalf("RestoreInheritance on protected object: %v", err)
	}
	if l.readSD(t, dn, 4).Control.Protected() {
		t.Fatal("PD not cleared before SDProp")
	}
	runSDProp()
	eventually(t, "SDProp re-sets PD", sdvWait, func() bool { return l.readSD(t, dn, 4).Control.Protected() })
	t.Logf("RESULT PD-clear reverted by SDProp: %s", summary(l.readSD(t, dn, 4)))
}

// Open question from T-0583 round 3: does an inherit-only OWNER RIGHTS / owner-SID ACE suppress the owner's
// implicit WRITE_DAC? Each case is a separate object owned by the service account, with every other route
// to WRITE_DAC for it removed (PD + BlockRemoveInherited).
func TestWindowsLabSDWriteOwnerImplicitRights(t *testing.T) {
	l := sdvDial(t)
	g := l.grp(t, "sdv-own-t1")
	ownerRights, _ := sid.Parse("S-1-3-4")
	cases := []struct {
		name    string
		trustee func() sid.SID
		flags   uint8
		mask    uint32
		// suppresses: expected outcome pinned to what the first lab run observed and MS-DTYP says.
		suppresses bool
	}{
		{name: "control-no-ace"},
		{name: "owner-rights-applies-to-object", trustee: func() sid.SID { return ownerRights }, mask: sd.MaskReadControl, suppresses: true},
		{name: "owner-rights-inherit-only", trustee: func() sid.SID { return ownerRights }, flags: sd.FlagContainerInherit | sd.FlagInheritOnly, mask: sd.MaskReadControl},
		{name: "owner-sid-inherit-only", trustee: func() sid.SID { return l.svcSID }, flags: sd.FlagContainerInherit | sd.FlagInheritOnly, mask: sd.MaskReadControl},
	}
	for i, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			dn := "CN=sdv-own-" + strings.ReplaceAll(c.name, "-", "") + ",OU=Managed," + winBase
			l.user(t, dn, fmt.Sprintf("sdv-own-%d", i), l.svc)
			if o := l.readSD(t, dn, 1); !o.HasOwner || o.Owner != l.svcSID {
				t.Fatalf("object not owned by the service account (owner %v): the test needs svc as owner", o.Owner)
			}
			if err := send(l.admin, dn, l.planInh(t, dn, sd.BlockRemoveInherited)); err != nil {
				t.Fatalf("PD + remove inherited: %v", err)
			}
			if c.trustee != nil {
				if err := send(l.admin, dn, l.planAdd(t, dn, c.trustee(), c.mask, c.flags, false)); err != nil {
					t.Fatalf("add %s ACE: %v", c.name, err)
				}
			}
			cur := l.readSD(t, dn, 4)
			t.Logf("RESULT %s DACL: %s", c.name, summary(cur))
			if sd.Grants(sd.PrincipalFromSIDs(l.svcSID), sd.Right{Mask: sd.MaskWriteDACL}, cur).Decision == sd.Yes {
				t.Fatal("svc holds an explicit WRITE_DAC route: case is not isolating the owner right")
			}
			// The write is planned as Administrator and sent as the owner, so only the DC decides.
			err := send(l.svc, dn, l.planAdd(t, dn, g, sd.MaskReadProp, 0, false))
			t.Logf("RESULT %s: owner's DACL write -> code %d err=%v", c.name, sdvCode(err), err)
			switch {
			case c.suppresses && err == nil:
				t.Errorf("%s: owner still wrote the DACL; the planner's SD-W rule for this shape is over-cautious", c.name)
			case !c.suppresses && err != nil:
				t.Errorf("%s: owner could not write the DACL (code %d %v); the implicit right is suppressed", c.name, sdvCode(err), err)
			}
		})
	}
}
