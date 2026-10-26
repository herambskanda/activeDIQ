package tier0

import (
	"fmt"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// TM-D26 test table (threat-model §6.4 proof TM-F-T0GUARD, T-0227 additions). Every positive case
// has a negative twin. Samba proves the LDAP and sIDHistory semantics only; DACL, owner and callback
// cases need the Windows lab (T-0226).

const (
	wDACL     = 0x40000
	wOwner    = 0x80000
	gAll      = 0x10000000
	gWrite    = 0x40000000
	wProp     = 0x20
	rProp     = 0x10
	allExt    = 0x100
	foreignID = "S-1-5-21-9-9-9"
)

func u(f *fakeDir, name string, rid int, kv ...string) string {
	d := fmt.Sprintf("CN=%s,OU=Staff,%s", name, dom)
	f.add(d, fmt.Sprintf("%s-%d", dsid, rid), user, kv...)
	return d
}

func setSD(f *fakeDir, objDN string, aces ...aceSpec) {
	f.find(objDN).raw["nTSecurityDescriptor"] = sdBytes(aces...)
}

func wantBasis(t *testing.T, f *fakeDir, target string, b Basis, want bool) {
	t.Helper()
	r, err := classify(t, f, target)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	if has(r, b) != want {
		t.Errorf("%s: basis %v = %v, want %v (bases %v)", target, b, has(r, b), want, r.Bases)
	}
}

func TestC17WriteDACL(t *testing.T) { // T0-C17-DACL
	f := forest()
	us, v := u(f, "u17", 4001), u(f, "v17", 4002)
	setSD(f, dom, aceSpec{sid: dsid + "-4001", mask: wDACL}, aceSpec{sid: dsid + "-4002", mask: rProp})
	wantBasis(t, f, us, C17, true)
	wantBasis(t, f, v, C17, false)
}

func TestC17Rights(t *testing.T) { // T0-C17-OWN
	other := mustGUID("bf967950-0de6-11d0-a285-00aa003049e2") // description
	cases := []struct {
		name string
		ace  aceSpec
		want bool
	}{
		{"WriteOwner", aceSpec{mask: wOwner}, true},
		{"GenericAll", aceSpec{mask: gAll}, true},
		{"GenericWrite", aceSpec{mask: gWrite}, true},
		{"WriteProperty all properties", aceSpec{mask: wProp}, true},
		{"WriteProperty gPLink", aceSpec{mask: wProp, objType: &gpLinkID}, true},
		{"all extended rights", aceSpec{mask: allExt}, true},
		{"WriteProperty description", aceSpec{mask: wProp, objType: &other}, false},
		{"one extended right", aceSpec{mask: allExt, objType: &getChanges}, false},
		{"read only", aceSpec{mask: rProp | 0x20000}, false},
		{"WriteDACL but inherit-only", aceSpec{mask: wDACL, flags: aceInheritOnly}, false},
	}
	for _, c := range cases {
		f := forest()
		us := u(f, "x", 4010)
		c.ace.sid = dsid + "-4010"
		setSD(f, dom, c.ace)
		t.Run(c.name, func(t *testing.T) { wantBasis(t, f, us, C17, c.want) })
	}
}

func TestC17Owner(t *testing.T) { // T0-C17-OWNER
	for _, ownerRights := range []bool{false, true} {
		f := forest()
		o := u(f, "owner", 4020)
		aces := []aceSpec{{sid: dsid + "-512", mask: gAll}}
		if ownerRights {
			aces = append(aces, aceSpec{sid: "S-1-3-4", mask: 0x20000}) // OWNER RIGHTS
		}
		f.find(dom).raw["nTSecurityDescriptor"] = sdOwned(dsid+"-4020", aces...)
		wantBasis(t, f, o, C17, true)
	}
	// Twin: a C1 owner adds nothing; an ordinary user stays clear.
	f := forest()
	f.find(dom).raw["nTSecurityDescriptor"] = sdOwned(dsid+"-512", aceSpec{sid: "S-1-5-9", mask: rProp})
	wantBasis(t, f, "CN=carol,OU=Staff,"+dom, C17, false)
	// The owner of AdminSDHolder counts the same.
	f = forest()
	o := u(f, "adhowner", 4021)
	f.find("CN=AdminSDHolder,CN=System," + dom).raw["nTSecurityDescriptor"] = sdOwned(dsid+"-4021", aceSpec{sid: dsid + "-512", mask: gAll})
	wantBasis(t, f, o, C17, true)
}

func TestC17Group(t *testing.T) { // T0-C17-GROUP
	f := forest()
	f.add("CN=ctl,OU=Staff,"+dom, dsid+"-4030", group, "member", "CN=inner,OU=Staff,"+dom)
	f.add("CN=inner,OU=Staff,"+dom, dsid+"-4031", group, "member", "CN=nested,OU=Staff,"+dom, "member", "CN=ctl,OU=Staff,"+dom) // cycle
	nested := u(f, "nested", 4032)
	prim := u(f, "prim", 4033, "primaryGroupID", "4030")
	out := u(f, "outsider", 4034)
	setSD(f, dom, aceSpec{sid: dsid + "-4030", mask: wDACL})
	wantBasis(t, f, nested, C17, true)
	wantBasis(t, f, prim, C17, true)
	wantBasis(t, f, out, C17, false)
}

func TestC17AdminSDHolderAndConfig(t *testing.T) { // T0-C17-ADMINSDH
	for _, obj := range []string{"CN=AdminSDHolder,CN=System," + dom, cfg, "CN=Schema," + cfg} {
		f := forest()
		us, other := u(f, "w", 4040), u(f, "z", 4041)
		setSD(f, obj, aceSpec{sid: dsid + "-4040", mask: wDACL}, aceSpec{sid: dsid + "-4041", mask: rProp})
		wantBasis(t, f, us, C17, true)
		wantBasis(t, f, other, C17, false)
	}
}

func TestC17Broad(t *testing.T) { // T0-C17-BROAD
	f := forest()
	setSD(f, dom, aceSpec{sid: "S-1-5-11", mask: wDACL})
	r, err := classify(t, f, "CN=carol,OU=Staff,"+dom)
	if err == nil || !r.Tier0 || !r.Unknown || !strings.Contains(err.Error(), "S-1-5-11") {
		t.Errorf("Authenticated Users WriteDACL: %+v %v", r, err)
	}
	f = forest() // twin: Authenticated Users with read only is fine
	setSD(f, dom, aceSpec{sid: "S-1-5-11", mask: rProp})
	wantBasis(t, f, "CN=carol,OU=Staff,"+dom, C17, false)
}

func TestC17NotSplit(t *testing.T) { // T0-C17-NOTSPLIT
	f := forest()
	x, y := u(f, "ctl", 4050), u(f, "half", 4051)
	setSD(f, dom, aceSpec{sid: dsid + "-4050", mask: wDACL}, aceSpec{sid: dsid + "-4051", mask: allExt, objType: &getChanges})
	wantBasis(t, f, x, C17, true)
	wantBasis(t, f, x, C11, false)
	wantBasis(t, f, y, C17, false)
	wantBasis(t, f, y, C11, false)
}

func TestCallbackACEs(t *testing.T) { // T0-CB-CALLBACK
	for _, typ := range []byte{0x09, 0x0B} {
		f := forest()
		us, dcs := u(f, "cb", 4060), u(f, "cbsync", 4061)
		setSD(f, dom,
			aceSpec{sid: dsid + "-4060", mask: wDACL, typ: typ, junk: 4},
			aceSpec{sid: dsid + "-4061", mask: allExt, typ: 0x0B, objType: &getChanges, junk: 4},
			aceSpec{sid: dsid + "-4061", mask: allExt, typ: 0x0B, objType: &getChangesAll, junk: 4},
			// deny callbacks on the same principals, ahead of nothing: they must not remove the grant
			aceSpec{sid: dsid + "-4060", mask: wDACL, typ: 0x0A, junk: 4},
			aceSpec{sid: dsid + "-4061", mask: allExt, typ: 0x0C, objType: &getChanges, junk: 4},
		)
		wantBasis(t, f, us, C17, true)
		wantBasis(t, f, dcs, C11, true)
	}
	// Twin: a deny callback alone grants nothing.
	f := forest()
	us := u(f, "cbdeny", 4062)
	setSD(f, dom, aceSpec{sid: dsid + "-4062", mask: wDACL, typ: 0x0A, junk: 4})
	wantBasis(t, f, us, C17, false)
	// A malformed callback ACE fails closed.
	f = forest()
	u(f, "cbbad", 4063)
	bad := sdBytes(aceSpec{sid: dsid + "-4063", mask: wDACL, typ: 0x09, junk: 4})
	bad[20+8+2] = 6 // ACE size 6: smaller than any ACE
	f.find(dom).raw["nTSecurityDescriptor"] = bad
	if r, err := classify(t, f, "CN=carol,OU=Staff,"+dom); err == nil || !r.Tier0 || !r.Unknown {
		t.Errorf("malformed callback: %+v %v", r, err)
	}
}

func TestC18PrivilegedHistory(t *testing.T) { // T0-C18-DA
	for _, h := range []string{foreignID + "-512", foreignID + "-519", "S-1-5-32-544", foreignID + "-500"} {
		f := forest()
		us := u(f, "mig", 4070)
		f.find(us).history(h)
		wantBasis(t, f, us, C18, true)
		wantBasis(t, f, us, C2, false) // a member of nothing
	}
	f := forest() // twin: Domain Users and an ordinary RID
	us := u(f, "plain", 4071)
	f.find(us).history(foreignID+"-513", foreignID+"-1105", "S-1-5-32-545")
	wantBasis(t, f, us, C18, false)
}

func TestC18PrefixAndUnresolved(t *testing.T) { // T0-C18-PREFIX
	f := forest()
	a, b := u(f, "unk512", 4080), u(f, "unk1105", 4081)
	f.find(a).history("S-1-5-21-5-6-7-512")
	f.find(b).history("S-1-5-21-5-6-7-1105")
	wantBasis(t, f, a, C18, true)
	wantBasis(t, f, b, C18, false)
	set, err := NewAD(f).Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	un := set.Unresolved()
	if len(un) != 1 || un[0].SID.String() != "S-1-5-21-5-6-7-1105" {
		t.Errorf("unresolved = %+v", un)
	}
}

func TestC18Group(t *testing.T) { // T0-C18-GROUP
	f := forest()
	g := "CN=migrated,OU=Staff," + dom
	f.add(g, dsid+"-4090", group, "member", "CN=gm,OU=Staff,"+dom).history(foreignID + "-512")
	gm := u(f, "gm", 4091)
	f.add("CN=plaing,OU=Staff,"+dom, dsid+"-4092", group, "member", "CN=pm,OU=Staff,"+dom)
	pm := u(f, "pm", 4093)
	wantBasis(t, f, g, C18, true)
	wantBasis(t, f, gm, C2, true)
	wantBasis(t, f, pm, C2, false)
}

func TestC18InsideACE(t *testing.T) { // T0-C18-ACE
	f := forest()
	us := u(f, "heir", 4100)
	f.find(us).history(foreignID + "-1105")
	setSD(f, dom, aceSpec{sid: foreignID + "-1105", mask: wDACL})
	wantBasis(t, f, us, C17, true)
	// Twin: nobody holds that SID in sIDHistory, so the foreign trustee fails the snapshot naming it.
	f = forest()
	setSD(f, dom, aceSpec{sid: foreignID + "-1105", mask: wDACL})
	if _, err := classify(t, f, "CN=carol,OU=Staff,"+dom); err == nil || !strings.Contains(err.Error(), foreignID+"-1105") {
		t.Errorf("unresolved foreign trustee: %v", err)
	}
	// C18 by resolution: sIDHistory holds the SID of an object that is tier0 by another basis.
	f = forest()
	us = u(f, "heir2", 4101)
	f.find(us).history(dsid + "-1101") // alice, C2
	wantBasis(t, f, us, C18, true)
}

func TestC18FailClosed(t *testing.T) { // T0-C18-FAIL
	f := forest()
	f.failHas = "sIDHistory"
	if r, err := classify(t, f, "CN=carol,OU=Staff,"+dom); err == nil || !r.Tier0 || !r.Unknown {
		t.Errorf("sIDHistory read denied: %+v %v", r, err)
	}
	f = forest()
	us := u(f, "gcfail", 4110)
	f.find(us).history(dsid + "-4111")
	f.add("CN=target,OU=gcfail,"+dom, dsid+"-4111", user)
	f.failDN = "OU=gcfail"
	if r, err := classify(t, f, "CN=carol,OU=Staff,"+dom); err == nil || !r.Tier0 || !r.Unknown {
		t.Errorf("GC lookup fails: %+v %v", r, err)
	}
}

func TestC8DirectoryService(t *testing.T) { // T0-C8-DSH
	f := forest()
	wantBasis(t, f, "CN=Directory Service,CN=Windows NT,CN=Services,"+cfg, C8, true)
	wantBasis(t, f, "CN=Windows NT,CN=Services,"+cfg, C8, false)
	f.find("CN=Directory Service,CN=Windows NT,CN=Services," + cfg).attrs["dsheuristics"] = []string{"0000001100010000000000000000000000000001"[:29]}
	set, err := NewAD(f).Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, h := range set.DSHeuristics() {
		got = append(got, fmt.Sprintf("%d:%s", h.Pos, h.Name))
	}
	if strings.Join(got, ",") != "7:fLDAPBlockAnonOps,8:fAllowAnonNSPI,12:fDontStandardizeSDs" {
		t.Errorf("heuristics = %v", got)
	}
	// A missing Directory Service object fails closed.
	f = forest()
	f.objs = f.objs[:len(f.objs):len(f.objs)]
	for i, o := range f.objs {
		if strings.HasPrefix(o.dn, "CN=Directory Service,") {
			f.objs = append(f.objs[:i], f.objs[i+1:]...)
			break
		}
	}
	if _, err := classify(t, f, "CN=carol,OU=Staff,"+dom); err == nil {
		t.Error("missing Directory Service accepted")
	}
}

func TestC13ByRIDAndPinnedGUID(t *testing.T) { // T0-C13-RENAME
	f := forest()
	cp := f.add("CN=Renamed CP,CN=Users,"+dom, dsid+"-517", group, "sAMAccountName", "Publishers-X", "member", "CN=cpm,OU=Staff,"+dom)
	cpm := u(f, "cpm", 4120)
	dns := f.find("CN=DnsAdmins,CN=Users," + dom)
	pin := dns.guid
	dns.attrs["samaccountname"] = []string{"NetOps"} // renamed after the pin
	decoy := f.add("CN=Decoy,OU=Staff,"+dom, dsid+"-4121", group, "sAMAccountName", "DnsAdmins")
	_ = decoy
	for _, g := range []*fobj{cp, decoy} { // C19 reads every C13 group's descriptor
		g.raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: dsid + "-512", mask: gAll})
	}
	// Cert Publishers renamed: found by RID without any pin; members follow.
	wantBasis(t, f, cp.dn, C13, true)
	wantBasis(t, f, cpm, C13, true)
	// The decoy named DnsAdmins is tier0 as well.
	wantBasis(t, f, "CN=Decoy,OU=Staff,"+dom, C13, true)
	// The renamed DnsAdmins: tier0 with its pin, not without (it is only found by name).
	r, err := NewAD(f).Classify(t.Context(), ref(t, dns.dn), ADInput{CorrelationKnown: true, PinnedC13: []guid.GUID{pin}})
	if err != nil || !has(r, C13) {
		t.Errorf("pinned: %+v %v", r, err)
	}
	if r, err := classify(t, f, dns.dn); err != nil || has(r, C13) {
		t.Errorf("unpinned renamed group should not be C13: %+v %v", r, err)
	}
	// The snapshot reports the groups to pin.
	set, err := NewAD(f).Snapshot(t.Context(), pin)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.C13Groups()) != 3 { // Cert Publishers (RID), pinned DnsAdmins, decoy
		t.Errorf("C13Groups = %v", set.C13Groups())
	}
	// A pinned GUID that no longer exists marks nothing and is not an error.
	if _, err := NewAD(f).Snapshot(t.Context(), guid.GUID{1, 2, 3}); err != nil {
		t.Errorf("stale pin: %v", err)
	}
}

func TestC17Live(t *testing.T) { // T0-C17-LIVE, CC-WRITE-15(d): classification is re-read on every call
	f := forest()
	us := u(f, "late", 4130)
	wantBasis(t, f, us, C17, false)
	setSD(f, dom, aceSpec{sid: dsid + "-4130", mask: wDACL}) // granted after "Verify"
	wantBasis(t, f, us, C17, true)
	// ... and the owner of AdminSDHolder, separately.
	f = forest()
	o := u(f, "late2", 4131)
	wantBasis(t, f, o, C17, false)
	f.find("CN=AdminSDHolder,CN=System," + dom).raw["nTSecurityDescriptor"] = sdOwned(dsid+"-4131", aceSpec{sid: dsid + "-512", mask: gAll})
	wantBasis(t, f, o, C17, true)
	// Fail closed: the head DACL made unreadable.
	delete(f.find(dom).raw, "nTSecurityDescriptor")
	if r, err := classify(t, f, o); err == nil || !r.Unknown {
		t.Errorf("unreadable head DACL: %+v %v", r, err)
	}
}
