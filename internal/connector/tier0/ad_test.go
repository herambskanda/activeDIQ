package tier0

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

var (
	gpLinkID     = mustGUID("f30e3bbe-9ff0-11d1-b603-0000f80367c1")
	gpOptionsID  = mustGUID("f30e3bbf-9ff0-11d1-b603-0000f80367c1")
	memberID     = mustGUID("bf9679c0-0de6-11d0-a285-00aa003049e2") // also the Self-Membership right
	unicodePwdID = mustGUID("bf9679e1-0de6-11d0-a285-00aa003049e2")
	spnID        = mustGUID("f3a64788-5306-11d1-a9c5-0000f80367c1")
	uacID        = mustGUID("bf967a68-0de6-11d0-a285-00aa003049e2")
	keyCredID    = mustGUID("5b47d60f-6090-40b2-9f37-2a4de88f3063")
	rbcdID       = mustGUID("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")
	descID       = mustGUID("bf967950-0de6-11d0-a285-00aa003049e2")
	resetPwdID   = mustGUID("00299570-246d-11d0-a768-00aa006e0529")
	computerID   = mustGUID("bf967a86-0de6-11d0-a285-00aa003049e2")
	ouClassID    = mustGUID("bf967aa5-0de6-11d0-a285-00aa003049e2")
	gpcID        = mustGUID("f30e3bc2-9ff0-11d1-b603-0000f80367c1")
	userClassID  = mustGUID("bf967aba-0de6-11d0-a285-00aa003049e2")
)

const (
	dom   = "DC=lab,DC=test"
	cfg   = "CN=Configuration," + dom
	dsid  = "S-1-5-21-1-2-3"
	gpoNS = "CN=Policies,CN=System," + dom
)

func gpoDN(id string) string { return "CN={" + id + "}," + gpoNS }
func link(id string, opts string) string {
	return "[LDAP://cn={" + id + "},cn=policies,cn=system," + dom + ";" + opts + "]"
}

var (
	cls   = func(c ...string) []string { return c }
	user  = cls("top", "person", "organizationalPerson", "user")
	group = cls("top", "group")
	comp  = cls("top", "person", "organizationalPerson", "user", "computer")
	ou    = cls("top", "organizationalUnit")
	cont  = cls("top", "container")
)

const (
	gDom    = "11111111-0000-0000-0000-000000000001"
	gDCOU   = "11111111-0000-0000-0000-000000000002"
	gStaff  = "11111111-0000-0000-0000-000000000003"
	gServ   = "11111111-0000-0000-0000-000000000004"
	gSite   = "11111111-0000-0000-0000-000000000005"
	gAdmins = "11111111-0000-0000-0000-000000000006"
	gBranch = "11111111-0000-0000-0000-000000000007"
)

// forest builds the lab: every C row has at least one object, plus plain objects that must stay out.
func forest() *fakeDir {
	f := newFake()
	f.add(dom, dsid, cls("top", "domain", "domainDNS"), "wellKnownObjects", "B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,"+dom,
		"gPLink", link(gDom, "0"))
	f.add(cfg, "", cls("top", "configuration"))
	f.add("CN=Schema,"+cfg, "", cls("top", "dMD"))
	// The roots of trust carry a readable descriptor with an owner (C17); the domain head's is set below.
	rootSD := sdBytes(aceSpec{sid: dsid + "-512", mask: 0x10000000})
	f.find(cfg).raw["nTSecurityDescriptor"] = rootSD
	f.find("CN=Schema," + cfg).raw["nTSecurityDescriptor"] = rootSD
	gp := f.add("CN=GP-Link,CN=Schema,"+cfg, "", cls("attributeSchema"), "lDAPDisplayName", "gPLink")
	gp.raw["schemaIDGUID"] = gpLinkID.Bytes()
	// TM-D27 schema objects and extended rights (GUIDs as shipped by AD).
	for _, x := range [][2]string{{"member", memberID.String()}, {"unicodePwd", unicodePwdID.String()},
		{"servicePrincipalName", spnID.String()}, {"userAccountControl", uacID.String()}, {"gPOptions", gpOptionsID.String()},
		{"msDS-KeyCredentialLink", keyCredID.String()}, {"msDS-AllowedToActOnBehalfOfOtherIdentity", rbcdID.String()},
		{"description", descID.String()}} {
		o := f.add("CN="+x[0]+",CN=Schema,"+cfg, "", cls("attributeSchema"), "lDAPDisplayName", x[0])
		o.raw["schemaIDGUID"] = mustGUID(x[1]).Bytes()
	}
	for n, id := range map[string]guid.GUID{"computer": computerID, "organizationalUnit": ouClassID, "groupPolicyContainer": gpcID, "user": userClassID} {
		o := f.add("CN="+n+",CN=Schema,"+cfg, "", cls("classSchema"), "lDAPDisplayName", n)
		o.raw["schemaIDGUID"] = id.Bytes()
	}
	f.add("CN=Extended-Rights,"+cfg, "", cont)
	f.add("CN=User-Force-Change-Password,CN=Extended-Rights,"+cfg, "", cls("controlAccessRight"), "cn", "User-Force-Change-Password", "rightsGuid", resetPwdID.String())
	f.add("CN=Self-Membership,CN=Extended-Rights,"+cfg, "", cls("controlAccessRight"), "cn", "Self-Membership", "rightsGuid", memberID.String())
	f.add("CN=Windows NT,CN=Services,"+cfg, "", cont)
	f.add("CN=Directory Service,CN=Windows NT,CN=Services,"+cfg, "", cont)

	// Default foreignSecurityPrincipals for well-known SIDs, as in real AD and the Samba lab.
	f.add("CN=ForeignSecurityPrincipals,"+dom, "", cont)
	for _, w := range []string{"S-1-5-4", "S-1-5-9", "S-1-5-11", "S-1-5-17"} {
		f.add("CN="+w+",CN=ForeignSecurityPrincipals,"+dom, w, cls("top", "foreignSecurityPrincipal"))
	}
	// C1 groups, with the nesting nasties.
	f.add("CN=Domain Admins,CN=Users,"+dom, dsid+"-512", group, "member", "CN=alice,OU=Admins,"+dom, "member", "CN=Nested,OU=Staff,"+dom)
	f.add("CN=Domain Controllers,CN=Users,"+dom, dsid+"-516", group)
	f.add("CN=Administrators,CN=Builtin,"+dom, "S-1-5-32-544", group, "member", "CN=Domain Admins,CN=Users,"+dom)
	f.add("CN=Enterprise Admins,CN=Users,"+dom, dsid+"-519", group)
	f.add("CN=Nested,OU=Staff,"+dom, dsid+"-2001", group, "member", "CN=dave\\, Dev,OU=Staff,"+dom, "member", "CN=Domain Admins,CN=Users,"+dom) // circular
	f.add("CN=Administrator,CN=Users,"+dom, dsid+"-500", user)
	f.add("CN=krbtgt,CN=Users,"+dom, dsid+"-502", user, "adminCount", "1")
	f.add("CN=krbtgt_1234,CN=Users,"+dom, dsid+"-1234", user, "msDS-SecondaryKrbTgtNumber", "1234")
	// C2
	f.add("CN=alice,OU=Admins,"+dom, dsid+"-1101", user)
	f.add("CN=dave\\, Dev,OU=Staff,"+dom, dsid+"-1102", user) // comma in the DN
	f.add("CN=bob,OU=Staff,"+dom, dsid+"-1103", user, "primaryGroupID", "512")
	// plain objects and a stale adminCount
	f.add("CN=carol,OU=Staff,"+dom, dsid+"-1104", user)
	f.add("CN=erin,OU=Staff,"+dom, dsid+"-1105", user, "adminCount", "1")
	f.add("CN=Sales,OU=Staff,"+dom, dsid+"-1106", group, "member", "CN=carol,OU=Staff,"+dom)
	f.add("OU=Staff,"+dom, "", ou)
	f.add("OU=Plain,"+dom, "", ou, "gPLink", link(gStaff, "0"))
	f.add("CN=plainuser,OU=Plain,"+dom, dsid+"-1900", user)
	f.add("OU=Workstations,"+dom, "", ou)
	f.add("CN=ws1,OU=Workstations,"+dom, dsid+"-1107", comp, "userAccountControl", "4096")
	f.add("OU=Admins,"+dom, "", ou, "gPLink", link(gAdmins, "0")) // reaches alice, a C2 account

	// C3, C8
	f.add("CN=System,"+dom, "", cont)
	adh := f.add("CN=AdminSDHolder,CN=System,"+dom, "", cont)
	adh.raw["nTSecurityDescriptor"] = rootSD
	f.add("CN=RID Manager$,CN=System,"+dom, "", cls("top", "rIDManager"))
	f.add("CN=Services,"+cfg, "", cont)
	f.add("CN=Group Key Distribution Service,CN=Services,"+cfg, "", cont)
	f.add("CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,"+cfg, "", cont)
	// C10
	f.add("CN=Public Key Services,CN=Services,"+cfg, "", cont)
	f.add("CN=Certificate Templates,CN=Public Key Services,CN=Services,"+cfg, "", cont)
	f.add("CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,"+cfg, "", cls("pKICertificateTemplate"))

	// C5, C6, C15: DC1 in the default OU, DC2 moved out; two sites, one holding DCs.
	f.add("OU=Domain Controllers,"+dom, "", ou, "gPLink", link(gDCOU, "0"))
	f.add("CN=DC1,OU=Domain Controllers,"+dom, dsid+"-1000", comp, "userAccountControl", "532480", "dNSHostName", "dc1.lab.test", "sAMAccountName", "DC1$")
	rb := f.add("CN=DC2,OU=Servers,"+dom, dsid+"-1001", comp, "userAccountControl", "8192", "dNSHostName", "dc2.lab.test", "sAMAccountName", "DC2$")
	rb.raw["msDS-AllowedToActOnBehalfOfOtherIdentity"] = sdBytes(aceSpec{sid: dsid + "-1301", mask: 0x10})
	f.add("OU=Servers,"+dom, "", ou, "gPLink", link(gServ, "0"))
	f.add("CN=rbcd-user,OU=Staff,"+dom, dsid+"-1301", user)
	f.add("CN=Sites,"+cfg, "", cont)
	f.add("CN=Default-First-Site-Name,CN=Sites,"+cfg, "", cls("site"), "gPLink", link(gSite, "1")) // disabled link still counts
	f.add("CN=Servers,CN=Default-First-Site-Name,CN=Sites,"+cfg, "", cont)
	f.add("CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,"+cfg, "", cls("server"), "serverReference", "CN=DC1,OU=Domain Controllers,"+dom)
	f.add("CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,"+cfg, "", cls("nTDSDSA"))
	f.add("CN=Branch,CN=Sites,"+cfg, "", cls("site"), "gPLink", link(gBranch, "0"))

	// GPOs
	for _, g := range []string{gDom, gDCOU, gStaff, gServ, gSite, gAdmins, gBranch} {
		f.add(gpoDN(g), "", cls("groupPolicyContainer"))
	}
	f.add(gpoNS, "", cont)

	// C11: svc-sync holds both rights, half holds one, via a group holder too.
	f.add("CN=svc-sync,OU=Staff,"+dom, dsid+"-1201", user)
	f.add("CN=half,OU=Staff,"+dom, dsid+"-1202", user)
	f.add("CN=repl-group,OU=Staff,"+dom, dsid+"-1203", group, "member", "CN=grp-member,OU=Staff,"+dom)
	f.add("CN=grp-member,OU=Staff,"+dom, dsid+"-1204", user)
	f.find(dom).raw["nTSecurityDescriptor"] = sdBytes(
		aceSpec{sid: dsid + "-1201", mask: 0x100, objType: &getChanges},
		aceSpec{sid: dsid + "-1201", mask: 0x100, objType: &getChangesAll},
		aceSpec{sid: dsid + "-1202", mask: 0x100, objType: &getChanges},
		aceSpec{sid: dsid + "-1203", mask: 0x100},                        // all extended rights
		aceSpec{sid: dsid + "-1105", mask: 0x100, flags: aceInheritOnly}, // does not apply to the root
		aceSpec{sid: dsid + "-9999", mask: 0x10000000},                   // orphan SID under the domain prefix
	)

	// C12
	f.add("CN=svc-unc,OU=Staff,"+dom, dsid+"-1301000", user, "userAccountControl", "524800")
	f.add("CN=app1,OU=Workstations,"+dom, dsid+"-1401", comp, "msDS-AllowedToDelegateTo", "ldap/dc1.lab.test/lab.test")
	f.add("CN=app2,OU=Workstations,"+dom, dsid+"-1402", comp, "msDS-AllowedToDelegateTo", "cifs/files.lab.test")
	// C13
	f.add("CN=DnsAdmins,CN=Users,"+dom, dsid+"-1500", group, "sAMAccountName", "DnsAdmins", "member", "CN=frank,OU=Staff,"+dom)
	f.add("CN=frank,OU=Staff,"+dom, dsid+"-1501", user)
	f.add("CN=Group Policy Creator Owners,CN=Users,"+dom, dsid+"-520", group, "sAMAccountName", "Group Policy Creator Owners")
	// C14
	f.add("CN=AZUREADSSOACC,OU=Servers,"+dom, dsid+"-1600", comp, "sAMAccountName", "AZUREADSSOACC$")
	// Every object C19 reads carries a descriptor, as in AD: Domain Admins full control, owned by the
	// built-in Administrators (a C1 owner adds nothing). Tests overwrite it per case.
	for _, o := range f.objs {
		if len(o.raw["nTSecurityDescriptor"]) == 0 && (o.is("group") || o.is("computer") || o.is("organizationalUnit") ||
			o.is("groupPolicyContainer") || strings.HasPrefix(strings.ToLower(o.dn), "cn=krbtgt") || strings.HasPrefix(o.dn, "CN=Administrator,")) {
			o.raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: dsid + "-512", mask: gAll})
		}
	}
	return f
}

func ref(t *testing.T, s string) dn.ObjectRef {
	t.Helper()
	return dn.DNRef(mustDN(s))
}

func known() ADInput { return ADInput{CorrelationKnown: true} }

func has(r ADResult, b Basis) bool { return slices.Contains(r.Bases, b) }

// AC2: each row C1..C15 has a fixture that classifies tier0 through that row; plain objects do not.
func TestADClassifyRowsC1ToC15(t *testing.T) {
	c := NewAD(forest())
	rows := []struct {
		name string
		dn   string
		want Basis
	}{
		{"C1 protected group", "CN=Domain Admins,CN=Users," + dom, C1},
		{"C1 builtin Administrators", "CN=Administrators,CN=Builtin," + dom, C1},
		{"C1 Administrator account", "CN=Administrator,CN=Users," + dom, C1},
		{"C2 direct member without adminCount", "CN=alice,OU=Admins," + dom, C2},
		{"C2 member of nested group, comma in DN", "CN=dave\\, Dev,OU=Staff," + dom, C2},
		{"C2 nested (circular) group itself", "CN=Nested,OU=Staff," + dom, C2},
		{"C2 primary-group edge", "CN=bob,OU=Staff," + dom, C2},
		{"C3 AdminSDHolder", "CN=AdminSDHolder,CN=System," + dom, C3},
		{"C4 krbtgt", "CN=krbtgt,CN=Users," + dom, C4},
		{"C4 RODC krbtgt", "CN=krbtgt_1234,CN=Users," + dom, C4},
		{"C5 DC by SERVER_TRUST", "CN=DC2,OU=Servers," + dom, C5},
		{"C5 DC in default OU", "CN=DC1,OU=Domain Controllers," + dom, C5},
		{"C6 Domain Controllers OU", "OU=Domain Controllers," + dom, C6},
		{"C6 OU holding a moved DC", "OU=Servers," + dom, C6},
		{"C7 domain head", dom, C7},
		{"C7 configuration", cfg, C7},
		{"C7 schema", "CN=Schema," + cfg, C7},
		{"C8 CN=System", "CN=System," + dom, C8},
		{"C8 RID Manager", "CN=RID Manager$,CN=System," + dom, C8},
		{"C8 KDS root keys", "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services," + cfg, C8},
		{"C9 GPO on domain head", gpoDN(gDom), C9},
		{"C9 GPO on DC OU", gpoDN(gDCOU), C9},
		{"C9 GPO on OU holding a DC", gpoDN(gServ), C9},
		{"C9 GPO on DC site (disabled link)", gpoDN(gSite), C9},
		{"C9 GPO on OU above a C2 account", gpoDN(gAdmins), C9},
		{"C10 template", "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services," + cfg, C10},
		{"C11 DCSync user", "CN=svc-sync,OU=Staff," + dom, C11},
		{"C11 DCSync group", "CN=repl-group,OU=Staff," + dom, C11},
		{"C11 member of DCSync group", "CN=grp-member,OU=Staff," + dom, C11},
		{"C12 unconstrained", "CN=svc-unc,OU=Staff," + dom, C12},
		{"C12 constrained to DC", "CN=app1,OU=Workstations," + dom, C12},
		{"C12 RBCD on DC", "CN=rbcd-user,OU=Staff," + dom, C12},
		{"C13 DnsAdmins", "CN=DnsAdmins,CN=Users," + dom, C13},
		{"C13 DnsAdmins member", "CN=frank,OU=Staff," + dom, C13},
		{"C14 AZUREADSSOACC$", "CN=AZUREADSSOACC,OU=Servers," + dom, C14},
		{"C15 site holding a DC", "CN=Default-First-Site-Name,CN=Sites," + cfg, C15},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			res, err := c.Classify(context.Background(), ref(t, r.dn), known())
			if err != nil || !res.Tier0 || res.Unknown || !has(res, r.want) {
				t.Fatalf("%+v %v", res, err)
			}
		})
	}
	plain := []string{
		"CN=carol,OU=Staff," + dom, "CN=Sales,OU=Staff," + dom, "OU=Staff," + dom, "OU=Workstations," + dom,
		"CN=ws1,OU=Workstations," + dom,
		"CN=erin,OU=Staff," + dom,        // stale adminCount=1 is not membership
		"CN=half,OU=Staff," + dom,        // only one of the two DCSync rights
		"CN=app2,OU=Workstations," + dom, // delegation to a non-DC service
		gpoDN(gStaff), gpoDN(gBranch),    // linked only where no tier0 lives
		"CN=Branch,CN=Sites," + cfg,                      // a site without a DC
		"CN=Group Policy Creator Owners,CN=Users," + dom, // sensitive, not tier0
		"CN=Services," + cfg,
	}
	for _, p := range plain {
		t.Run("plain "+p, func(t *testing.T) {
			res, err := c.Classify(context.Background(), ref(t, p), known())
			if err != nil || res.Tier0 || res.Unknown {
				t.Fatalf("%+v %v", res, err)
			}
		})
	}
}

// AC1: a user added to Domain Admins after the last classification is tier0 at the next call, with
// adminCount unset (live re-read, never trusted from the attribute).
func TestADLiveReadAfterMembershipChange(t *testing.T) {
	f := forest()
	c := NewAD(f)
	target := ref(t, "CN=carol,OU=Staff,"+dom)
	if r, err := c.Classify(context.Background(), target, known()); err != nil || r.Tier0 {
		t.Fatalf("before: %+v %v", r, err)
	}
	f.find("CN=Domain Admins,CN=Users," + dom).attrs["member"] = append(f.find("CN=Domain Admins,CN=Users," + dom).attrs["member"], "CN=carol,OU=Staff,"+dom)
	if len(f.find("CN=carol,OU=Staff," + dom).attrs["admincount"]) != 0 {
		t.Fatal("fixture has adminCount")
	}
	r, err := c.Classify(context.Background(), target, known())
	if err != nil || !r.Tier0 || !has(r, C2) {
		t.Fatalf("after: %+v %v", r, err)
	}
}

// AC3: C16 for candidate, matched, broken (and unspecified: inconsistent counts).
func TestADC16(t *testing.T) {
	f := forest()
	c := NewAD(f)
	carol := f.find("CN=carol,OU=Staff," + dom)
	for _, st := range []State{StateCandidate, StateMatched, StateBroken, StateUnspecified} {
		in := ADInput{CorrelationKnown: true, Correlated: []Peer{{ADObject: carol.guid.String(), State: st}}}
		r, err := c.Classify(context.Background(), ref(t, carol.dn), in)
		if err != nil || !r.Tier0 || !has(r, C16) {
			t.Errorf("state %d: %+v %v", st, r, err)
		}
	}
	other := ADInput{CorrelationKnown: true, Correlated: []Peer{{ADObject: f.find("CN=erin,OU=Staff," + dom).guid.String(), State: StateMatched}}}
	if r, err := c.Classify(context.Background(), ref(t, carol.dn), other); err != nil || r.Tier0 {
		t.Errorf("correlation of another object: %+v %v", r, err)
	}
	for name, in := range map[string]ADInput{
		"statement absent": {},
		"bad guid":         {CorrelationKnown: true, Correlated: []Peer{{ADObject: "nope"}}},
	} {
		if r, err := c.Classify(context.Background(), ref(t, carol.dn), in); err == nil || !r.Tier0 || !r.Unknown {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
}

// AC4: a read error anywhere makes the target tier0 and reports the error.
func TestADReadErrorFailsClosed(t *testing.T) {
	for _, fail := range []string{"Public Key Services", "OU=Domain Controllers", "CN=Sites", "AdminSDHolder", "CN=Policies"} {
		f := forest()
		f.failDN = fail
		r, err := NewAD(f).Classify(context.Background(), ref(t, "CN=carol,OU=Staff,"+dom), known())
		if err == nil || !r.Tier0 || !r.Unknown {
			t.Errorf("%s: %+v %v", fail, r, err)
		}
	}
	// A target that cannot be resolved is unknown too.
	r, err := NewAD(forest()).Classify(context.Background(), ref(t, "CN=ghost,"+dom), known())
	if err == nil || !r.Tier0 || !r.Unknown || ad.CodeOf(errors.Unwrap(err)) != ad.CodeObjectNotFound {
		t.Errorf("ghost: %+v %v", r, err)
	}
}

func TestADMalformedInputsFailClosed(t *testing.T) {
	f := forest()
	f.find(dom).attrs["gplink"] = []string{"[LDAP://garbage"}
	if r, err := NewAD(f).Classify(context.Background(), ref(t, "CN=carol,OU=Staff,"+dom), known()); err == nil || !r.Unknown {
		t.Errorf("gPLink: %+v %v", r, err)
	}
	f = forest()
	f.find(dom).raw["nTSecurityDescriptor"] = []byte{1, 0, 4}
	if r, err := NewAD(f).Classify(context.Background(), ref(t, "CN=carol,OU=Staff,"+dom), known()); err == nil || !r.Unknown {
		t.Errorf("sd: %+v %v", r, err)
	}
	f = forest()
	delete(f.find(dom).attrs, "wellknownobjects")
	if r, err := NewAD(f).Classify(context.Background(), ref(t, "CN=carol,OU=Staff,"+dom), known()); err == nil || !r.Unknown {
		t.Errorf("wellKnownObjects: %+v %v", r, err)
	}
}

// AC5: designations add; omitting a computed entry cannot remove it.
func TestADDesignations(t *testing.T) {
	f := forest()
	c := NewAD(f)
	staff := ref(t, "OU=Staff,"+dom)
	in := known()
	in.Designated = []dn.ObjectRef{staff, ref(t, "CN=ghost,"+dom)} // a designation of nothing is ignored
	r, err := c.Classify(context.Background(), staff, in)
	if err != nil || !r.Tier0 || !has(r, Designated) {
		t.Fatalf("designated OU: %+v %v", r, err)
	}
	// by GUID
	g := dn.GUIDRef(f.find("CN=Sales,OU=Staff," + dom).guid)
	in.Designated = []dn.ObjectRef{g}
	if r, err := c.Classify(context.Background(), g, in); err != nil || !has(r, Designated) {
		t.Fatalf("designated by GUID: %+v %v", r, err)
	}
	// A designation of something else, or none at all, leaves the computed entry in place.
	da := ref(t, "CN=Domain Admins,CN=Users,"+dom)
	for _, d := range [][]dn.ObjectRef{nil, {staff}} {
		in := known()
		in.Designated = d
		r, err := c.Classify(context.Background(), da, in)
		if err != nil || !r.Tier0 || !has(r, C1) || has(r, Designated) {
			t.Errorf("computed entry lost: %+v %v", r, err)
		}
	}
	// A plain object stays plain without a designation.
	if r, _ := c.Classify(context.Background(), staff, known()); r.Tier0 {
		t.Errorf("OU=Staff tier0 without designation: %+v", r)
	}
}

func TestSnapshotDeterministic(t *testing.T) {
	a, err1 := NewAD(forest()).Snapshot(context.Background())
	b, err2 := NewAD(forest()).Snapshot(context.Background())
	if err1 != nil || err2 != nil || a.Len() != b.Len() || a.Len() == 0 {
		t.Fatalf("%v %v %d %d", err1, err2, a.Len(), b.Len())
	}
	var zero guid.GUID
	if len(a.Bases(zero)) != 0 {
		t.Error("zero GUID has bases")
	}
}

func TestQueryFilterEscapes(t *testing.T) {
	f, err := Query{Classes: []string{"group"}, Eq: []AttrEq{{Attr: "sAMAccountName", Value: "a)(cn=*\\"}}, UACAny: 0x2000}.filter()
	if err != nil {
		t.Fatal(err)
	}
	r, err := ldapfilter.Render(f, ad.DefaultSchema())
	if err != nil {
		t.Fatal(err)
	}
	want := `(&(|(objectClass=group))(sAMAccountName=a\29\28cn=\2a\5c)(userAccountControl:1.2.840.113556.1.4.804:=8192))`
	if r.String() != want {
		t.Errorf("got %s", r.String())
	}
	if _, err := (Query{Eq: []AttrEq{{Attr: "notInSchema", Value: "x"}}}).filter(); err == nil {
		t.Error("attribute outside the schema accepted")
	}
}

// The schema types schemaIDGUID/attributeSecurityGUID as octet strings and rightsGuid as a string; the
// C19 resolution queries must render against the real filter schema (fakes do not enforce kinds).
func TestQueryAnyGUIDRendersAgainstSchema(t *testing.T) {
	g, err := guid.Parse("ab721a55-1e2f-11d0-9819-00aa0040529b")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []Query{
		{AnyGUID: []AttrGUID{{Attr: "schemaIDGUID", Value: g}, {Attr: "attributeSecurityGUID", Value: g}}},
		{Classes: []string{"controlAccessRight"}, Eq: []AttrEq{{Attr: "rightsGuid", Value: g.String()}}},
	} {
		f, err := q.filter()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ldapfilter.Render(f, ad.DefaultSchema()); err != nil {
			t.Errorf("render %+v: %v", q, err)
		}
	}
}

func TestGrantsOf(t *testing.T) {
	good := sdBytes(aceSpec{sid: dsid + "-5", mask: 0x100, objType: &getChanges})
	d, aces, err := grantsOf(good)
	if err != nil || len(aces) != 1 || !aces[0].grants(getChanges) || aces[0].grants(getChangesAll) || !d.HasOwner {
		t.Fatalf("%+v %v", aces, err)
	}
	for i := 0; i < len(good); i++ { // every truncation is refused, never panics
		if _, _, err := grantsOf(good[:i]); err == nil {
			t.Errorf("truncation to %d bytes accepted", i)
		}
	}
	null := append([]byte(nil), good...)
	null[16], null[17], null[18], null[19] = 0, 0, 0, 0
	if _, _, err := grantsOf(null); err == nil {
		t.Error("NULL DACL accepted")
	}
	if _, _, err := grantsOf(sdBytes(aceSpec{sid: dsid + "-5", mask: 0x100, typ: 0x20})); err == nil {
		t.Error("ACE of an unknown type accepted")
	}
}

func classify(t *testing.T, f *fakeDir, target string) (ADResult, error) {
	t.Helper()
	return NewAD(f).Classify(context.Background(), ref(t, target), known())
}

// Security review #1: Get-Changes via group A, Get-Changes-All via group B; the common member can DCSync.
func TestC11SplitGrant(t *testing.T) {
	f := forest()
	f.add("CN=grpA,OU=Staff,"+dom, dsid+"-3001", group, "member", "CN=both,OU=Staff,"+dom, "member", "CN=onlyA,OU=Staff,"+dom)
	f.add("CN=grpB,OU=Staff,"+dom, dsid+"-3002", group, "member", "CN=both,OU=Staff,"+dom, "member", "CN=onlyB,OU=Staff,"+dom)
	for i, n := range []string{"both", "onlyA", "onlyB"} {
		f.add("CN="+n+",OU=Staff,"+dom, fmt.Sprintf("%s-%d", dsid, 3010+i), user)
	}
	root := f.find(dom)
	root.raw["nTSecurityDescriptor"] = sdBytes(
		aceSpec{sid: dsid + "-3001", mask: 0x100, objType: &getChanges},
		aceSpec{sid: dsid + "-3002", mask: 0x100, objType: &getChangesAll})
	if r, err := classify(t, f, "CN=both,OU=Staff,"+dom); err != nil || !r.Tier0 || !has(r, C11) {
		t.Errorf("both: %+v %v", r, err)
	}
	for _, n := range []string{"onlyA", "onlyB"} {
		if r, err := classify(t, f, "CN="+n+",OU=Staff,"+dom); err != nil || r.Tier0 {
			t.Errorf("%s: %+v %v", n, r, err)
		}
	}
}

// Security review #2: broad token SIDs with no object must not be skipped.
func TestUnresolvableBroadSIDFailsClosed(t *testing.T) {
	f := forest()
	f.find(dom).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: "S-1-5-11", mask: 0x100}) // Authenticated Users, all extended rights
	if r, err := classify(t, f, "CN=carol,OU=Staff,"+dom); err == nil || !r.Tier0 || !r.Unknown {
		t.Errorf("auth users DCSync: %+v %v", r, err)
	}
	f = forest()
	f.find("CN=DC2,OU=Servers," + dom).raw["msDS-AllowedToActOnBehalfOfOtherIdentity"] = sdBytes(aceSpec{sid: "S-1-1-0", mask: 0x10})
	if r, err := classify(t, f, "CN=ws1,OU=Workstations,"+dom); err == nil || !r.Tier0 || !r.Unknown {
		t.Errorf("everyone RBCD: %+v %v", r, err)
	}
}

// Security review #3: delegation to a DC's alias SPN host or additional DNS host name.
func TestC12DelegationToDCAlias(t *testing.T) {
	for _, attr := range []string{"servicePrincipalName", "msDS-AdditionalDnsHostName"} {
		f := forest()
		v := "dcalias.lab.test"
		if attr == "servicePrincipalName" {
			v = "HOST/dcalias.lab.test"
		}
		o := f.find("CN=DC1,OU=Domain Controllers," + dom)
		o.attrs[strings.ToLower(attr)] = append(o.attrs[strings.ToLower(attr)], v)
		f.find("CN=app2,OU=Workstations," + dom).attrs["msds-allowedtodelegateto"] = []string{"cifs/dcalias.lab.test"}
		if r, err := classify(t, f, "CN=app2,OU=Workstations,"+dom); err != nil || !r.Tier0 || !has(r, C12) {
			t.Errorf("%s: %+v %v", attr, r, err)
		}
	}
}

// Security review #4: a group in the walk without objectSid fails closed.
func TestMembershipWalkGroupWithoutSIDFailsClosed(t *testing.T) {
	f := forest()
	f.add("CN=nosid,OU=Staff,"+dom, "", group)
	da := f.find("CN=Domain Admins,CN=Users," + dom)
	da.attrs["member"] = append(da.attrs["member"], "CN=nosid,OU=Staff,"+dom)
	if r, err := classify(t, f, "CN=carol,OU=Staff,"+dom); err == nil || !r.Tier0 || !r.Unknown {
		t.Errorf("%+v %v", r, err)
	}
}

// T-0268 / T-0263: every DN map key goes through ObjectRef.ForRequest. A Domain Admins member whose
// DN cannot be requested (opaque #hex RDN) or renders over dn.MaxDNLen must leave the classification
// Tier0+Unknown with the dn error wrapped - never silently dropped from the walk.
func TestMembershipWalkUnrequestableDNFailsClosed(t *testing.T) {
	// 5000 '=' signs are 5 KB as input but render as \3D (3 bytes each) well past MaxDNLen.
	long := "CN=" + strings.Repeat("=", dn.MaxDNLen/3) + ",OU=Staff," + dom
	if len(long) > dn.MaxDNLen {
		t.Fatalf("fixture must parse: input %d > MaxDNLen", len(long))
	}
	for _, c := range []struct {
		name, member string
		kind         dn.Kind
	}{
		{"opaque hex RDN", "1.3.6.1.4.1.1466.0=#04024869,OU=Staff," + dom, dn.NotRequestable},
		{"renders over MaxDNLen", long, dn.TooLong},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := dn.Parse(c.member, dn.Strict); err != nil {
				t.Fatalf("fixture must parse under Strict (the walk's mode): %v", err)
			}
			f := forest()
			da := f.find("CN=Domain Admins,CN=Users," + dom)
			da.attrs["member"] = append(da.attrs["member"], c.member)
			r, err := classify(t, f, "CN=carol,OU=Staff,"+dom)
			if err == nil || !r.Tier0 || !r.Unknown {
				t.Fatalf("want Tier0+Unknown+error, got %+v %v", r, err)
			}
			if !errors.Is(err, &dn.Error{Kind: c.kind}) || dn.KindOf(err) != c.kind {
				t.Errorf("want error wrapping dn %s, got %v", c.kind, err)
			}
		})
	}
}
