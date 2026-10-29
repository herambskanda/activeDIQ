package tier0

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
)

// TM-D27 test table (threat-model §6.4 proof TM-F-T0GUARD, T-0235 additions). Every positive case has
// a negative twin. Samba proves the LDAP semantics only; SDProp, adminCount on DC objects and the
// owner reset need the Windows lab (T-0226) and are not claimed here.

const (
	dcDN   = "CN=DC1,OU=Domain Controllers," + dom
	dcOUDN = "OU=Domain Controllers," + dom
	daDN   = "CN=Domain Admins,CN=Users," + dom
	eaDN   = "CN=Enterprise Admins,CN=Users," + dom
	krbDN  = "CN=krbtgt,CN=Users," + dom
)

// grant gives user rid the ace on the object, keeping the default Domain Admins ACE.
func grant(f *fakeDir, objDN string, rid int, mask uint32, objType *guid.GUID) {
	id := fmt.Sprintf("%s-%d", dsid, rid)
	o := f.find(objDN)
	o.raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: dsid + "-512", mask: gAll}, aceSpec{sid: id, mask: mask, objType: objType})
}

func TestC19GroupMember(t *testing.T) { // T0-C19-GROUP-MEMBER
	f := forest()
	us, twin := u(f, "gm", 5001), u(f, "gm2", 5002)
	grant(f, daDN, 5001, wProp, &memberID)
	grant(f, "CN=Sales,OU=Staff,"+dom, 5002, wProp, &memberID) // not a C1 group
	wantBasis(t, f, us, C19, true)
	wantBasis(t, f, twin, C19, false)
	// Property-set coverage: the Membership property set names member through attributeSecurityGUID.
	set := mustGUID("bc0ac240-79a9-11d0-9020-00c04fc2d4cf")
	f2 := forest()
	u2 := u(f2, "ps", 5003)
	f2.find("CN=member,CN=Schema," + cfg).raw["attributeSecurityGUID"] = set.Bytes()
	grant(f2, daDN, 5003, wProp, &set)
	wantBasis(t, f2, u2, C19, true)
}

func TestC19GroupACL(t *testing.T) { // T0-C19-GROUP-ACL
	for _, m := range []uint32{wDACL, wOwner, gAll, gWrite, wProp} {
		f := forest()
		us := u(f, "ga", 5010)
		grant(f, eaDN, 5010, m, nil)
		wantBasis(t, f, us, C19, true)
	}
	// Account Operators (excluded by dwAdminSDExMask) and a renamed DnsAdmins.
	f := forest()
	f.add("CN=Account Operators,CN=Builtin,"+dom, "S-1-5-32-548", group)
	f.find("CN=Account Operators,CN=Builtin," + dom).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: dsid + "-512", mask: gAll})
	us, un := u(f, "ao", 5011), u(f, "dns", 5012)
	grant(f, "CN=Account Operators,CN=Builtin,"+dom, 5011, wDACL, nil)
	dns := f.find("CN=DnsAdmins,CN=Users," + dom)
	grant(f, dns.dn, 5012, wDACL, nil)
	dns.attrs["samaccountname"] = []string{"NetOps"}
	wantBasis(t, f, us, C19, true)
	r, err := NewAD(f).Classify(t.Context(), ref(t, un), ADInput{CorrelationKnown: true, PinnedC13: []guid.GUID{dns.guid}})
	if err != nil || !has(r, C19) {
		t.Errorf("renamed DnsAdmins pinned: %+v %v", r, err)
	}
	// Twin: read and a non-member property write do nothing.
	f = forest()
	tw := u(f, "gt", 5013)
	grant(f, daDN, 5013, wProp|rProp, &descID)
	wantBasis(t, f, tw, C19, false)
}

func TestC19SelfMembership(t *testing.T) { // T0-C19-SELFMEM
	f := forest()
	us, twin := u(f, "sm", 5020), u(f, "smC1", 5021)
	grant(f, "CN=Enterprise Admins,CN=Users,"+dom, 5020, 0x8, &memberID)
	grant(f, daDN, 5021, 0x8, &memberID)
	f.find(daDN).attrs["member"] = append(f.find(daDN).attrs["member"], twin) // already tier0 through C2
	wantBasis(t, f, us, C19, true)
	wantBasis(t, f, twin, C19, false)
	wantBasis(t, f, twin, C2, true)
}

func TestC19Krbtgt(t *testing.T) { // T0-C19-KRBTGT
	reset := resetPwdID
	for _, obj := range []string{krbDN, "CN=krbtgt_1234,CN=Users," + dom} {
		f := forest()
		us, tw := u(f, "kr", 5030), u(f, "krtwin", 5031)
		f.find(obj).raw["nTSecurityDescriptor"] = sdBytes(
			aceSpec{sid: dsid + "-5030", mask: allExt, objType: &reset},
			aceSpec{sid: dsid + "-5031", mask: rProp})
		wantBasis(t, f, us, C19, true)
		wantBasis(t, f, tw, C19, false)
	}
	for _, p := range []*guid.GUID{&unicodePwdID, &keyCredID, &spnID, &uacID} {
		f := forest()
		us := u(f, "krp", 5032)
		grant(f, krbDN, 5032, wProp, p)
		wantBasis(t, f, us, C19, true)
	}
	// All extended rights on RID 500.
	f := forest()
	us := u(f, "adm", 5033)
	grant(f, "CN=Administrator,CN=Users,"+dom, 5033, allExt, nil)
	wantBasis(t, f, us, C19, true)
}

func TestC19DCShadow(t *testing.T) { // T0-C19-DC-SHADOW
	for _, p := range []*guid.GUID{&keyCredID, &rbcdID} {
		f := forest()
		us := u(f, "sh", 5040)
		grant(f, dcDN, 5040, wProp, p)
		wantBasis(t, f, us, C19, true)
	}
	f := forest()
	tw := u(f, "shtwin", 5041)
	grant(f, dcDN, 5041, wProp, &descID)
	wantBasis(t, f, tw, C19, false)
}

func TestC19DCMoved(t *testing.T) { // T0-C19-DC-MOVED: DC2 lives in OU=Servers, outside the DC OU
	f := forest()
	us := u(f, "mv", 5050)
	grant(f, "CN=DC2,OU=Servers,"+dom, 5050, gWrite, nil)
	wantBasis(t, f, us, C19, true)
}

func TestC19DCOU(t *testing.T) { // T0-C19-DCOU-GPLINK
	f := forest()
	us := u(f, "lk", 5060)
	grant(f, dcOUDN, 5060, wProp, &gpLinkID)
	wantBasis(t, f, us, C19, true)
	f = forest()
	us = u(f, "cc", 5061)
	grant(f, dcOUDN, 5061, 0x1, &gpcID)
	wantBasis(t, f, us, C19, true)
	f = forest() // twin: the same right on a sibling OU
	tw := u(f, "sib", 5062)
	grant(f, "OU=Workstations,"+dom, 5062, wProp, &gpLinkID)
	wantBasis(t, f, tw, C19, false)
	f = forest() // CreateChild of a class outside the list
	tw = u(f, "ccu", 5063)
	grant(f, dcOUDN, 5063, 0x1, &userClassID)
	wantBasis(t, f, tw, C19, false)
}

func TestC19DCHolder(t *testing.T) { // T0-C19-DCOU-HOLDER
	f := forest()
	us := u(f, "hold", 5070)
	grant(f, "OU=Servers,"+dom, 5070, wDACL, nil)
	wantBasis(t, f, us, C19, true)
}

func TestC19GPO(t *testing.T) { // T0-C19-GPO
	f := forest()
	us, tw := u(f, "gpo", 5080), u(f, "gpotwin", 5081)
	grant(f, gpoDN(gDCOU), 5080, gWrite, nil)  // linked to the DC OU
	grant(f, gpoDN(gStaff), 5081, gWrite, nil) // linked to an unrelated OU
	wantBasis(t, f, us, C19, true)
	wantBasis(t, f, tw, C19, false)
}

func TestC19Owner(t *testing.T) { // T0-C19-OWNER
	for _, ownerRights := range []bool{false, true} {
		f := forest()
		o := u(f, "own", 5090)
		aces := []aceSpec{{sid: dsid + "-512", mask: gAll}}
		if ownerRights {
			aces = append(aces, aceSpec{sid: "S-1-3-4", mask: 0x20000})
		}
		f.find(dcDN).raw["nTSecurityDescriptor"] = sdOwned(dsid+"-5090", aces...)
		wantBasis(t, f, o, C19, true)
	}
}

func TestC19GroupTrustee(t *testing.T) { // T0-C19-GROUPTRUSTEE
	f := forest()
	f.add("CN=ctl19,OU=Staff,"+dom, dsid+"-5100", group, "member", "CN=inner19,OU=Staff,"+dom)
	f.add("CN=inner19,OU=Staff,"+dom, dsid+"-5101", group, "member", "CN=nested19,OU=Staff,"+dom)
	nested := u(f, "nested19", 5102)
	prim := u(f, "prim19", 5103, "primaryGroupID", "5100")
	out := u(f, "out19", 5104)
	grant(f, daDN, 5100, wProp, &memberID)
	wantBasis(t, f, nested, C19, true)
	wantBasis(t, f, prim, C19, true)
	wantBasis(t, f, out, C19, false)
}

func TestC19Broad(t *testing.T) { // T0-C19-BROAD
	f := forest()
	f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: "S-1-5-11", mask: wProp, objType: &memberID})
	r, err := classify(t, f, "CN=carol,OU=Staff,"+dom)
	if err == nil || !r.Tier0 || !r.Unknown || !strings.Contains(err.Error(), "S-1-5-11") {
		t.Errorf("Authenticated Users WP member: %+v %v", r, err)
	}
}

func TestC19Ignore(t *testing.T) { // T0-C19-IGNORE
	f := forest()
	carol := "CN=carol,OU=Staff," + dom
	f.find(dcDN).raw["nTSecurityDescriptor"] = sdBytes(
		aceSpec{sid: "S-1-5-18", mask: gAll},
		aceSpec{sid: "S-1-5-9", mask: gAll},
		aceSpec{sid: "S-1-5-498", mask: wProp},
		aceSpec{sid: "S-1-5-10", mask: gAll},
		aceSpec{sid: "S-1-3-0", mask: gAll, flags: aceInheritOnly},
		aceSpec{sid: dsid + "-516", mask: gAll}, // Domain Controllers (C1)
	)
	wantBasis(t, f, carol, C19, false)
	if _, err := classify(t, f, carol); err != nil {
		t.Errorf("default DC ACEs raised: %v", err)
	}
	// A non-listed well-known SID with the same ACE is a finding (Everyone).
	f.find(dcDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: "S-1-1-0", mask: wProp})
	if _, err := classify(t, f, carol); err == nil {
		t.Error("Everyone with a takeover right was ignored")
	}
}

func TestC19Callback(t *testing.T) { // T0-C19-CALLBACK
	for _, typ := range []byte{0x09, 0x0B} {
		f := forest()
		us := u(f, "cb19", 5110)
		f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: dsid + "-5110", mask: wDACL, typ: typ, junk: 4})
		wantBasis(t, f, us, C19, true)
	}
	f := forest()
	u(f, "cbbad19", 5111)
	bad := sdBytes(aceSpec{sid: dsid + "-5111", mask: wDACL, typ: 0x09, junk: 4})
	bad[20+8+2] = 6
	f.find(daDN).raw["nTSecurityDescriptor"] = bad
	if r, err := classify(t, f, "CN=carol,OU=Staff,"+dom); err == nil || !r.Tier0 || !r.Unknown {
		t.Errorf("malformed callback: %+v %v", r, err)
	}
}

func TestC19Live(t *testing.T) { // T0-C19-LIVE
	f := forest()
	us := u(f, "late19", 5120)
	wantBasis(t, f, us, C19, false)
	grant(f, daDN, 5120, wProp, &memberID) // granted after "Verify"
	wantBasis(t, f, us, C19, true)
}

func TestC19Fail(t *testing.T) { // T0-C19-FAIL
	for _, how := range []string{"missing", "denied", "noowner"} {
		f := forest()
		switch how {
		case "missing":
			delete(f.find(dcDN).raw, "nTSecurityDescriptor")
		case "denied":
			f.failDN = "CN=DC1,OU=Domain Controllers"
		case "noowner":
			f.find(dcDN).raw["nTSecurityDescriptor"] = sdOwned("", aceSpec{sid: dsid + "-512", mask: gAll})
		}
		if r, err := classify(t, f, "CN=carol,OU=Staff,"+dom); err == nil || !r.Tier0 || !r.Unknown {
			t.Errorf("%s: %+v %v", how, r, err)
		}
	}
	f := forest() // a schema object the rule needs is missing
	delete(f.find("CN=member,CN=Schema,"+cfg).attrs, "ldapdisplayname")
	if _, err := classify(t, f, "CN=carol,OU=Staff,"+dom); err == nil {
		t.Error("missing schema attribute accepted")
	}
}

func TestC19NotTransitive(t *testing.T) { // T0-C19-NOTTRANS (TM-R21 pinned)
	f := forest()
	us, v := u(f, "t19", 5130), u(f, "v19", 5131)
	grant(f, daDN, 5130, wProp, &memberID)
	f.find(us).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: dsid + "-5131", mask: wDACL})
	wantBasis(t, f, us, C19, true)
	wantBasis(t, f, v, C19, false)
}

func TestC19SelfMembershipGroup(t *testing.T) { // T0-C19-SELFMEM-GROUP
	f := forest()
	// A group that is tier0 through C10 (under Public Key Services) never had its members walked.
	pki := f.add("CN=PKIOps,CN=Public Key Services,CN=Services,"+cfg, dsid+"-5200", group, "member", "CN=inner20,OU=Staff,"+dom)
	_ = pki
	f.add("CN=inner20,OU=Staff,"+dom, dsid+"-5201", group, "member", "CN=nested20,OU=Staff,"+dom)
	nested := u(f, "nested20", 5202)
	prim := u(f, "prim20", 5203, "primaryGroupID", "5200")
	out := u(f, "out20", 5204)
	grant(f, daDN, 5200, 0x8, &memberID)
	wantBasis(t, f, nested, C19, true)
	wantBasis(t, f, prim, C19, true)
	wantBasis(t, f, out, C19, false)
}

func TestC19UnresolvedGUID(t *testing.T) { // T0-C19-UNRESOLVED-GUID
	ghost := mustGUID("11111111-2222-3333-4444-555555555555")
	cases := []struct {
		name string
		obj  string
		mask uint32
	}{
		{"WP", daDN, wProp},
		{"CA", krbDN, allExt},
		{"CC", dcOUDN, 0x1},
	}
	for _, c := range cases {
		f := forest()
		us, tw := u(f, "ug", 5300), u(f, "ugtwin", 5301)
		o := f.find(c.obj)
		o.raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: dsid + "-512", mask: gAll},
			aceSpec{sid: dsid + "-5300", mask: c.mask, objType: &ghost},
			aceSpec{sid: dsid + "-5301", mask: c.mask, objType: &descID})
		wantBasis(t, f, us, C19, true)
		wantBasis(t, f, tw, C19, false) // description resolves and is not a listed attribute
	}
}

// T-0380: a foreignSecurityPrincipal is the principal only for a domain account SID. Every other FSP
// (well-known and built-in SIDs, including the two-sub-authority ones) is a placeholder, so a rule-2
// right granted to its SID fails the snapshot closed naming the SID.
var defaultFSP = map[string]bool{"S-1-5-4": true, "S-1-5-9": true, "S-1-5-11": true, "S-1-5-17": true}

func TestBroadSIDWithFSPFailsClosed(t *testing.T) {
	sids := []string{"S-1-1-0", "S-1-5-4", "S-1-5-11", "S-1-5-15", "S-1-5-64-10", "S-1-5-64-14", "S-1-5-64-21",
		"S-1-5-65-1", "S-1-18-1", "S-1-18-2", "S-1-2-0", "S-1-2-1", "S-1-5-113", "S-1-5-114"}
	for _, w := range sids {
		for _, c := range []struct {
			name, obj string
			ace       aceSpec
		}{
			{"C19", daDN, aceSpec{sid: w, mask: wProp, objType: &memberID}},
			{"C17", dom, aceSpec{sid: w, mask: wDACL}},
		} {
			t.Run(c.name+"/"+w, func(t *testing.T) {
				f := forest()
				if !defaultFSP[w] {
					f.add("CN="+w+",CN=ForeignSecurityPrincipals,"+dom, w, cls("top", "foreignSecurityPrincipal"))
				}
				if c.name == "C19" {
					f.find(c.obj).raw["nTSecurityDescriptor"] = sdBytes(c.ace)
				} else {
					setSD(f, c.obj, c.ace)
				}
				r, err := classify(t, f, "CN=carol,OU=Staff,"+dom)
				if err == nil || !r.Tier0 || !r.Unknown || !strings.Contains(err.Error(), w) {
					t.Errorf("%+v %v", r, err)
				}
			})
		}
	}
}

// The twin: an FSP for a foreign-domain account is a real principal and is marked.
func TestForeignDomainAccountFSPStaysPrincipal(t *testing.T) {
	f := forest()
	fsp := "S-1-5-21-111-222-333-1105"
	f.add("CN="+fsp+",CN=ForeignSecurityPrincipals,"+dom, fsp, cls("top", "foreignSecurityPrincipal"))
	f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: fsp, mask: wProp, objType: &memberID})
	f.trust = map[string]TrustedPrincipal{fsp: {Kind: TrustUser}}
	wantBasisTrust(t, f, "CN=S-1-5-21-111-222-333-1105,CN=ForeignSecurityPrincipals,"+dom, C19, true)
	wantBasisTrust(t, f, "CN=carol,OU=Staff,"+dom, C19, false)
}

// TM-D27 rule 8 input: the snapshot exposes each rule-2 right and each owner with the C19 object it
// sits on, so the rights check blames the connector identity by object and right. The negative twin
// (a trustee with a read-only ACE) records nothing.
func TestC19RightsExposed(t *testing.T) { // T0-RIGHTS-C19 (classifier half)
	f := forest()
	u(f, "rt", 5200)
	u(f, "rt2", 5201)
	reset := resetPwdID
	f.find(krbDN).raw["nTSecurityDescriptor"] = sdBytes(
		aceSpec{sid: dsid + "-512", mask: gAll},
		aceSpec{sid: dsid + "-5200", mask: allExt, objType: &reset},
		aceSpec{sid: dsid + "-5201", mask: rProp})
	set, err := NewAD(f).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	krb := f.find(krbDN).guid
	var got []C19Right
	for _, r := range set.C19Rights() {
		if r.Object == krb && !r.Owner && r.Trustee.String() == dsid+"-5200" {
			got = append(got, r)
		}
		if r.Trustee.String() == dsid+"-5201" {
			t.Fatalf("read-only trustee recorded: %+v", r)
		}
	}
	if len(got) != 1 || got[0].ObjectType == nil || *got[0].ObjectType != reset || got[0].Mask&allExt == 0 {
		t.Fatalf("rights on krbtgt: %+v", got)
	}
	owners := 0
	for _, r := range set.C19Rights() {
		if r.Owner && r.Object == krb {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("owner of krbtgt recorded %d times", owners)
	}
}

// A broad trustee (Everyone, Authenticated Users, INTERACTIVE) with a rule-2 right on a C19 object is
// recorded even when the default ForeignSecurityPrincipal placeholders for those SIDs exist, so the
// rights check (which matches the identity's whole token) can refuse. Regression for T-0362 review.
func TestC19RightsBroadTrusteeWithFSPs(t *testing.T) {
	for _, s := range []string{"S-1-1-0", "S-1-5-4", "S-1-5-11"} {
		f := forest()
		for _, p := range []string{"S-1-5-4", "S-1-5-9", "S-1-5-11", "S-1-5-17"} {
			f.add("CN="+p+",CN=ForeignSecurityPrincipals,"+dom, p, cls("top", "foreignSecurityPrincipal"))
		}
		f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: dsid + "-512", mask: gAll},
			aceSpec{sid: s, mask: wProp, objType: &memberID})
		set, err := NewAD(f).Snapshot(context.Background())
		if err != nil {
			t.Logf("%s: snapshot failed closed: %v", s, err) // refusal-by-failure is also allowed by rule 4
			continue
		}
		found := false
		for _, r := range set.C19Rights() {
			if r.Trustee.String() == s && r.Object == f.find(daDN).guid {
				found = true
			}
		}
		if !found {
			t.Errorf("%s WP member on Domain Admins not recorded as a C19 right", s)
		}
	}
}

// T-0382: a broad FSP nested anywhere in the membership closure of a group that holds a C19/C17 right
// (or of a tier0 group) puts every principal in that closure, yet tokenGroups never lists the group
// (Pre-Windows 2000 Compatible Access S-1-5-32-554 ⊇ Authenticated Users). The walk fails closed naming
// the group and the SID.
func TestNestedBroadFSPInTrusteeClosureFailsClosed(t *testing.T) {
	const pre2k = "S-1-5-32-554"
	for _, w := range []string{"S-1-1-0", "S-1-5-4", "S-1-5-11", "S-1-5-15", "S-1-5-2"} {
		for _, c := range []string{"C19", "C17", "C19nested"} {
			t.Run(c+"/"+w, func(t *testing.T) {
				f := forest()
				fspDN := "CN=" + w + ",CN=ForeignSecurityPrincipals," + dom
				f.add(fspDN, w, cls("top", "foreignSecurityPrincipal"))
				member := fspDN
				if c == "C19nested" {
					f.add("CN=inner382,CN=Builtin,"+dom, "S-1-5-32-900", group, "member", fspDN)
					member = "CN=inner382,CN=Builtin," + dom
				}
				f.add("CN=Pre-Windows 2000 Compatible Access,CN=Builtin,"+dom, pre2k, group, "member", member)
				if c == "C17" {
					setSD(f, dom, aceSpec{sid: pre2k, mask: wDACL})
				} else {
					f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: pre2k, mask: wProp, objType: &memberID})
				}
				r, err := classify(t, f, "CN=carol,OU=Staff,"+dom)
				if err == nil || !r.Tier0 || !r.Unknown || !strings.Contains(err.Error(), w) ||
					(c != "C19nested" && !strings.Contains(err.Error(), "Compatible Access")) {
					t.Errorf("%+v %v", r, err)
				}
			})
		}
	}
}

// The twin: a foreign-domain account FSP nested in a trustee group is a real principal, not a failure.
func TestNestedForeignAccountFSPInTrusteeClosureIsMarked(t *testing.T) {
	f := forest()
	fsp := "S-1-5-21-111-222-333-1105"
	fspDN := "CN=" + fsp + ",CN=ForeignSecurityPrincipals," + dom
	f.add(fspDN, fsp, cls("top", "foreignSecurityPrincipal"))
	f.add("CN=ops382,CN=Builtin,"+dom, "S-1-5-32-901", group, "member", fspDN)
	f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: "S-1-5-32-901", mask: wProp, objType: &memberID})
	f.trust = map[string]TrustedPrincipal{fsp: {Kind: TrustUser}}
	wantBasisTrust(t, f, fspDN, C19, true)
	wantBasisTrust(t, f, "CN=carol,OU=Staff,"+dom, C19, false)
}

// T-0384: a foreign-domain FSP for a well-known group RID (Domain Users/Guests/Computers, ...) stands
// for every principal of that domain, so a right it holds fails the snapshot closed naming the SID;
// the well-known single accounts 500/501/502 stay a single principal.
func TestForeignBroadRIDFSPFailsClosed(t *testing.T) {
	for _, rid := range []string{"512", "513", "514", "515", "516", "525", "999"} {
		for _, c := range []string{"C19", "C17", "nested"} {
			t.Run(c+"/"+rid, func(t *testing.T) {
				f := forest()
				fsp := "S-1-5-21-111-222-333-" + rid
				fspDN := "CN=" + fsp + ",CN=ForeignSecurityPrincipals," + dom
				f.add(fspDN, fsp, cls("top", "foreignSecurityPrincipal"))
				switch c {
				case "C19":
					f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: fsp, mask: wProp, objType: &memberID})
				case "C17":
					setSD(f, dom, aceSpec{sid: fsp, mask: wDACL})
				default:
					f.add("CN=ops384,CN=Builtin,"+dom, "S-1-5-32-902", group, "member", fspDN)
					f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: "S-1-5-32-902", mask: wProp, objType: &memberID})
				}
				r, err := classify(t, f, "CN=carol,OU=Staff,"+dom)
				if err == nil || !r.Tier0 || !r.Unknown || !strings.Contains(err.Error(), fsp) {
					t.Errorf("%+v %v", r, err)
				}
			})
		}
	}
}

func TestForeignWellKnownAccountFSPStaysPrincipal(t *testing.T) {
	for _, rid := range []string{"500", "501", "502"} {
		f := forest()
		fsp := "S-1-5-21-111-222-333-" + rid
		f.add("CN="+fsp+",CN=ForeignSecurityPrincipals,"+dom, fsp, cls("top", "foreignSecurityPrincipal"))
		f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: fsp, mask: wProp, objType: &memberID})
		wantBasis(t, f, "CN="+fsp+",CN=ForeignSecurityPrincipals,"+dom, C19, true)
	}
}

func classifyTrust(t *testing.T, f *fakeDir, target string) (ADResult, error) {
	t.Helper()
	return NewAD(trustFakeDir{f}).Classify(context.Background(), ref(t, target), known())
}

func wantBasisTrust(t *testing.T, f *fakeDir, target string, b Basis, want bool) {
	t.Helper()
	r, err := classifyTrust(t, f, target)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	if has(r, b) != want {
		t.Errorf("%s: basis %v = %v, want %v (bases %v)", target, b, has(r, b), want, r.Bases)
	}
}

// T-0435: a foreign FSP with RID >= 1000 may be a custom group of the trusted domain. Without a trust
// lookup, with a failing one, or when the trust cannot identify it, a right it holds fails closed.
func TestForeignCustomRIDFSPFailsClosedWithoutTrustAnswer(t *testing.T) {
	fsp := "S-1-5-21-111-222-333-1105"
	for _, tc := range []string{"no-seam", "error", "unknown"} {
		for _, c := range []string{"C19", "C17", "nested"} {
			t.Run(tc+"/"+c, func(t *testing.T) {
				f := forest()
				fspDN := "CN=" + fsp + ",CN=ForeignSecurityPrincipals," + dom
				f.add(fspDN, fsp, cls("top", "foreignSecurityPrincipal"))
				switch c {
				case "C19":
					f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: fsp, mask: wProp, objType: &memberID})
				case "C17":
					setSD(f, dom, aceSpec{sid: fsp, mask: wDACL})
				default:
					f.add("CN=ops435,CN=Builtin,"+dom, "S-1-5-32-903", group, "member", fspDN)
					f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: "S-1-5-32-903", mask: wProp, objType: &memberID})
				}
				var r ADResult
				var err error
				switch tc {
				case "no-seam":
					r, err = classify(t, f, "CN=carol,OU=Staff,"+dom)
				case "error":
					f.trustErr = errors.New("trust unreachable")
					r, err = classifyTrust(t, f, "CN=carol,OU=Staff,"+dom)
				default:
					r, err = classifyTrust(t, f, "CN=carol,OU=Staff,"+dom)
				}
				if err == nil || !r.Tier0 || !r.Unknown || !strings.Contains(err.Error(), fsp) {
					t.Errorf("%+v %v", r, err)
				}
			})
		}
	}
}

// T-0435: resolved through the trust as a group, the FSPs of its members are marked too.
func TestForeignCustomGroupFSPMembersAreMarked(t *testing.T) {
	for _, c := range []string{"C19", "nested"} {
		t.Run(c, func(t *testing.T) {
			f := forest()
			grp, mem, other := "S-1-5-21-111-222-333-1200", "S-1-5-21-111-222-333-1201", "S-1-5-21-111-222-333-1202"
			dnOf := func(s string) string { return "CN=" + s + ",CN=ForeignSecurityPrincipals," + dom }
			for _, s := range []string{grp, mem, other} {
				f.add(dnOf(s), s, cls("top", "foreignSecurityPrincipal"))
			}
			f.trust = map[string]TrustedPrincipal{grp: {Kind: TrustGroup, Members: []sid.SID{mustSID(t, mem)}}}
			trustee := grp
			if c == "nested" {
				f.add("CN=ops435b,CN=Builtin,"+dom, "S-1-5-32-904", group, "member", dnOf(grp))
				trustee = "S-1-5-32-904"
			}
			f.find(daDN).raw["nTSecurityDescriptor"] = sdBytes(aceSpec{sid: trustee, mask: wProp, objType: &memberID})
			wantBasisTrust(t, f, dnOf(mem), C19, true)
			wantBasisTrust(t, f, dnOf(other), C19, false)
		})
	}
}

func mustSID(t *testing.T, s string) sid.SID {
	t.Helper()
	v, err := sid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
