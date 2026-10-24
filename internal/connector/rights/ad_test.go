package rights

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	adguid "github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	domS    = "S-1-5-21-1-2-3"
	idSIDt  = domS + "-1105"
	daSID   = domS + "-512"
	dusSID  = domS + "-513"
	nestSID = domS + "-1200"
)

// ---- a tiny in-memory directory: it implements reads, nothing of the check ----

type fakeAD struct {
	byGUID  map[string]*ad.Entry
	bySID   map[string]*ad.Entry
	byDN    map[string]*ad.Entry
	fail    map[string]error // key (guid text, "sid:<s>", lower dn) -> error from Read
	rbcd    []*ad.Entry
	findErr error
	attrs   map[string]SchemaObject // by lower name
	reads   []readCall
	next    uint16
}

type readCall struct {
	attrs []string
	sd    ad.SDFlags
}

func newFakeAD() *fakeAD {
	return &fakeAD{byGUID: map[string]*ad.Entry{}, bySID: map[string]*ad.Entry{}, byDN: map[string]*ad.Entry{},
		fail: map[string]error{}, attrs: map[string]SchemaObject{}}
}

func (f *fakeAD) gid() adguid.GUID {
	f.next++
	var g adguid.GUID
	g[0], g[1], g[15] = byte(f.next), byte(f.next>>8), 0xA5
	return g
}

// obj adds an object. kv holds string values by attribute; raw holds binary ones.
func (f *fakeAD) obj(dnText, sidText string, kv map[string][]string, raw map[string][][]byte) (*ad.Entry, adguid.GUID) {
	g := f.gid()
	m := map[string][][]byte{"objectGUID": {g.Bytes()}}
	for k, vs := range kv {
		for _, v := range vs {
			m[k] = append(m[k], []byte(v))
		}
	}
	for k, vs := range raw {
		m[k] = vs
	}
	if _, ok := m["nTSecurityDescriptor"]; ok && m["sDRightsEffective"] == nil {
		m["sDRightsEffective"] = [][]byte{[]byte("0")} // a DC always returns the constructed attribute
	}
	if sidText != "" {
		s, err := sid.Parse(sidText)
		if err != nil {
			panic(err)
		}
		m["objectSid"] = [][]byte{s.Bytes()}
	}
	e := ad.NewEntry(dnText, m)
	f.byGUID[g.String()] = e
	f.byDN[strings.ToLower(dnText)] = e
	if sidText != "" {
		f.bySID[sidText] = e
	}
	return e, g
}

func (f *fakeAD) Naming(context.Context) (tier0.Naming, error) {
	d, _ := dn.Parse("DC=lab,DC=test", dn.Strict)
	return tier0.Naming{Domain: d, RootDomain: d, Config: d, Schema: d}, nil
}

func (f *fakeAD) Get(ctx context.Context, ref dn.ObjectRef, attrs []string) (*ad.Entry, error) {
	return f.Read(ctx, ref, attrs, ad.ReadOptions{})
}

func (f *fakeAD) Find(_ context.Context, _ dn.DN, _ ad.Scope, _ tier0.Query, _ []string, fn func(*ad.Entry) error) error {
	if f.findErr != nil {
		return f.findErr
	}
	for _, e := range f.rbcd {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeAD) Read(_ context.Context, ref dn.ObjectRef, attrs []string, opts ad.ReadOptions) (*ad.Entry, error) {
	f.reads = append(f.reads, readCall{attrs, opts.SD})
	var key string
	var e *ad.Entry
	if g, ok := ref.GUID(); ok {
		key, e = g.String(), f.byGUID[g.String()]
	} else if s, ok := ref.SID(); ok {
		key, e = "sid:"+s.String(), f.bySID[s.String()]
	} else if d, ok := ref.DN(); ok {
		key = strings.ToLower(d.CanonicalString())
		e = f.byDN[key]
	}
	if err := f.fail[key]; err != nil {
		return nil, err
	}
	if e == nil {
		return nil, &ad.Error{Code: ad.CodeObjectNotFound}
	}
	return e, nil
}

func (f *fakeAD) SchemaByName(_ context.Context, name string, class bool) (SchemaObject, bool, error) {
	o, ok := f.attrs[strings.ToLower(name)]
	return o, ok && o.Class == class, nil
}

func (f *fakeAD) SchemaByID(_ context.Context, id adguid.GUID) (SchemaObject, bool, error) {
	for _, o := range f.attrs {
		if o.ID == id {
			return o, true, nil
		}
	}
	return SchemaObject{}, false, nil
}

func (f *fakeAD) schemaAttr(name string, flags int32) adguid.GUID {
	g := f.gid()
	f.attrs[strings.ToLower(name)] = SchemaObject{Name: name, ID: g, SearchFlags: flags}
	return g
}

func (f *fakeAD) schemaClass(name string) adguid.GUID {
	g := f.gid()
	f.attrs[strings.ToLower(name)] = SchemaObject{Name: name, ID: g, Class: true}
	return g
}

// ---- security descriptor builder ----

type tace struct {
	deny         bool
	flags        byte
	mask         uint32
	objType, inh *adguid.GUID
	trustee      string
}

func sdBytes(owner string, aces ...tace) []byte {
	var acl []byte
	for _, a := range aces {
		s, _ := sid.Parse(a.trustee)
		typ := byte(aceTypeAllowed)
		object := a.objType != nil || a.inh != nil
		switch {
		case a.deny && object:
			typ = aceTypeDeniedObject
		case a.deny:
			typ = aceTypeDenied
		case object:
			typ = aceTypeAllowedObject
		}
		body := binary.LittleEndian.AppendUint32(nil, a.mask)
		if object {
			var of uint32
			var rest []byte
			if a.objType != nil {
				of |= aceObjectTypePresent
				rest = append(rest, a.objType.Bytes()...)
			}
			if a.inh != nil {
				of |= aceInheritedPresent
				rest = append(rest, a.inh.Bytes()...)
			}
			body = binary.LittleEndian.AppendUint32(body, of)
			body = append(body, rest...)
		}
		body = append(body, s.Bytes()...)
		hdr := []byte{typ, a.flags, 0, 0}
		binary.LittleEndian.PutUint16(hdr[2:], uint16(4+len(body)))
		acl = append(acl, hdr...)
		acl = append(acl, body...)
	}
	o, _ := sid.Parse(owner)
	ob := o.Bytes()
	aclHdr := []byte{2, 0, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(aclHdr[2:], uint16(8+len(acl)))
	binary.LittleEndian.PutUint16(aclHdr[4:], uint16(len(aces)))
	sd := make([]byte, 20)
	sd[0] = 1
	binary.LittleEndian.PutUint16(sd[2:], 0x8004) // DACL present, self-relative
	binary.LittleEndian.PutUint32(sd[4:], 20)
	binary.LittleEndian.PutUint32(sd[16:], uint32(20+len(ob)))
	sd = append(sd, ob...)
	sd = append(sd, aclHdr...)
	return append(sd, acl...)
}

// ---- a baseline forest ----

type world struct {
	f        *fakeAD
	id       *ad.Entry
	idG      adguid.GUID
	da       *ad.Entry
	daG      adguid.GUID
	t0       *ad.Entry // a tier0 object other than the group
	t0G      adguid.GUID
	set      *tier0.ADSet
	tokens   []string
	attrMem  adguid.GUID
	attrConf adguid.GUID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	f := newFakeAD()
	w := &world{f: f}
	w.attrMem = f.schemaAttr("member", 0)
	w.attrConf = f.schemaAttr("msFVE-RecoveryPassword", searchFlagConfidential)
	for _, n := range neverDelegateAttrs {
		f.schemaAttr(n, 0)
	}
	w.da, w.daG = f.obj("CN=Domain Admins,CN=Users,DC=lab,DC=test", daSID, nil,
		map[string][][]byte{"nTSecurityDescriptor": {sdBytes(daSID, tace{mask: dsFullControl, trustee: daSID})}})
	w.t0, w.t0G = f.obj("CN=AdminSDHolder,CN=System,DC=lab,DC=test", "", nil,
		map[string][][]byte{"nTSecurityDescriptor": {sdBytes(daSID, tace{mask: dsFullControl, trustee: daSID})}})
	w.tokens = []string{dusSID, "S-1-1-0", "S-1-5-11"}
	w.id, w.idG = f.obj("CN=svc,CN=Users,DC=lab,DC=test", idSIDt, map[string][]string{"userAccountControl": {"512"}, "primaryGroupID": {"513"}}, nil)
	f.obj("CN=Domain Users,CN=Users,DC=lab,DC=test", dusSID, nil, nil)
	w.set = tier0.NewADSet()
	w.set.Add(w.daG, tier0.C1)
	w.set.Add(w.t0G, tier0.C3)
	return w
}

func (w *world) setTokens(extra ...string) {
	var raw [][]byte
	for _, t := range append(append([]string{}, w.tokens...), extra...) {
		s, _ := sid.Parse(t)
		raw = append(raw, s.Bytes())
	}
	w.putRaw(w.id, "tokenGroups", raw)
}

func (w *world) putRaw(e *ad.Entry, name string, v [][]byte) {
	m := map[string][][]byte{}
	for _, k := range []string{"objectGUID", "objectSid", "userAccountControl", "primaryGroupID", "memberOf", "tokenGroups", "nTSecurityDescriptor", "allowedAttributesEffective", "allowedChildClassesEffective", "sDRightsEffective", "msDS-AllowedToDelegateTo"} {
		if r := e.Raw(k); r != nil {
			m[k] = r
		}
	}
	m[name] = v
	ne := ad.NewEntry(e.DN, m)
	*e = *ne
}

func (w *world) put(e *ad.Entry, name string, vals ...string) {
	var raw [][]byte
	for _, v := range vals {
		raw = append(raw, []byte(v))
	}
	w.putRaw(e, name, raw)
}

func (w *world) run(t *testing.T, in ADInput) *ADResult {
	t.Helper()
	w.setTokens()
	ref, _ := dn.ParseObjectRef(w.id.DN)
	in.Identity = ref
	set := w.set
	in.Snapshot = func(context.Context) (*tier0.ADSet, error) { return set, nil }
	res, err := VerifyAD(context.Background(), w.f, in)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func codes(r *ADResult) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, fmt.Sprintf("%v/%s", f.Check, f.Code))
	}
	return out
}

func onlyKind(r *ADResult, k v1.FindingKind) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Kind == k {
			out = append(out, f)
		}
	}
	return out
}

func count(r *ADResult, code string) int {
	n := 0
	for _, f := range r.Findings {
		if f.Code == code {
			n++
		}
	}
	return n
}

func TestPass(t *testing.T) {
	w := newWorld(t)
	r := w.run(t, ADInput{})
	if r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS || !r.WriteGateOpenable || len(r.Findings) != 0 {
		t.Fatalf("%v %v", r.Verdict, codes(r))
	}
	if len(r.Checks) != 3 || len(r.Tier0Set) != 2 {
		t.Fatalf("checks %d set %d", len(r.Checks), len(r.Tier0Set))
	}
}

// AC4: no read the check makes can carry the SACL bit, and a non-admin identity (which cannot read
// the SACL) is not failed by it.
func TestNeverRequestsSACL(t *testing.T) {
	w := newWorld(t)
	r := w.run(t, ADInput{})
	if r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS {
		t.Fatal(codes(r))
	}
	sawSD := false
	for _, c := range w.f.reads {
		for _, a := range c.attrs {
			if strings.EqualFold(a, "nTSecurityDescriptor") || strings.EqualFold(a, attrSDRights) {
				sawSD = true
				if !c.sd.IsZero() && c.sd.Value()&8 != 0 {
					t.Fatalf("SACL bit requested: %d", c.sd.Value())
				}
			}
		}
	}
	if !sawSD {
		t.Fatal("no security descriptor read at all")
	}
	if _, err := ad.NewSDFlags(ad.SDPart(8)); err == nil {
		t.Fatal("a SACL request can be constructed")
	}
}

func TestMembershipPaths(t *testing.T) {
	w := newWorld(t)
	_, nestG := w.f.obj("CN=Nested,CN=Users,DC=lab,DC=test", nestSID, map[string][]string{"memberOf": {w.da.DN}, "primaryGroupID": {"513"}}, nil)
	w.put(w.id, "memberOf", "CN=Nested,CN=Users,DC=lab,DC=test")
	w.tokens = append(w.tokens, nestSID, daSID)
	r := w.run(t, ADInput{})
	if r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED {
		t.Fatalf("%v %v", r.Verdict, codes(r))
	}
	fs := onlyKind(r, v1.FindingKind_FINDING_KIND_TIER0_GROUP_MEMBERSHIP)
	if len(fs) != 1 || fs[0].Kind != v1.FindingKind_FINDING_KIND_TIER0_GROUP_MEMBERSHIP {
		t.Fatalf("%v", codes(r))
	}
	hops := fs[0].Source.GetMembership().Hops
	if len(hops) != 2 || guidText(hops[0].Group) != nestG.String() || guidText(hops[1].Group) != w.daG.String() {
		t.Fatalf("hops %v", hops)
	}
	if fs[0].ObjectTier0Basis[0] != tier0.C1 || fs[0].Qualifier != nestG.String() {
		t.Fatalf("basis/qualifier %v %s", fs[0].ObjectTier0Basis, fs[0].Qualifier)
	}
}

func TestMembershipPrimaryGroupEdge(t *testing.T) {
	w := newWorld(t)
	w.put(w.id, "primaryGroupID", "512")
	w.tokens = append(w.tokens, daSID)
	r := w.run(t, ADInput{})
	fs := onlyKind(r, v1.FindingKind_FINDING_KIND_TIER0_GROUP_MEMBERSHIP)
	if len(fs) != 1 {
		t.Fatalf("%v", codes(r))
	}
	h := fs[0].Source.GetMembership().Hops
	if len(h) != 1 || !h[0].PrimaryGroupEdge {
		t.Fatalf("hops %v", h)
	}
}

func TestDesignatedAndCorrelatedGroups(t *testing.T) {
	w := newWorld(t)
	_, g := w.f.obj("CN=Ops,CN=Users,DC=lab,DC=test", domS+"-1300", nil,
		map[string][][]byte{"nTSecurityDescriptor": {sdBytes(daSID, tace{mask: dsFullControl, trustee: daSID})}})
	w.put(w.id, "memberOf", "CN=Ops,CN=Users,DC=lab,DC=test")
	w.tokens = append(w.tokens, domS+"-1300")
	r := w.run(t, ADInput{Correlated: []adguid.GUID{g}})
	if len(r.Findings) != 1 || r.Findings[0].ObjectTier0Basis[0] != tier0.C16 {
		t.Fatalf("%v", codes(r))
	}
	r = w.run(t, ADInput{Designated: []adguid.GUID{g}})
	if len(r.Findings) != 1 || r.Findings[0].ObjectTier0Basis[0] != tier0.Designated {
		t.Fatalf("%v", codes(r))
	}
}

func TestStep2EffectiveRights(t *testing.T) {
	w := newWorld(t)
	w.put(w.da, "allowedAttributesEffective", "member")
	w.putRaw(w.da, "nTSecurityDescriptor", [][]byte{sdBytes(daSID)})
	w.put(w.da, "sDRightsEffective", "5")
	w.f.schemaClass("user")
	w.put(w.da, "allowedChildClassesEffective", "user")
	r := w.run(t, ADInput{})
	if r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED {
		t.Fatal(codes(r))
	}
	for _, c := range []string{CodeTier0Write, CodeTier0Child, CodeTier0WriteOwner, CodeTier0WriteDACL} {
		if count(r, c) != 1 {
			t.Errorf("%s: %v", c, codes(r))
		}
	}
	for _, f := range r.Findings {
		if f.Code == CodeTier0Write && (guidText(f.Right.GetAd().ObjectType) != w.attrMem.String() ||
			f.Source.GetEffectiveAttribute().Name != v1.EffectiveRightsAttributeName_EFFECTIVE_RIGHTS_ATTRIBUTE_NAME_ALLOWED_ATTRIBUTES_EFFECTIVE) {
			t.Errorf("attribute right: %+v", f.RightsFinding)
		}
	}
}

func TestStep3DACL(t *testing.T) {
	w := newWorld(t)
	w.tokens = append(w.tokens, nestSID)
	resetPw := rightResetPassword
	conf := w.attrConf
	cases := []struct {
		name string
		ace  tace
		code string
		n    int
	}{
		{"generic all", tace{mask: dsFullControl, trustee: idSIDt}, CodeTier0GenericAll, 1},
		{"write dac via group", tace{mask: maskWriteDAC, trustee: nestSID}, CodeTier0WriteDACL, 1},
		{"control access typed", tace{mask: dsControlAccess, objType: &resetPw, trustee: idSIDt}, CodeTier0Control, 1},
		{"control access all", tace{mask: dsControlAccess, trustee: idSIDt}, CodeTier0Control, 1},
		{"validated write", tace{mask: dsSelf, objType: &resetPw, trustee: idSIDt}, CodeTier0Validated, 1},
		{"confidential read", tace{mask: dsReadProp, objType: &conf, trustee: idSIDt}, CodeTier0Confid, 1},
		{"plain read of a normal attribute", tace{mask: dsReadProp, objType: &w.attrMem, trustee: idSIDt}, CodeTier0Confid, 0},
		{"inherit only skipped", tace{mask: maskWriteDAC, flags: aceFlagInheritOnly, trustee: idSIDt}, CodeTier0WriteDACL, 0},
		{"other trustee", tace{mask: maskWriteDAC, trustee: daSID}, CodeTier0WriteDACL, 0},
		{"authenticated users baseline is not the identity's", tace{mask: dsControlAccess, trustee: "S-1-5-11"}, CodeTier0Control, 0},
		{"deny first removes the grant", tace{}, CodeTier0WriteDACL, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aces := []tace{tc.ace}
			if tc.name == "deny first removes the grant" {
				aces = []tace{{deny: true, mask: maskWriteDAC, trustee: idSIDt}, {mask: maskWriteDAC, trustee: idSIDt}}
			}
			w.putRaw(w.t0, "nTSecurityDescriptor", [][]byte{sdBytes(daSID, aces...)})
			r := w.run(t, ADInput{})
			if got := count(r, tc.code); got != tc.n {
				t.Fatalf("%s x%d, want %d: %v", tc.code, got, tc.n, codes(r))
			}
			if tc.n > 0 {
				f := r.Findings[0]
				if f.Source.GetAce() == nil || f.Object == nil || f.ObjectTier0Basis[0] != tier0.C3 {
					t.Fatalf("shape %+v", f.RightsFinding)
				}
			}
		})
	}
}

func TestStep5Delegation(t *testing.T) {
	w := newWorld(t)
	w.put(w.id, "userAccountControl", fmt.Sprint(512|uacTrustedForDelegation|uacTrustedToAuthForDeleg))
	w.put(w.id, attrAllowedToDelegateTo, "ldap/dc1.lab.test")
	dc, dcG := w.f.obj("CN=DC1,OU=Domain Controllers,DC=lab,DC=test", "", nil,
		map[string][][]byte{attrRBCD: {sdBytes(daSID, tace{mask: dsFullControl, trustee: idSIDt})}})
	w.f.rbcd = []*ad.Entry{dc}
	r := w.run(t, ADInput{})
	for _, c := range []string{CodeDelegUncons, CodeDelegProto, CodeDelegConstr, CodeDelegRBCD} {
		if count(r, c) != 1 {
			t.Errorf("%s: %v", c, codes(r))
		}
	}
	for _, f := range r.Findings {
		if f.Code == CodeDelegRBCD && guidText(f.Object) != dcG.String() {
			t.Error("RBCD finding must name the DC")
		}
	}
	if r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED {
		t.Fatal(r.Verdict)
	}
}

// AC5: a read error in any step is never a pass.
func TestReadErrorsNeverPass(t *testing.T) {
	boom := errors.New("connection reset")
	for _, tc := range []struct {
		name string
		prep func(w *world, in *ADInput)
	}{
		{"tier0 object unreadable", func(w *world, _ *ADInput) { w.f.fail[w.t0G.String()] = boom }},
		{"security descriptor not returned", func(w *world, _ *ADInput) {
			w.putRaw(w.t0, "nTSecurityDescriptor", nil)
		}},
		{"security descriptor malformed", func(w *world, _ *ADInput) {
			w.putRaw(w.t0, "nTSecurityDescriptor", [][]byte{{1, 2, 3}})
		}},
		{"null dacl", func(w *world, _ *ADInput) {
			sd := sdBytes(daSID)
			binary.LittleEndian.PutUint16(sd[2:], 0x8000)
			w.putRaw(w.t0, "nTSecurityDescriptor", [][]byte{sd})
		}},
		{"group read fails", func(w *world, _ *ADInput) { w.f.fail["sid:"+dusSID] = boom }},
		{"rbcd search fails", func(w *world, _ *ADInput) { w.f.findErr = boom }},
		{"managed domain read fails", func(w *world, in *ADInput) {
			_, g := w.f.obj("DC=lab,DC=test", domS, nil, nil)
			w.f.fail[g.String()] = boom
			in.ManagedDomains = []adguid.GUID{g}
		}},
		{"managed root read fails", func(w *world, in *ADInput) {
			_, g := w.f.obj("OU=Managed,DC=lab,DC=test", "", nil, nil)
			w.f.fail[g.String()] = boom
			in.ManagedRoots = []adguid.GUID{g}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			var in ADInput
			tc.prep(w, &in)
			r := w.run(t, in)
			if r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY || r.WriteGateOpenable {
				t.Fatalf("%v openable=%v %v", r.Verdict, r.WriteGateOpenable, codes(r))
			}
			if count(r, CodeUnverifiedAD) == 0 {
				t.Fatalf("no COULD_NOT_VERIFY finding: %v", codes(r))
			}
		})
	}
}

func TestSnapshotErrorAndIdentityError(t *testing.T) {
	w := newWorld(t)
	w.setTokens()
	ref, _ := dn.ParseObjectRef(w.id.DN)
	r, err := VerifyAD(context.Background(), w.f, ADInput{Identity: ref,
		Snapshot: func(context.Context) (*tier0.ADSet, error) { return nil, errors.New("down") }})
	if err != nil || r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY || r.WriteGateOpenable {
		t.Fatalf("%v %v", r, err)
	}
	w.f.fail[w.idG.String()] = errors.New("down")
	gref := dn.GUIDRef(w.idG)
	if r, err := VerifyAD(context.Background(), w.f, ADInput{Identity: gref}); err == nil || r != nil || !errors.Is(err, errNoIdentity) {
		t.Fatalf("identity error must be returned, got %v %v", r, err)
	}
}

func TestV8MissingRead(t *testing.T) {
	w := newWorld(t)
	_, g := w.f.obj("DC=lab,DC=test", domS, nil, nil)
	w.f.fail[g.String()] = &ad.Error{Code: ad.CodeInsufficientRights}
	r := w.run(t, ADInput{ManagedDomains: []adguid.GUID{g}})
	if r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED || count(r, CodeMissingRead) != 1 || r.Checks[1].Outcome != v1.CheckOutcome_CHECK_OUTCOME_FAIL {
		t.Fatalf("%v %v", r.Verdict, codes(r))
	}
}

func TestV9ExcessAndMissing(t *testing.T) {
	w := newWorld(t)
	classUserG := w.f.schemaClass("user")
	w.f.schemaAttr("userAccountControl", 0)
	spn := w.f.attrs["serviceprincipalname"].ID
	ouE, ouG := w.f.obj("OU=Managed,DC=lab,DC=test", "", nil, nil)
	w.putRaw(ouE, "nTSecurityDescriptor", [][]byte{sdBytes(daSID,
		tace{mask: dsFullControl, flags: 0x02 | aceFlagInheritOnly, trustee: dusSID},  // GenericAll inherited to children
		tace{mask: dsWriteProp, objType: &spn, flags: 0x02, trustee: idSIDt},          // never-delegate WP
		tace{mask: dsWriteProp, objType: &w.attrMem, flags: 0x02, trustee: idSIDt},    // benign WP, no finding
		tace{mask: dsCreateChild, objType: &classUserG, flags: 0x02, trustee: idSIDt}, // R3 expectation met
		tace{mask: dsCreateChild, flags: 0x02, trustee: idSIDt},                       // create all child objects
	)})
	ou2, ou2G := w.f.obj("OU=Other,DC=lab,DC=test", "", nil, nil)
	w.putRaw(ou2, "nTSecurityDescriptor", [][]byte{sdBytes(daSID,
		tace{mask: dsCreateChild, objType: &classUserG, flags: 0x02, trustee: idSIDt})})
	// a tier0 root is skipped: it is judged, and blocks, in V7
	t0root := w.t0G
	r := w.run(t, ADInput{ManagedRoots: []adguid.GUID{ouG, ou2G, t0root},
		EnabledFamilies: []v1.RightsFamily{v1.RightsFamily_RIGHTS_FAMILY_AD_R3_USER_LIFECYCLE, v1.RightsFamily_RIGHTS_FAMILY_AD_R4_ACCOUNT_STATE}})
	if r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS {
		t.Fatalf("V9 must warn, not block: %v %v", r.Verdict, codes(r))
	}
	for _, c := range []string{CodeExcessOU + "generic_all", CodeExcessOU + "write_never_delegate", CodeExcessOU + "create_child"} {
		if count(r, c) != 1 {
			t.Errorf("%s: %v", c, codes(r))
		}
	}
	for _, f := range r.Findings {
		if f.Check != v9 || f.Severity != v1.FindingSeverity_FINDING_SEVERITY_WARN {
			t.Errorf("not a V9 warning: %s", f.Code)
		}
		if f.Code == CodeExcessOU+"generic_all" && f.Source.GetAce().Trustee == nil {
			t.Error("no ace trustee")
		}
	}
	// On the second OU: R3 lacks delete-child of user and R4's one resolvable attribute
	// (userAccountControl) is not granted. GenericAll on the first OU covers everything.
	miss := 0
	for _, f := range r.Findings {
		if f.Code == CodeMissingFamily {
			miss++
			if guidText(f.Object) != ou2G.String() || f.Family == 0 || f.Source.GetExpectedBy() != f.Family {
				t.Errorf("missing finding shape: %+v", f.RightsFinding)
			}
		}
	}
	if miss != 2 {
		t.Fatalf("missing x%d: %v", miss, codes(r))
	}
	if r.Checks[2].Outcome != v1.CheckOutcome_CHECK_OUTCOME_WARN {
		t.Fatalf("V9 outcome %v", r.Checks[2].Outcome)
	}
}

func TestParseSDNeverPanicsOnTruncation(t *testing.T) {
	g := rightResetPassword
	sd := sdBytes(daSID, tace{mask: dsControlAccess, objType: &g, inh: &g, trustee: idSIDt}, tace{deny: true, mask: 1, trustee: dusSID})
	if _, err := parseSD(sd); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(sd); i++ {
		if _, err := parseSD(sd[:i]); err == nil {
			t.Fatalf("truncated at %d parsed", i)
		}
	}
	bad := append([]byte(nil), sd...)
	bad[0] = 9
	if _, err := parseSD(bad); err == nil {
		t.Fatal("bad revision parsed")
	}
}

func TestGUIDRoundTrip(t *testing.T) {
	var g adguid.GUID
	for i := range g {
		g[i] = byte(i*17 + 3)
	}
	back, err := ParseGUID(pbGuid(g))
	if err != nil || back != g {
		t.Fatalf("%v %v", back, err)
	}
	if _, err := ParseGUID(&v1.Guid{Value: []byte{1}}); err == nil {
		t.Fatal("short guid parsed")
	}
}

// T-0237: dangerous rights held by broad principals on a tier0 object.
func TestBroadPrincipalExposure(t *testing.T) {
	w := newWorld(t)
	resetPw, getAll, changePw := rightResetPassword, rightGetChangesAll, mustAD("ab721a53-1e2f-11d0-9819-00aa0040529b")
	conf := w.attrConf
	cases := []struct {
		name string
		ace  tace
		want int
	}{
		{"auth users reset password", tace{mask: dsControlAccess, objType: &resetPw, trustee: "S-1-5-11"}, 1},
		{"auth users CA on confidential attr", tace{mask: dsControlAccess, objType: &conf, trustee: "S-1-5-11"}, 1},
		{"domain users reset password", tace{mask: dsControlAccess, objType: &resetPw, trustee: dusSID}, 1},
		{"everyone get-changes-all", tace{mask: dsControlAccess, objType: &getAll, trustee: "S-1-1-0"}, 1},
		{"auth users all extended rights", tace{mask: dsControlAccess, trustee: "S-1-5-11"}, 1},
		{"auth users confidential read", tace{mask: dsReadProp, objType: &conf, trustee: "S-1-5-11"}, 1},
		{"everyone write dac", tace{mask: maskWriteDAC, trustee: "S-1-1-0"}, 1},
		{"default: everyone change password", tace{mask: dsControlAccess, objType: &changePw, trustee: "S-1-1-0"}, 0},
		{"default: auth users plain read", tace{mask: dsReadProp, objType: &w.attrMem, trustee: "S-1-5-11"}, 0},
		{"default: auth users read all", tace{mask: 0x20094, trustee: "S-1-5-11"}, 0},
		{"self is not broad", tace{mask: dsSelf, trustee: "S-1-5-10"}, 0},
		{"inherit only skipped", tace{mask: maskWriteDAC, flags: aceFlagInheritOnly, trustee: "S-1-5-11"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w.putRaw(w.t0, "nTSecurityDescriptor", [][]byte{sdBytes(daSID, tc.ace)})
			r := w.run(t, ADInput{})
			if got := count(r, CodeTier0BroadPrincipal); got != tc.want {
				t.Fatalf("broad x%d, want %d: %v", got, tc.want, codes(r))
			}
			if tc.want == 0 {
				return
			}
			for _, f := range r.Findings {
				if f.Code != CodeTier0BroadPrincipal {
					continue
				}
				if f.Severity != v1.FindingSeverity_FINDING_SEVERITY_WARN || f.Object == nil || f.Right == nil || f.Source.GetAce().GetTrustee() == nil {
					t.Fatalf("shape %+v", f.RightsFinding)
				}
			}
			if count(r, CodeTier0Control) != 0 {
				t.Fatalf("one ACE, one finding: %v", codes(r))
			}
			if r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS {
				t.Fatalf("a broad-principal exposure warns, it does not refuse: %v", r.Verdict)
			}
		})
	}
}

// An absent sDRightsEffective is unknown, never zero.
func TestAbsentSDRightsEffectiveCouldNotVerify(t *testing.T) {
	w := newWorld(t)
	w.putRaw(w.t0, "sDRightsEffective", nil)
	r := w.run(t, ADInput{})
	if r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_COULD_NOT_VERIFY || count(r, CodeUnverifiedAD) != 1 {
		t.Fatalf("%v %v", r.Verdict, codes(r))
	}
}

// The owner in the token gives WRITE_DAC from the parsed descriptor even when sDRightsEffective
// reads 0; an OWNER RIGHTS ACE replaces the implicit grant.
func TestOwnerImplicitWriteDAC(t *testing.T) {
	w := newWorld(t)
	w.putRaw(w.t0, "nTSecurityDescriptor", [][]byte{sdBytes(idSIDt, tace{mask: dsFullControl, trustee: daSID})})
	if r := w.run(t, ADInput{}); count(r, CodeTier0WriteDACL) != 1 || r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED {
		t.Fatalf("owner: %v %v", r.Verdict, codes(r))
	}
	w.putRaw(w.t0, "nTSecurityDescriptor", [][]byte{sdBytes(idSIDt, tace{mask: dsFullControl, trustee: daSID}, tace{mask: dsReadProp, trustee: "S-1-3-4"})})
	if r := w.run(t, ADInput{}); count(r, CodeTier0WriteDACL) != 0 {
		t.Fatalf("owner rights ace: %v", codes(r))
	}
	w.putRaw(w.t0, "nTSecurityDescriptor", [][]byte{sdBytes(idSIDt, tace{mask: maskWriteDAC, trustee: "S-1-3-4"})})
	if r := w.run(t, ADInput{}); count(r, CodeTier0WriteDACL) != 1 || r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED {
		t.Fatalf("owner rights write dac: %v %v", r.Verdict, codes(r))
	}
	w.putRaw(w.t0, "nTSecurityDescriptor", [][]byte{sdBytes(idSIDt, tace{mask: dsFullControl, trustee: "S-1-3-4"})})
	if r := w.run(t, ADInput{}); count(r, CodeTier0GenericAll) != 1 || r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_REFUSED {
		t.Fatalf("owner rights full control: %v %v", r.Verdict, codes(r))
	}
	w.putRaw(w.t0, "nTSecurityDescriptor", [][]byte{sdBytes(daSID, tace{mask: dsFullControl, trustee: daSID})})
	if r := w.run(t, ADInput{}); count(r, CodeTier0WriteDACL) != 0 {
		t.Fatalf("other owner: %v", codes(r))
	}
}

// A token group of another domain with a privileged RID that the DC cannot resolve is not skipped.
func TestForeignPrivilegedTokenSID(t *testing.T) {
	w := newWorld(t)
	for sidText, want := range map[string]int{"S-1-5-21-9-8-7-519": 1, "S-1-5-21-9-8-7-1105": 0} {
		w.tokens = []string{dusSID, "S-1-1-0", "S-1-5-11", sidText}
		r := w.run(t, ADInput{})
		if got := count(r, CodeUnverifiedAD); got != want {
			t.Fatalf("%s: unverified x%d, want %d: %v", sidText, got, want, codes(r))
		}
	}
}
