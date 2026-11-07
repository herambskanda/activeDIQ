package write

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// refDir answers Get for GUID and DN references, Naming, and the schema search of the optional
// attribute proof. memberOf and lastKnownParent are DNs.
type refDir struct {
	tier0.ADDirectory
	byGUID map[guid.GUID]*ad.Entry
	byDN   map[string]guid.GUID
	errDN  map[string]error
	schema map[string]*ad.Entry
}

func (d *refDir) Get(_ context.Context, ref dn.ObjectRef, _ []string) (*ad.Entry, error) {
	if id, ok := ref.GUID(); ok {
		if e := d.byGUID[id]; e != nil {
			return e, nil
		}
		return nil, &ad.Error{Code: ad.CodeObjectNotFound}
	}
	x, _ := ref.DN()
	if err := d.errDN[x.String()]; err != nil {
		return nil, err
	}
	if id, ok := d.byDN[x.String()]; ok {
		return ad.NewEntry(x.String(), map[string][][]byte{"objectGUID": {id.Bytes()}}), nil
	}
	return nil, &ad.Error{Code: ad.CodeObjectNotFound}
}

func (d *refDir) Naming(context.Context) (tier0.Naming, error) {
	sch, _ := dn.Parse("CN=Schema,CN=Configuration,DC=lab", dn.Strict)
	return tier0.Naming{Schema: sch}, nil
}

func (d *refDir) Find(_ context.Context, _ dn.DN, _ ad.Scope, q tier0.Query, _ []string, fn func(*ad.Entry) error) error {
	if e := d.schema[q.Eq[0].Value]; e != nil {
		return fn(e)
	}
	return nil
}

var (
	delID    = mk(79)
	selfSID  = "S-1-5-21-1-2-3-1100"
	grpDN    = "CN=Staff,OU=G,DC=lab"
	parentDN = "OU=Old,DC=lab"
)

// aceSD builds a self-relative descriptor with one allow or deny ACE per (type, mask, sid).
type testACE struct {
	deny bool
	mask uint32
	sid  string
}

func buildSD(t *testing.T, aces ...testACE) []byte {
	t.Helper()
	var acl []byte
	for _, a := range aces {
		sb := sidBytes(t, a.sid)
		ace := make([]byte, 8, 8+len(sb))
		if a.deny {
			ace[0] = 1
		}
		binary.LittleEndian.PutUint16(ace[2:], uint16(8+len(sb)))
		binary.LittleEndian.PutUint32(ace[4:], a.mask)
		acl = append(acl, append(ace, sb...)...)
	}
	hdr := make([]byte, 8)
	hdr[0], hdr[1] = 2, 0
	binary.LittleEndian.PutUint16(hdr[2:], uint16(8+len(acl)))
	binary.LittleEndian.PutUint16(hdr[4:], uint16(len(aces)))
	out := make([]byte, 20)
	out[0] = 1
	binary.LittleEndian.PutUint16(out[2:], 0x8004) // SELF_RELATIVE | DACL_PRESENT
	binary.LittleEndian.PutUint32(out[16:], 20)    // DACL offset
	return append(out, append(hdr, acl...)...)
}

const authenticatedUsers = "S-1-5-11"

type delRig struct {
	p      *ADProvider
	d      *refDir
	objs   *fakeObjects
	grp    guid.GUID
	parent guid.GUID
	set    *tier0.ADSet
}

func newDelRig(t *testing.T) *delRig {
	t.Helper()
	d := &refDir{byGUID: map[guid.GUID]*ad.Entry{}, byDN: map[string]guid.GUID{}, errDN: map[string]error{}, schema: map[string]*ad.Entry{}}
	r := &delRig{d: d, grp: mk(80), parent: mk(81), set: tier0.NewADSet()}
	d.byDN[grpDN], d.byDN[parentDN] = r.grp, r.parent
	d.byGUID[r.grp] = ad.NewEntry(grpDN, map[string][][]byte{"objectClass": {[]byte("group")}, "cn": {[]byte("Staff")}})
	d.byGUID[r.parent] = ad.NewEntry(parentDN, map[string][][]byte{"objectClass": {[]byte("organizationalUnit")}, "cn": {[]byte("Old")}})
	self := mk(90)
	d.byGUID[self] = ad.NewEntry("CN=svc,DC=lab", map[string][][]byte{
		"objectSid": {sidBytes(t, selfSID)}, "tokenGroups": {sidBytes(t, authenticatedUsers)}})
	for _, n := range ad.DeletedTargetOptional {
		d.schema[n] = ad.NewEntry("", map[string][][]byte{"schemaIDGUID": {mk(100).Bytes()}, "searchFlags": {[]byte("0")}})
	}
	newParent, np := mk(82), mk(82)
	_ = np
	r.objs = &fakeObjects{parent: map[guidT]guidT{}, rdn: map[guidT]string{newParent: "New"}, deleted: map[guidT]bool{}, bin: true,
		members: map[guidT][]string{}, container: buildSD(t, testACE{mask: sd.MaskListContents, sid: authenticatedUsers})}
	r.p = &ADProvider{Dir: d, Pins: &memPins{}, Self: dn.GUIDRef(self)}
	r.p.snapshot = func(context.Context, []guid.GUID) (*tier0.ADSet, error) { return r.set, nil }
	r.setTier0()
	return r
}

func (r *delRig) setTier0(ids ...guid.GUID) {
	r.p.classify = func(_ context.Context, id guid.GUID, _ tier0.ADInput) (tier0.ADResult, error) {
		res := tier0.ADResult{GUID: id}
		for _, x := range ids {
			if x == id {
				res.Tier0 = true
			}
		}
		return res, nil
	}
}

func (r *delRig) principal(t *testing.T) sd.Principal {
	t.Helper()
	pr, err := r.p.principal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return pr
}

// entry is a clean deleted user; mod edits the attribute map.
func (r *delRig) entry(t *testing.T, mod func(map[string][][]byte)) *ad.Entry {
	t.Helper()
	a := map[string][][]byte{
		"objectGUID":           {delID.Bytes()},
		"objectClass":          {[]byte("top"), []byte("person"), []byte("user")},
		"isDeleted":            {[]byte("TRUE")},
		"msDS-LastKnownRDN":    {[]byte("Jo")},
		"nTSecurityDescriptor": {buildSD(t, testACE{mask: sd.MaskReadProp, sid: authenticatedUsers})},
		"userAccountControl":   {[]byte("512")},
		"objectSid":            {sidBytes(t, "S-1-5-21-1-2-3-1500")},
		"primaryGroupID":       {[]byte("513")},
		"memberOf":             {[]byte(grpDN)},
		"lastKnownParent":      {[]byte(parentDN)},
	}
	if mod != nil {
		mod(a)
	}
	return ad.NewEntry("CN=Jo\\0ADEL:x,CN=Deleted Objects,DC=lab", a)
}

func (r *delRig) classify(t *testing.T, e *ad.Entry, des []guid.GUID) (Verdict, error) {
	t.Helper()
	return r.p.classifyDeletedEntry(context.Background(), r.objs, delID, e, des, r.principal(t))
}

// A clean user passes; every basis refuses; anything unreadable fails closed (rule 8).
func TestClassifyDeletedEntry(t *testing.T) {
	r := newDelRig(t)
	if v, err := r.classify(t, r.entry(t, nil), nil); err != nil || v.Tier0 {
		t.Fatalf("clean user: %+v %v", v, err)
	}
	gone := func(a map[string][][]byte) { a["lastKnownParent"] = [][]byte{[]byte("OU=Gone,DC=lab")} }
	if v, err := r.classify(t, r.entry(t, gone), nil); err != nil || v.Tier0 {
		t.Fatalf("gone parent: %+v %v", v, err)
	}
	cases := []struct {
		name  string
		mod   func(map[string][][]byte)
		setup func(*delRig) []guid.GUID
		want  Basis
	}{
		{"C1 rid<1000", func(a map[string][][]byte) { a["objectSid"] = [][]byte{sidBytes(t, "S-1-5-21-1-2-3-500")} }, nil, tier0.C1},
		{"C18 sIDHistory", func(a map[string][][]byte) { a["sIDHistory"] = [][]byte{sidBytes(t, "S-1-5-21-9-9-9-1100")} }, nil, tier0.C18},
		{"primary group", func(a map[string][][]byte) { a["primaryGroupID"] = [][]byte{[]byte("512")} }, nil, tier0.C2},
		{"adminCount", func(a map[string][][]byte) { a["adminCount"] = [][]byte{[]byte("1")} }, nil, tier0.C3},
		{"DC uac", func(a map[string][][]byte) { a["userAccountControl"] = [][]byte{[]byte("532480")} }, nil, tier0.C5},
		{"RODC uac", func(a map[string][][]byte) { a["userAccountControl"] = [][]byte{[]byte("67109376")} }, nil, tier0.C5},
		{"delegation uac", func(a map[string][][]byte) { a["userAccountControl"] = [][]byte{[]byte("524800")} }, nil, tier0.C12},
		{"pgid 516", func(a map[string][][]byte) { a["primaryGroupID"] = [][]byte{[]byte("516")} }, nil, tier0.C5},
		{"designated target", nil, func(r *delRig) []guid.GUID { return []guid.GUID{delID} }, designatedBasis},
		{"tier0 group", nil, func(r *delRig) []guid.GUID { r.setTier0(r.grp); return nil }, tier0.C2},
		{"designated group", nil, func(r *delRig) []guid.GUID { return []guid.GUID{r.grp} }, tier0.C2},
		{"group unreadable", nil, func(r *delRig) []guid.GUID { r.d.errDN[grpDN] = errors.New("boom"); return nil }, tier0.C2},
		{"bad memberOf", func(a map[string][][]byte) { a["memberOf"] = [][]byte{[]byte("not a dn")} }, nil, tier0.C2},
		{"tier0 last parent", nil, func(r *delRig) []guid.GUID { r.setTier0(r.parent); return nil }, tier0.C3},
	}
	for _, c := range cases {
		rg := newDelRig(t)
		var des []guid.GUID
		if c.setup != nil {
			des = c.setup(rg)
		}
		v, err := rg.classify(t, rg.entry(t, c.mod), des)
		if err != nil || !v.Tier0 || len(v.Bases) != 1 || v.Bases[0] != c.want {
			t.Errorf("%s: %+v %v", c.name, v, err)
		}
	}
	fail := map[string]func(map[string][][]byte){
		"bad adminCount":      func(a map[string][][]byte) { a["adminCount"] = [][]byte{[]byte("x")} },
		"bad objectSid":       func(a map[string][][]byte) { a["objectSid"] = [][]byte{{1, 2}} },
		"bad lastKnownParent": func(a map[string][][]byte) { a["lastKnownParent"] = [][]byte{[]byte("not a dn")} },
	}
	for name, mod := range fail {
		rg := newDelRig(t)
		if v, err := rg.classify(t, rg.entry(t, mod), nil); err == nil || !v.Tier0 {
			t.Errorf("%s: %+v %v", name, v, err)
		}
	}
	rg := newDelRig(t)
	rg.d.errDN[parentDN] = errors.New("boom")
	if v, err := rg.classify(t, rg.entry(t, nil), nil); err == nil || !v.Tier0 {
		t.Errorf("parent read error: %+v %v", v, err)
	}
}

// Step 3: an absent must-be-present attribute is unreadable, tier0 with an unknown basis.
func TestClassifyDeletedMustBePresent(t *testing.T) {
	names := append([]string{"objectSid", "userAccountControl", "primaryGroupID"}, ad.DeletedTargetMustBePresent...)
	for _, n := range names {
		r := newDelRig(t)
		v, err := r.classify(t, r.entry(t, func(a map[string][][]byte) { delete(a, n) }), nil)
		if err != nil || !v.Tier0 || len(v.Bases) != 0 {
			t.Errorf("absent %s: %+v %v", n, v, err)
		}
	}
	// A group without objectSid is unreadable; an OU needs none.
	r := newDelRig(t)
	grp := func(a map[string][][]byte) { a["objectClass"] = [][]byte{[]byte("group")}; delete(a, "objectSid") }
	if v, _ := r.classify(t, r.entry(t, grp), nil); !v.Tier0 {
		t.Error("group without objectSid passed")
	}
	ou := func(a map[string][][]byte) {
		a["objectClass"] = [][]byte{[]byte("top"), []byte("organizationalUnit")}
		delete(a, "objectSid")
		delete(a, "userAccountControl")
		delete(a, "primaryGroupID")
	}
	if v, err := r.classify(t, r.entry(t, ou), nil); err != nil || v.Tier0 {
		t.Errorf("ou: %+v %v", v, err)
	}
}

// Step 3: an absent optional attribute is "not set" only when the retained descriptor proves Read
// Property for the connection identity; a deny, a missing grant, a property-set ACE, a confidential
// attribute without Control Access, an unreadable descriptor or an unknown schema all refuse.
func TestClassifyDeletedOptionalProof(t *testing.T) {
	read := testACE{mask: sd.MaskReadProp, sid: authenticatedUsers}
	cases := map[string]struct {
		sd    []byte
		setup func(*delRig)
		clean bool
	}{
		"granted":        {sd: buildSD(t, read), clean: true},
		"no grant":       {sd: buildSD(t, testACE{mask: sd.MaskListContents, sid: authenticatedUsers})},
		"deny first":     {sd: buildSD(t, testACE{deny: true, mask: sd.MaskReadProp, sid: authenticatedUsers}, read)},
		"not in token":   {sd: buildSD(t, testACE{mask: sd.MaskReadProp, sid: "S-1-5-32-544"})},
		"garbage sd":     {sd: []byte{1, 2, 3}},
		"unknown schema": {sd: buildSD(t, read), setup: func(r *delRig) { delete(r.d.schema, "adminCount") }},
		"confidential":   {sd: buildSD(t, read), setup: func(r *delRig) { r.d.schema["isCriticalSystemObject"].Raw("searchFlags")[0] = []byte("128") }},
	}
	for name, c := range cases {
		r := newDelRig(t)
		if c.setup != nil {
			c.setup(r)
		}
		v, err := r.classify(t, r.entry(t, func(a map[string][][]byte) { a["nTSecurityDescriptor"] = [][]byte{c.sd} }), nil)
		if err != nil || v.Tier0 == c.clean {
			t.Errorf("%s: %+v %v", name, v, err)
		}
	}
	// Control Access as well makes a confidential attribute provable.
	r := newDelRig(t)
	r.d.schema["isCriticalSystemObject"].Raw("searchFlags")[0] = []byte("128")
	both := buildSD(t, read, testACE{mask: sd.MaskControlAccess, sid: authenticatedUsers})
	if v, err := r.classify(t, r.entry(t, func(a map[string][][]byte) { a["nTSecurityDescriptor"] = [][]byte{both} }), nil); err != nil || v.Tier0 {
		t.Errorf("confidential with control access: %+v %v", v, err)
	}
}

var newParentID = mk(82)

func (r *delRig) restore(t *testing.T, mod func(map[string][][]byte)) (Verdict, error) {
	t.Helper()
	r.objs.target = r.entry(t, mod)
	r.objs.calls = nil
	return r.p.classifyDeleted(context.Background(), r.objs, delID, newParentID, nil)
}

// Step 1 comes before step 2, and a grant that is not proven never reads the target and is never
// OBJECT_NOT_FOUND (TM-D33 rule 4).
func TestClassifyDeletedGrantFirst(t *testing.T) {
	lc := buildSD(t, testACE{mask: sd.MaskListContents, sid: authenticatedUsers})
	cases := map[string]func(*delRig){
		"no List Contents": func(r *delRig) {
			r.objs.container = buildSD(t, testACE{mask: sd.MaskReadProp, sid: authenticatedUsers})
		},
		"deny List Contents": func(r *delRig) {
			r.objs.container = buildSD(t, testACE{deny: true, mask: sd.MaskListContents, sid: authenticatedUsers}, testACE{mask: sd.MaskListContents, sid: authenticatedUsers})
		},
		"descriptor unreadable": func(r *delRig) { r.objs.containerErr = ad.NewError(ad.CodeObjectNotFound) },
		"insufficient rights":   func(r *delRig) { r.objs.containerErr = ad.NewError(ad.CodeInsufficientRights) },
		"garbage descriptor":    func(r *delRig) { r.objs.container = []byte{9, 9} },
		"no identity":           func(r *delRig) { r.p.Self = dn.ObjectRef{} },
		"identity unreadable":   func(r *delRig) { r.d.byGUID = map[guid.GUID]*ad.Entry{} },
	}
	for name, mod := range cases {
		r := newDelRig(t)
		r.objs.dnOf = map[guidT]dn.DN{newParentID: mustDN(t, "OU=New,DC=lab")}
		r.objs.container = lc
		mod(r)
		_, err := r.restore(t, nil)
		var re *DeletedRightsError
		if !errors.As(err, &re) || re.Domain != "DC=lab" {
			t.Errorf("%s: %v", name, err)
		}
		for _, c := range r.objs.calls {
			if c == "target" {
				t.Errorf("%s: read the target without the grant", name)
			}
		}
	}
	// A lost DC is not a rights answer.
	r := newDelRig(t)
	r.objs.dnOf = map[guidT]dn.DN{newParentID: mustDN(t, "OU=New,DC=lab")}
	r.objs.containerErr = ad.NewError(ad.CodeUnreachable)
	if _, err := r.restore(t, nil); err == nil || errors.As(err, new(*DeletedRightsError)) {
		t.Errorf("unreachable: %v", err)
	}
}

func mustDN(t *testing.T, s string) dn.DN {
	t.Helper()
	d, err := dn.Parse(s, dn.Strict)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// With the grant proven the target is read once, a clean user passes, and the failures map.
func TestClassifyDeletedTargetRead(t *testing.T) {
	setup := func() *delRig {
		r := newDelRig(t)
		r.objs.dnOf = map[guidT]dn.DN{newParentID: mustDN(t, "OU=New,DC=lab")}
		return r
	}
	r := setup()
	if v, err := r.restore(t, nil); err != nil || v.Tier0 {
		t.Fatalf("clean: %+v %v", v, err)
	}
	if len(r.objs.calls) < 2 || r.objs.calls[0] != "container" || r.objs.calls[1] != "target" {
		t.Fatalf("order: %v", r.objs.calls)
	}
	r = setup()
	r.objs.targetErr = ad.NewError(ad.CodeObjectNotFound)
	if _, err := r.restore(t, nil); !errors.Is(err, ErrDeletedNotFound) {
		t.Errorf("noSuchObject after grant: %v", err)
	}
	r = setup()
	if _, err := r.restore(t, func(a map[string][][]byte) { a["isRecycled"] = [][]byte{[]byte("TRUE")} }); !errors.Is(err, ErrDeletedNotFound) {
		t.Errorf("recycled: %v", err)
	}
	r = setup()
	if v, err := r.restore(t, func(a map[string][][]byte) { a["objectGUID"] = [][]byte{mk(5).Bytes()} }); err == nil || !v.Tier0 {
		t.Errorf("another object: %+v %v", v, err)
	}
	r = setup()
	r.d.byGUID[delID] = ad.NewEntry("CN=Jo,DC=lab", map[string][][]byte{"objectClass": {[]byte("user")}, "cn": {[]byte("Jo")}})
	if v, err := r.restore(t, func(a map[string][][]byte) { delete(a, "isDeleted") }); err != nil || v.Tier0 {
		t.Errorf("live meanwhile: %+v %v", v, err) // the live classification (stubbed clean)
	}
	r = setup()
	r.objs.target = r.entry(t, nil)
	r.objs.target = ad.NewEntry("CN=Jo,CN=Deleted Objects,DC=other", map[string][][]byte{"objectGUID": {delID.Bytes()}, "isDeleted": {[]byte("TRUE")}})
	if v, err := r.p.classifyDeleted(context.Background(), r.objs, delID, newParentID, nil); err == nil || !v.Tier0 {
		t.Errorf("other domain: %+v %v", v, err)
	}
}

// Step 4: a target that memberOf does not show, but that a tier0 group's member attribute holds
// (read with the deactivated-link control), is tier0 with basis C2; a failed read is tier0.
func TestClassifyDeletedMemberCrossCheck(t *testing.T) {
	setup := func() *delRig {
		r := newDelRig(t)
		r.objs.dnOf = map[guidT]dn.DN{newParentID: mustDN(t, "OU=New,DC=lab")}
		r.set.Add(r.grp, tier0.C13)
		return r
	}
	ext := "<GUID=" + guidHex(delID) + ">;CN=Jo\\0ADEL:x,CN=Deleted Objects,DC=lab"
	noMemberOf := func(a map[string][][]byte) { delete(a, "memberOf") }

	r := setup()
	r.objs.members[r.grp] = []string{"<GUID=" + guidHex(mk(7)) + ">;CN=other,DC=lab", ext}
	if v, err := r.restore(t, noMemberOf); err != nil || !v.Tier0 || len(v.Bases) != 1 || v.Bases[0] != tier0.C2 {
		t.Errorf("member holds target: %+v %v", v, err)
	}
	r = setup()
	r.objs.members[r.grp] = []string{"<GUID=" + guidHex(mk(7)) + ">;CN=other,DC=lab"}
	if v, err := r.restore(t, noMemberOf); err != nil || v.Tier0 {
		t.Errorf("not a member: %+v %v", v, err)
	}
	r = setup()
	r.objs.memberErr = errors.New("boom")
	if v, err := r.restore(t, noMemberOf); err == nil || !v.Tier0 {
		t.Errorf("failed read: %+v %v", v, err)
	}
	r = setup()
	r.objs.members[r.grp] = []string{"garbage <"}
	if v, err := r.restore(t, noMemberOf); err == nil || !v.Tier0 {
		t.Errorf("garbage member value: %+v %v", v, err)
	}
	// Only groups held by C1, C13 or designation are read.
	r = setup()
	r.set = tier0.NewADSet()
	r.set.Add(r.grp, tier0.C3)
	if _, err := r.restore(t, noMemberOf); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.objs.calls {
		if c == "members" {
			t.Error("read a group that is not C1/C13/designated")
		}
	}
}

func guidHex(g guid.GUID) string { return hexOf(g.Bytes()) }

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, x := range b {
		out = append(out, d[x>>4], d[x&15])
	}
	return string(out)
}

// Without the Recycle Bin kind 6 is unsupported before any grant or target read (the flag, never try-and-see).
func TestClassifyDeletedNoRecycleBin(t *testing.T) {
	r := newDelRig(t)
	r.objs.bin = false
	if _, err := r.restore(t, nil); !errors.Is(err, ErrNoRecycleBin) {
		t.Fatalf("got %v", err)
	}
	if len(r.objs.calls) != 0 {
		t.Fatalf("read before the capability check: %v", r.objs.calls)
	}
}
