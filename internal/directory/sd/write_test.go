package sd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

type mapCatalog map[guid.GUID]RightKind

func (m mapCatalog) Kind(g guid.GUID) (RightKind, bool) { k, ok := m[g]; return k, ok }

var kindNames = map[string]RightKind{"class": Class, "attribute": Attribute, "property_set": PropertySet,
	"control_access": ControlAccess, "validated_write": ValidatedWrite}

type jsonACE struct {
	Trustee   string `json:"trustee"`
	Mask      uint32 `json:"mask"`
	Deny      bool   `json:"deny"`
	Flags     uint8  `json:"flags"`
	Object    string `json:"object"`
	Inherited string `json:"inherited_object"`
}

type jsonRef struct {
	Index  int    `json:"index"`
	Digest string `json:"digest"`
}

type jsonOpts struct {
	Normalize   bool   `json:"normalize"`
	SDProp      bool   `json:"sdprop"`
	NoConnector bool   `json:"no_connector"`
	NoObject    bool   `json:"no_object"`
	WantControl *int   `json:"want_control"`
	ExpectBase  string `json:"expect_base"`
	Connector   struct {
		User   string   `json:"user"`
		Groups []string `json:"groups"`
	} `json:"connector"`
}

func jarg[T any](r corpus.Record, name string) (v T, err error) {
	in, err := r.Arg(name)
	if err != nil {
		return v, err
	}
	err = json.Unmarshal(in.Raw, &v)
	return v, err
}

func mustGUID(s string) *guid.GUID {
	g, err := guid.Parse(s)
	if err != nil {
		panic(err)
	}
	return &g
}

// The one place the corpus turns trustee text into a SID is ParseTrustee, as a JSON API would.
func (j jsonACE) toNew() (NewACE, error) {
	tr, err := ParseTrustee(j.Trustee)
	if err != nil {
		return NewACE{}, err
	}
	n := NewACE{Deny: j.Deny, Trustee: tr, Mask: j.Mask, Flags: j.Flags}
	if j.Object != "" {
		n.ObjectType = mustGUID(j.Object)
	}
	if j.Inherited != "" {
		n.InheritedObjectType = mustGUID(j.Inherited)
	}
	return n, nil
}

type writeFixture struct {
	base    SD
	diff    ACEDiff
	cat     mapCatalog
	octx    ObjectCtx
	opt     PlanOpts
	current Raw
}

func loadWriteFixture(r corpus.Record) (writeFixture, error) {
	var f writeFixture
	in, err := r.Arg("sd")
	if err != nil {
		return f, err
	}
	if f.base, err = Decode(Raw(in.Raw)); err != nil {
		return f, fmt.Errorf("record sd does not decode: %v", err)
	}
	opts, err := jarg[jsonOpts](r, "opts")
	if err != nil {
		return f, err
	}
	f.opt.Normalize = opts.Normalize
	f.octx.ProtectedBySDProp = opts.SDProp
	if !opts.NoObject {
		f.octx.ObjectGUID = *mustGUID("11111111-0000-0000-0000-000000000001")
	}
	if !opts.NoConnector {
		u, err := sid.Parse(opts.Connector.User)
		if err != nil {
			return f, err
		}
		var gs []sid.SID
		for _, g := range opts.Connector.Groups {
			v, err := sid.Parse(g)
			if err != nil {
				return f, err
			}
			gs = append(gs, v)
		}
		f.octx.Connector = PrincipalFromToken(u, gs)
	}
	if opts.WantControl != nil {
		c := Control(*opts.WantControl)
		f.diff.WantControl = &c
	}
	if opts.ExpectBase != "" {
		b, err := hex.DecodeString(opts.ExpectBase)
		if err != nil || len(b) != len(Digest{}) {
			return f, fmt.Errorf("bad expect_base")
		}
		var d Digest
		copy(d[:], b)
		f.opt.ExpectBase = &d
	}
	if _, ok := r.Args["catalog"]; ok {
		raw, err := jarg[map[string]string](r, "catalog")
		if err != nil {
			return f, err
		}
		f.cat = mapCatalog{}
		for g, k := range raw {
			f.cat[*mustGUID(g)] = kindNames[k]
		}
	}
	if _, ok := r.Args["add"]; ok {
		adds, err := jarg[[]jsonACE](r, "add")
		if err != nil {
			return f, err
		}
		for _, a := range adds {
			n, err := a.toNew()
			if err != nil {
				return f, err
			}
			f.diff.Add = append(f.diff.Add, n)
		}
		var refs []jsonRef
		if _, ok := r.Args["remove"]; ok {
			if refs, err = jarg[[]jsonRef](r, "remove"); err != nil {
				return f, err
			}
		}
		for _, x := range refs {
			b, err := hex.DecodeString(x.Digest)
			if err != nil || len(b) != len(Digest{}) {
				return f, fmt.Errorf("bad digest")
			}
			ref := ACERef{Index: x.Index}
			copy(ref.Digest[:], b)
			f.diff.Remove = append(f.diff.Remove, ref)
		}
	}
	if in, ok := r.Args["current"]; ok {
		c, err := corpusInput(in)
		if err != nil {
			return f, err
		}
		f.current = Raw(c)
	}
	return f, nil
}

func corpusInput(raw json.RawMessage) ([]byte, error) {
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return hex.DecodeString(m["hex"])
}

func writeOutcome(w DACLWrite, p Plan, err error) (corpus.Result, error) {
	if err != nil {
		if w.Valid() || w.Value() != nil {
			return corpus.Result{}, fmt.Errorf("an error came with a usable DACLWrite")
		}
		return corpustest.Err(codec.Code(err)), nil
	}
	v := w.Value()
	c := w.Control()
	if c.OID != SDFlagsOID || !c.Critical {
		return corpus.Result{}, fmt.Errorf("control %+v", c)
	}
	moves := make([]any, 0)
	for _, m := range p.Moves {
		moves = append(moves, []any{float64(m.From), float64(m.To)})
	}
	changes := make([]any, 0)
	for _, ch := range p.Changes {
		m := map[string]any{"trustee": ch.Trustee.String(), "mask": float64(ch.Mask), "before": ch.Before.String(), "after": ch.After.String()}
		if ch.Object != nil {
			m["object"] = ch.Object.String()
		}
		changes = append(changes, m)
	}
	nums := func(xs []int) []any {
		out := make([]any, 0)
		for _, x := range xs {
			out = append(out, float64(x))
		}
		return out
	}
	noncanon := make([]any, 0)
	for _, nc := range p.NonCanonicalResult {
		noncanon = append(noncanon, []any{float64(nc.Rule), float64(nc.Index)})
	}
	return corpustest.Value(map[string]any{
		"sd_hex": hex.EncodeToString(v), "control_hex": hex.EncodeToString(c.Value), "critical": c.Critical,
		"offsets": []any{float64(binary.LittleEndian.Uint32(v[4:])), float64(binary.LittleEndian.Uint32(v[8:])),
			float64(binary.LittleEndian.Uint32(v[12:])), float64(binary.LittleEndian.Uint32(v[16:]))},
		"control": float64(binary.LittleEndian.Uint16(v[2:])), "inserted": nums(p.Inserted), "removed": nums(p.Removed),
		"moves": moves, "changes": changes, "changes_incomplete": p.ChangesIncomplete, "noncanonical": noncanon,
	})
}

// corpusWrite runs the sd.write unit. The gate runs one test per implementation (TestCorpus), so
// that test calls this after sd.read.
func corpusWrite(t *testing.T) {
	corpustest.Run(t, "go/sd", "sd.write", func(r corpus.Record) (corpus.Result, error) {
		switch r.Call {
		case "ParseTrustee":
			in, err := r.Arg("text")
			if err != nil {
				return corpus.Result{}, err
			}
			s, err := ParseTrustee(in.Text())
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Value(s.String())
		case "PlanDACL":
			f, err := loadWriteFixture(r)
			if err != nil {
				return corpus.Result{}, err
			}
			var cat RightsCatalog
			if f.cat != nil {
				cat = f.cat
			}
			w, p, err := PlanDACL(f.base, f.diff, cat, f.octx, f.opt)
			return writeOutcome(w, p, err)
		case "VerifyBase":
			f, err := loadWriteFixture(r)
			if err != nil {
				return corpus.Result{}, err
			}
			w, _, err := PlanDACL(f.base, f.diff, f.cat, f.octx, f.opt)
			if err != nil {
				return corpus.Result{}, fmt.Errorf("setup plan failed: %v", err)
			}
			cur, err := Decode(f.current)
			if err != nil {
				return corpus.Result{}, err
			}
			if err := w.VerifyBase(cur); err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Value(map[string]any{"ok": true})
		case "PlanInheritance":
			f, err := loadWriteFixture(r)
			if err != nil {
				return corpus.Result{}, err
			}
			op, _ := r.Arg("op")
			ops := map[string]InheritanceOp{"block_keep": BlockKeepInherited, "block_remove": BlockRemoveInherited, "restore": RestoreInheritance, "bogus": 99}
			w, p, err := PlanInheritance(f.base, ops[op.Text()], f.octx, f.opt)
			return writeOutcome(w, p, err)
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

// DACLWrite is constructible only by Plan*: every field is unexported, so no other package can set
// one, and the zero value is invalid and has no value.
func TestDACLWriteOnlyConstructibleByPlanners(t *testing.T) {
	ty := reflect.TypeOf(DACLWrite{})
	if ty.NumField() == 0 {
		t.Fatal("no fields")
	}
	for i := 0; i < ty.NumField(); i++ {
		if ty.Field(i).IsExported() {
			t.Fatalf("field %s is exported", ty.Field(i).Name)
		}
	}
	var z DACLWrite
	if z.Valid() || z.Value() != nil {
		t.Fatal("zero DACLWrite must be invalid and valueless")
	}
	if err := z.VerifyBase(SD{}); codec.Code(err) != ErrNotEditable {
		t.Fatalf("zero VerifyBase: %v", err)
	}
	if reflect.TypeOf(ACEDiff{}).Kind() != reflect.Struct {
		t.Fatal("unreachable")
	}
}

// Value() is a copy: a caller cannot edit the planned bytes.
func TestValueIsACopy(t *testing.T) {
	w := mustPlanSimple(t)
	a := w.Value()
	a[0] = 99
	if w.Value()[0] != 1 {
		t.Fatal("Value() aliases internal bytes")
	}
}

func mustPlanSimple(t *testing.T) DACLWrite {
	t.Helper()
	sys := mustSID("S-1-5-18")
	user := mustSID("S-1-5-21-1-2-3-1105")
	raw := buildBase(t, []NewACE{{Trustee: sys, Mask: 0xF01FF}}, user)
	s, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	w, _, err := PlanDACL(s, ACEDiff{Add: []NewACE{{Trustee: mustSID("S-1-1-0"), Mask: MaskReadProp}}}, nil,
		ObjectCtx{ObjectGUID: *mustGUID("11111111-0000-0000-0000-000000000001"), Connector: PrincipalFromToken(user, []sid.SID{mustSID("S-1-1-0")})}, PlanOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// buildBase makes a base SD by planning a first ACE list through encodeNew, owner set to owner.
func buildBase(t *testing.T, aces []NewACE, owner sid.SID) Raw {
	t.Helper()
	var list []ACE
	for _, n := range aces {
		a, err := encodeNew(n, nil)
		if err != nil {
			t.Fatal(err)
		}
		list = append(list, a)
	}
	size := aclHeaderLen
	for _, a := range list {
		size += len(a.Raw)
	}
	body := encodeDACLSD(0, 2, list, size)
	ob := owner.Bytes()
	binary.LittleEndian.PutUint32(body[4:], uint32(len(body)))
	return Raw(append(body, ob...))
}

// Property: for editable bases, Decode(Plan(...).Value()) round-trips to base minus removals plus
// additions, existing ACEs keep their relative order and bytes, and the result stays canonical.
func TestPlanRoundTripProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(135))
	trustees := []sid.SID{mustSID("S-1-5-11"), mustSID("S-1-1-0"), mustSID("S-1-5-32-544"), mustSID("S-1-5-21-1-2-3-1105"), mustSID("S-1-5-21-1-2-3-1200")}
	conn := mustSID("S-1-5-21-1-2-3-1105")
	masks := []uint32{MaskReadProp, MaskWriteProp, MaskReadControl, MaskReadProp | MaskWriteProp, MaskDelete}
	for iter := 0; iter < 300; iter++ {
		// A canonical base: denies, then allows, then (sometimes) inherited ones.
		var specs []NewACE
		for i, n := 0, 1+rng.Intn(8); i < n; i++ {
			specs = append(specs, NewACE{Deny: rng.Intn(3) == 0, Trustee: trustees[rng.Intn(len(trustees))], Mask: masks[rng.Intn(len(masks))]})
		}
		specs = append(specs, NewACE{Trustee: conn, Mask: MaskWriteDACL})
		var list []ACE
		for _, n := range specs {
			a, _ := encodeNew(n, nil)
			list = append(list, a)
		}
		sortCanonical(list)
		size := aclHeaderLen
		for _, a := range list {
			size += len(a.Raw)
		}
		body := encodeDACLSD(0, 2, list, size)
		binary.LittleEndian.PutUint32(body[4:], uint32(len(body)))
		base, err := Decode(Raw(append(body, mustSID("S-1-5-18").Bytes()...)))
		if err != nil || !base.Editable() {
			t.Fatalf("base: %v %v", err, base.Anomalies)
		}
		var diff ACEDiff
		removed := map[int]bool{}
		for i, a := range base.DACL.ACEs {
			if rng.Intn(4) == 0 && a.Trustee != conn {
				diff.Remove = append(diff.Remove, ACERef{i, DigestACE(a)})
				removed[i] = true
			}
		}
		for i, n := 0, rng.Intn(4); i < n; i++ {
			diff.Add = append(diff.Add, NewACE{Deny: rng.Intn(3) == 0, Trustee: trustees[rng.Intn(len(trustees))], Mask: masks[rng.Intn(len(masks))]})
		}
		if len(diff.Add)+len(diff.Remove) == 0 {
			continue
		}
		w, plan, err := PlanDACL(base, diff, nil, ObjectCtx{ObjectGUID: *mustGUID("11111111-0000-0000-0000-000000000001"), Connector: PrincipalFromToken(conn, []sid.SID{mustSID("S-1-1-0")})}, PlanOpts{})
		if err != nil {
			t.Fatalf("iter %d: %v", iter, err)
		}
		got, err := Decode(w.Value())
		if err != nil {
			t.Fatalf("iter %d: result does not decode: %v", iter, err)
		}
		if got.HasOwner || got.HasGroup || got.SACL.Kind != Absent || got.DACL.Kind != List {
			t.Fatalf("iter %d: result carries more than a DACL", iter)
		}
		if len(got.Anomalies) != 0 {
			t.Fatalf("iter %d: result not canonical: %v", iter, got.Anomalies)
		}
		isNew := map[int]bool{}
		for _, i := range plan.Inserted {
			isNew[i] = true
		}
		var survivors, kept [][]byte
		for i, a := range base.DACL.ACEs {
			if !removed[i] {
				kept = append(kept, a.Raw)
			}
		}
		for i, a := range got.DACL.ACEs {
			if !isNew[i] {
				survivors = append(survivors, a.Raw)
			}
		}
		if len(kept) != len(survivors) {
			t.Fatalf("iter %d: %d kept, %d survive", iter, len(kept), len(survivors))
		}
		for i := range kept {
			if !bytes.Equal(kept[i], survivors[i]) {
				t.Fatalf("iter %d: an existing ACE moved or changed", iter)
			}
		}
		if len(got.DACL.ACEs) != len(kept)+len(diff.Add) {
			t.Fatalf("iter %d: count", iter)
		}
	}
}

func sortCanonical(l []ACE) {
	// denies first, stable
	out := make([]ACE, 0, len(l))
	for _, a := range l {
		if a.deny() {
			out = append(out, a)
		}
	}
	for _, a := range l {
		if !a.deny() {
			out = append(out, a)
		}
	}
	copy(l, out)
}

func TestACLBoundIsTheSpecs(t *testing.T) {
	if MaxACEsPerACL != 4095 {
		t.Fatalf("MaxACEsPerACL = %d", MaxACEsPerACL)
	}
}

// FuzzPlan feeds corpus bytes as a base SD. Properties: no panic; when the base decodes and a plan
// succeeds, the value decodes back, carries only a DACL, keeps the existing ACEs' bytes in order and
// has a SD_FLAGS control of DACL only (the FF-SD5 round-trip property).
func FuzzPlan(f *testing.F) {
	corpustest.Seed(f, "sd.write")
	user := mustSID("S-1-5-21-1-2-3-1105")
	f.Fuzz(func(t *testing.T, in []byte) {
		base, err := Decode(Raw(in))
		if err != nil {
			return
		}
		diff := ACEDiff{Add: []NewACE{{Trustee: mustSID("S-1-1-0"), Mask: MaskReadProp}}}
		if n := len(base.DACL.ACEs); n > 0 {
			diff.Remove = []ACERef{{Index: 0, Digest: DigestACE(base.DACL.ACEs[0])}}
		}
		w, plan, err := PlanDACL(base, diff, nil, ObjectCtx{ObjectGUID: *mustGUID("11111111-0000-0000-0000-000000000001"), Connector: PrincipalFromToken(user, []sid.SID{mustSID("S-1-1-0")})}, PlanOpts{Normalize: len(in)%2 == 0})
		if err != nil {
			if codec.Code(err) == "" || w.Valid() {
				t.Fatalf("error %v without a code, or with a usable write", err)
			}
			return
		}
		got, err := Decode(w.Value())
		if err != nil {
			t.Fatalf("plan output does not decode: %v", err)
		}
		if got.HasOwner || got.HasGroup || got.SACL.Kind != Absent || got.DACL.Kind != List {
			t.Fatal("plan output carries more than a DACL")
		}
		if len(plan.Inserted) != 1 || !bytes.Equal(got.DACL.ACEs[plan.Inserted[0]].Raw[:2], []byte{TypeAccessAllowed, 0}) {
			t.Fatal("inserted ACE not where the plan says")
		}
		// The written DACL has no anomaly beyond the order violations the plan reports.
		for _, an := range got.Anomalies {
			if an.Code != AnomalyOrderOutcome {
				t.Fatalf("plan output has anomaly %v", an)
			}
		}
		if len(got.Anomalies) > 0 && len(plan.NonCanonicalResult) == 0 && len(base.Anomalies) == 0 {
			t.Fatal("plan output is non-canonical and the plan does not say so")
		}
	})
}

// The planners work only on bytes Decode parsed: editing exported fields, or building an SD by
// hand, changes nothing or is refused.
func TestPlannersIgnoreMutatedSD(t *testing.T) {
	user := mustSID("S-1-5-21-1-2-3-1105")
	octx := ObjectCtx{ObjectGUID: *mustGUID("11111111-0000-0000-0000-000000000001"), Connector: PrincipalFromToken(user, []sid.SID{mustSID("S-1-1-0")})}
	diff := ACEDiff{Add: []NewACE{{Trustee: mustSID("S-1-1-0"), Mask: MaskReadProp}}}

	for _, name := range []string{"literal", "zero"} {
		s := SD{}
		if name == "literal" {
			s = SD{DACL: ACL{Kind: List, Revision: 4}, Control: ControlDACLPresent | ControlSelfRelative}
		}
		if _, _, err := PlanDACL(s, diff, nil, octx, PlanOpts{}); codec.Code(err) != ErrNotEditable {
			t.Fatalf("%s PlanDACL: %v", name, err)
		}
		if _, _, err := PlanInheritance(s, BlockKeepInherited, octx); codec.Code(err) != ErrNotEditable {
			t.Fatalf("%s PlanInheritance: %v", name, err)
		}
	}

	// Mutating an SD from Decode must not change what is planned.
	raw := buildBase(t, []NewACE{{Trustee: mustSID("S-1-5-18"), Mask: 0xF01FF}, {Trustee: user, Mask: MaskWriteDACL}}, user)
	good, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	w0, _, err := PlanDACL(good, diff, nil, octx, PlanOpts{})
	if err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.DACL.ACEs = append([]ACE(nil), good.DACL.ACEs...)
	bad.DACL.ACEs[0].Raw = []byte{0x7F, 0, 3, 0}
	bad.DACL.ACEs[0].Flags |= FlagInherited
	bad.Anomalies = []Anomaly{{Code: "x"}}
	bad.Control |= ControlDACLProtected
	w1, _, err := PlanDACL(bad, diff, nil, octx, PlanOpts{})
	if err != nil {
		t.Fatalf("mutation changed the outcome: %v", err)
	}
	if !bytes.Equal(w0.Value(), w1.Value()) || w0.BaseDigest() != w1.BaseDigest() {
		t.Fatal("mutated exported fields reached the write")
	}
	if err := w0.VerifyBase(bad); err != nil {
		t.Fatalf("VerifyBase must use the decoded bytes: %v", err)
	}
	if _, _, err := PlanDACL(good, diff, nil, ObjectCtx{Connector: octx.Connector}, PlanOpts{}); codec.Code(err) != ErrObjectRequired {
		t.Fatalf("zero object: %v", err)
	}
}
