package sd

import (
	"bytes"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
)

func aclSummary(a ACL) map[string]any {
	switch a.Kind {
	case Null:
		return map[string]any{"kind": "null"}
	case List:
		aces := make([]any, 0, len(a.ACEs))
		for _, e := range a.ACEs {
			m := map[string]any{"type": float64(e.Type), "flags": float64(e.Flags)}
			if e.Kind == Opaque {
				m["opaque"] = true
			} else {
				m["mask"] = float64(e.Mask)
				m["trustee"] = e.Trustee.String()
			}
			if e.ObjectType != nil {
				m["objectType"] = e.ObjectType.String()
			}
			if e.InheritedObjectType != nil {
				m["inheritedObjectType"] = e.InheritedObjectType.String()
			}
			aces = append(aces, m)
		}
		return map[string]any{"kind": "list", "rev": float64(a.Revision), "aces": aces}
	}
	return map[string]any{"kind": "absent"}
}

func tag(code string, idx, rule int) string {
	if idx < 0 {
		return code
	}
	if rule != 0 {
		return fmt.Sprintf("%s@%d/r%d", code, idx, rule)
	}
	return fmt.Sprintf("%s@%d", code, idx)
}

// summary is the JSON projection the corpus compares against.
func summary(s SD) map[string]any {
	m := map[string]any{"control": float64(s.Control), "dacl": aclSummary(s.DACL)}
	if s.HasOwner {
		m["owner"] = s.Owner.String()
	}
	if s.HasGroup {
		m["group"] = s.Group.String()
	}
	if s.SACL.Kind != Absent {
		m["sacl"] = aclSummary(s.SACL)
	}
	an, notes := []any{}, []any{}
	for _, a := range s.Anomalies {
		an = append(an, tag(a.Code, a.Index, a.Rule))
	}
	for _, n := range s.Notes {
		notes = append(notes, tag(n.Code, n.Index, n.Rule))
	}
	m["anomalies"], m["notes"] = an, notes
	return m
}

func parseSIDs(t *testing.T, csv string) []sid.SID {
	var out []sid.SID
	for _, p := range strings.Split(csv, ",") {
		if p == "" {
			continue
		}
		v, err := sid.Parse(p)
		if err != nil {
			t.Fatalf("sid %q: %v", p, err)
		}
		out = append(out, v)
	}
	return out
}

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/sd", "sd.read", func(r corpus.Record) (corpus.Result, error) {
		switch r.Call {
		case "Decode":
			in, err := r.Arg("sd")
			if err != nil {
				return corpus.Result{}, err
			}
			s, err := Decode(Raw(in.Raw))
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			return corpustest.Value(summary(s))
		case "ReadControl":
			in, err := r.Arg("parts")
			if err != nil || len(in.Raw) != 1 {
				return corpus.Result{}, fmt.Errorf("parts: %v", err)
			}
			var caps []SACLCap
			if _, ok := r.Args["cap"]; ok {
				caps = append(caps, SACLCap{ok: true}) // package-internal test token
			}
			c, err := ReadControl(Parts(in.Raw[0]), caps...)
			if err != nil {
				return corpustest.Err(codec.Code(err)), nil
			}
			if c.OID != "1.2.840.113556.1.4.801" || !c.Critical {
				return corpus.Result{}, fmt.Errorf("control not critical SD_FLAGS: %+v", c)
			}
			return corpustest.BytesHex(c.Value), nil
		case "Grants":
			return grantsRecord(t, r)
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

func grantsRecord(t *testing.T, r corpus.Record) (corpus.Result, error) {
	sdIn, err := r.Arg("sd")
	if err != nil {
		return corpus.Result{}, err
	}
	s, err := Decode(Raw(sdIn.Raw))
	if err != nil {
		return corpus.Result{}, fmt.Errorf("record sd does not decode: %v", err)
	}
	maskIn, err := r.Arg("mask")
	if err != nil {
		return corpus.Result{}, err
	}
	mask, err := strconv.ParseUint(maskIn.Text(), 0, 32)
	if err != nil {
		return corpus.Result{}, err
	}
	right := Right{Mask: uint32(mask)}
	if _, ok := r.Args["object"]; ok {
		o, _ := r.Arg("object")
		g, err := guid.Parse(o.Text())
		if err != nil {
			return corpus.Result{}, err
		}
		right.Object = &g
	}
	var p Principal
	if _, ok := r.Args["sids"]; ok {
		in, _ := r.Arg("sids")
		p = PrincipalFromSIDs(parseSIDs(t, in.Text())...)
	} else {
		u, _ := r.Arg("user")
		g, _ := r.Arg("groups")
		p = PrincipalFromToken(parseSIDs(t, u.Text())[0], parseSIDs(t, g.Text()))
	}
	if _, ok := r.Args["object_sid"]; ok {
		o, _ := r.Arg("object_sid")
		p = p.WithObjectSID(parseSIDs(t, o.Text())[0])
	}
	res := Grants(p, right, s)
	srcs := []any{}
	for _, x := range res.Sources {
		srcs = append(srcs, map[string]any{"ace": float64(x.ACEIndex), "inherited": x.Inherited})
	}
	out := map[string]any{"decision": res.Decision.String(), "incomplete": res.Incomplete, "sources": srcs}
	if res.Why != "" {
		out["why"] = res.Why
	}
	return corpustest.Value(out)
}

func FuzzDecode(f *testing.F) {
	corpustest.Seed(f, "sd.read")
	f.Fuzz(func(t *testing.T, in []byte) {
		s, err := Decode(Raw(in))
		if err != nil {
			if codec.Code(err) == "" {
				t.Fatalf("error without a stable code: %v", err)
			}
			return
		}
		// Every ACE's bytes lie inside the input, and decoding is deterministic.
		for _, a := range append(append([]ACE{}, s.DACL.ACEs...), s.SACL.ACEs...) {
			if len(a.Raw) < minACELen || !bytes.Contains(in, a.Raw) {
				t.Fatalf("ACE bytes %x not inside the input", a.Raw)
			}
		}
		s2, err := Decode(Raw(in))
		if err != nil || fmt.Sprint(summary(s)) != fmt.Sprint(summary(s2)) {
			t.Fatalf("decode not deterministic")
		}
		// Grants never panics on a decoded SD.
		u := mustSID("S-1-5-21-1-2-3-1000")
		Grants(PrincipalFromToken(u, nil), Right{Mask: MaskReadProp}, s)
	})
}

func TestTooLarge(t *testing.T) { // SD-25
	if _, err := Decode(make([]byte, 1<<20)); codec.Code(err) != ErrTooLarge {
		t.Fatalf("got %v", err)
	}
	if _, err := Decode(make([]byte, MaxSDBytes)); codec.Code(err) == ErrTooLarge {
		t.Fatal("the limit itself is allowed")
	}
}

func TestNoPanicOnEveryPrefixAndFlip(t *testing.T) {
	f := corpustest.Load(t, "sd.read")
	for _, r := range f.Records {
		if r.Call != "Decode" {
			continue
		}
		in, _ := r.Arg("sd")
		for n := 0; n <= len(in.Raw); n++ {
			_, _ = Decode(Raw(in.Raw[:n]))
		}
		for i := range in.Raw {
			b := append([]byte(nil), in.Raw...)
			b[i] ^= 0xff
			_, _ = Decode(Raw(b))
		}
	}
}

func TestSACLCapabilityCannotBeForgedOutsidePackage(t *testing.T) {
	if _, err := ReadControl(PartSACL, SACLCap{}); codec.Code(err) != ErrSACLNeedsCapability {
		t.Fatalf("zero capability must not grant: %v", err)
	}
}

func TestGUIDBytesAreMixedEndian(t *testing.T) { // SD-H01 anchor
	f := corpustest.Load(t, "sd.read")
	want := []byte{0x70, 0x95, 0x29, 0x00, 0x6d, 0x24, 0xd0, 0x11, 0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29}
	for _, r := range f.Records {
		if r.ID != "SD-H01" {
			continue
		}
		in, _ := r.Arg("sd")
		if !bytes.Contains(in.Raw, want) {
			t.Fatal("Reset-Password GUID not in wire order")
		}
		s, err := Decode(Raw(in.Raw))
		if err != nil || s.DACL.ACEs[0].ObjectType.String() != "00299570-246d-11d0-a768-00aa006e0529" {
			t.Fatalf("decode: %v", err)
		}
		return
	}
	t.Fatal("SD-H01 missing")
}

// SD-27: for DACLs whose only order violations are cosmetic, Grants equals Grants on the copy
// stable-sorted by rules 3 and 4, for every principal/right pair.
func TestCosmeticOrderDoesNotChangeGrants(t *testing.T) {
	rng := rand.New(rand.NewSource(27))
	trustees := []sid.SID{mustSID("S-1-5-11"), mustSID("S-1-1-0"), mustSID("S-1-5-32-544"), mustSID("S-1-5-21-1-2-3-1105")}
	guids := make([]guid.GUID, 3)
	for i := range guids {
		guids[i][0] = byte(i + 1)
	}
	masks := []uint32{MaskReadProp, MaskWriteProp, MaskControlAccess, MaskReadProp | MaskWriteProp, MaskReadControl}
	for iter := 0; iter < 300; iter++ {
		var aces []ACE
		for i, n := 0, 2+rng.Intn(10); i < n; i++ {
			e := ACE{Kind: Basic, Type: TypeAccessAllowed, Mask: masks[rng.Intn(len(masks))], Trustee: trustees[rng.Intn(len(trustees))]}
			if rng.Intn(2) == 0 {
				e.Type = TypeAccessDenied
			}
			if rng.Intn(2) == 0 {
				e.Kind = Object
				e.Type += 5
				g := guids[rng.Intn(len(guids))]
				e.ObjectType = &g
			}
			aces = append(aces, e)
		}
		// Rule 2 (deny before allow) is outcome-changing: put the denies first, keep the rest random.
		sort.SliceStable(aces, func(i, j int) bool { return aces[i].deny() && !aces[j].deny() })
		a := ACL{Kind: List, Revision: 4, ACEs: aces}
		if len(a.Order().Outcome) != 0 {
			t.Fatal("setup broke an outcome rule")
		}
		sorted := append([]ACE(nil), aces...)
		sort.SliceStable(sorted, func(i, j int) bool { // within each type: whole-object ACEs first
			if sorted[i].deny() != sorted[j].deny() {
				return sorted[i].deny()
			}
			return sorted[i].ObjectType == nil && sorted[j].ObjectType != nil
		})
		s1 := SD{DACL: a}
		s2 := SD{DACL: ACL{Kind: List, Revision: 4, ACEs: sorted}}
		if len(s2.DACL.Order().Cosmetic) != 0 {
			t.Fatal("sorted copy still violates 3/4")
		}
		for _, tr := range trustees {
			for _, m := range masks {
				for _, o := range append([]*guid.GUID{nil}, &guids[0], &guids[1], &guids[2]) {
					p := PrincipalFromSIDs(tr, trustees[(iter)%len(trustees)])
					r := Right{Mask: m, Object: o}
					d1, d2 := Grants(p, r, s1).Decision, Grants(p, r, s2).Decision
					if d1 != d2 {
						t.Fatalf("iter %d: %v vs %v for %v %#x", iter, d1, d2, tr, m)
					}
				}
			}
		}
	}
}

func TestResultFlagsAnomalousSD(t *testing.T) {
	var s SD
	s.DACL = ACL{Kind: Null}
	s.Anomalies = []Anomaly{{AnomalyNullDACL, -1, 0}}
	r := Grants(PrincipalFromToken(mustSID("S-1-5-21-1-2-3-1"), []sid.SID{mustSID("S-1-1-0")}), Right{Mask: 1}, s)
	if r.Decision != Yes || !r.Anomalous {
		t.Fatalf("%+v", r)
	}
}
