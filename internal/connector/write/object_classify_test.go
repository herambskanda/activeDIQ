package write

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// refDir answers Get for GUID and DN references (memberOf and lastKnownParent are DNs).
type refDir struct {
	tier0.ADDirectory
	byGUID map[guid.GUID]*ad.Entry
	byDN   map[string]guid.GUID
	errDN  map[string]error
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

const (
	grpDN    = "CN=Staff,OU=G,DC=lab"
	parentDN = "OU=Old,DC=lab"
)

type delRig struct {
	p      *ADProvider
	d      *refDir
	grp    guid.GUID
	parent guid.GUID
}

func newDelRig(t *testing.T) *delRig {
	t.Helper()
	d := &refDir{byGUID: map[guid.GUID]*ad.Entry{}, byDN: map[string]guid.GUID{}, errDN: map[string]error{}}
	r := &delRig{d: d, grp: mk(80), parent: mk(81)}
	d.byDN[grpDN], d.byDN[parentDN] = r.grp, r.parent
	d.byGUID[r.grp] = ad.NewEntry(grpDN, map[string][][]byte{"objectClass": {[]byte("group")}, "cn": {[]byte("Staff")}})
	d.byGUID[r.parent] = ad.NewEntry(parentDN, map[string][][]byte{"objectClass": {[]byte("organizationalUnit")}, "cn": {[]byte("Old")}})
	r.p = &ADProvider{Dir: d, Pins: &memPins{}}
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

// entry is a clean deleted user; mod edits the attribute map.
func (r *delRig) entry(t *testing.T, mod func(map[string][][]byte)) *ad.Entry {
	t.Helper()
	a := map[string][][]byte{
		"objectSid":       {sidBytes(t, "S-1-5-21-1-2-3-1500")},
		"primaryGroupID":  {[]byte("513")},
		"memberOf":        {[]byte(grpDN)},
		"lastKnownParent": {[]byte(parentDN)},
	}
	if mod != nil {
		mod(a)
	}
	return ad.NewEntry("", a)
}

// A clean user passes; every basis refuses; anything unreadable fails closed (rule 8).
func TestClassifyDeletedEntry(t *testing.T) {
	ctx := context.Background()
	r := newDelRig(t)
	if v, err := r.p.classifyDeletedEntry(ctx, r.entry(t, nil), nil); err != nil || v.Tier0 {
		t.Fatalf("clean user: %+v %v", v, err)
	}
	gone := func(a map[string][][]byte) { a["lastKnownParent"] = [][]byte{[]byte("OU=Gone,DC=lab")} }
	if v, err := r.p.classifyDeletedEntry(ctx, r.entry(t, gone), nil); err != nil || v.Tier0 {
		t.Fatalf("gone parent: %+v %v", v, err)
	}

	cases := []struct {
		name  string
		mod   func(map[string][][]byte)
		setup func(*delRig) []guid.GUID // returns the designated set
		want  Basis
	}{
		{"C1 rid<1000", func(a map[string][][]byte) { a["objectSid"] = [][]byte{sidBytes(t, "S-1-5-21-1-2-3-500")} }, nil, tier0.C1},
		{"C5 sIDHistory", func(a map[string][][]byte) { a["sIDHistory"] = [][]byte{sidBytes(t, "S-1-5-21-9-9-9-1100")} }, nil, tier0.C5},
		{"primary group", func(a map[string][][]byte) { a["primaryGroupID"] = [][]byte{[]byte("512")} }, nil, tier0.C2},
		{"tier0 group", nil, func(r *delRig) []guid.GUID { r.setTier0(r.grp); return nil }, tier0.C2},
		{"designated group", nil, func(r *delRig) []guid.GUID { return []guid.GUID{r.grp} }, tier0.C2},
		{"group unreadable", nil, func(r *delRig) []guid.GUID { r.d.errDN[grpDN] = errors.New("boom"); return nil }, tier0.C2},
		{"tier0 last parent", nil, func(r *delRig) []guid.GUID { r.setTier0(r.parent); return nil }, tier0.C3},
	}
	for _, c := range cases {
		rg := newDelRig(t)
		var des []guid.GUID
		if c.setup != nil {
			des = c.setup(rg)
		}
		v, err := rg.p.classifyDeletedEntry(ctx, rg.entry(t, c.mod), des)
		if err != nil || !v.Tier0 || len(v.Bases) != 1 || v.Bases[0] != c.want {
			t.Errorf("%s: %+v %v", c.name, v, err)
		}
	}

	fail := map[string]func(map[string][][]byte){
		"no objectSid":        func(a map[string][][]byte) { delete(a, "objectSid") },
		"bad objectSid":       func(a map[string][][]byte) { a["objectSid"] = [][]byte{{1, 2}} },
		"bad memberOf":        func(a map[string][][]byte) { a["memberOf"] = [][]byte{[]byte("not a dn")} },
		"bad lastKnownParent": func(a map[string][][]byte) { a["lastKnownParent"] = [][]byte{[]byte("not a dn")} },
	}
	for name, mod := range fail {
		rg := newDelRig(t)
		if v, err := rg.p.classifyDeletedEntry(ctx, rg.entry(t, mod), nil); err == nil || !v.Tier0 {
			t.Errorf("%s: %+v %v", name, v, err)
		}
	}
	rg := newDelRig(t)
	rg.d.errDN[parentDN] = errors.New("boom")
	if v, err := rg.p.classifyDeletedEntry(ctx, rg.entry(t, nil), nil); err == nil || !v.Tier0 {
		t.Errorf("parent read error: %+v %v", v, err)
	}
}

// Handler: a restore of a deleted target refuses as tier0 before any write unless the provider can
// classify it and says clean.
func TestRestoreClassifyDeletedGate(t *testing.T) {
	kind := connectorv1.WriteKind_WRITE_KIND_OBJECT_RESTORE
	ch := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectRestore{ObjectRestore: &connectorv1.ObjectRestore{
		NewParent: &connectorv1.WriteTarget{Object: toWire(oP2), NcGuid: toWire(oNC)}, RdnValue: "Back"}}}
	attrs := []step.Attr{{Name: client.AttrNewParent, Values: []string{oP2.String()}}, {Name: client.AttrNewParentNC, Values: []string{oNC.String()}}, {Name: client.AttrRDN, Values: []string{"Back"}}}
	build := func(t *testing.T, mkp func(*fakeProv, ObjectDirectory) Provider) (*fakeObjects, *Handler) {
		run := passRun(nil)
		r := newRig(t, &run)
		r.prov.guard = &stubGuard{}
		d := &fakeObjects{parent: map[guidT]guidT{oT: oP1}, rdn: map[guidT]string{oT: "Jo", oP1: "A", oP2: "B"}, deleted: map[guidT]bool{oT: true}, bin: true}
		h, err := New(mkp(r.prov, d), r.gate, WithRecorder(r.rec), WithClock(func() time.Time { return r.now }))
		if err != nil {
			t.Fatal(err)
		}
		return d, h
	}
	plan := func(h *Handler) error {
		q := planReq(oT, ctxFor(oT, oP2))
		q.Kind, q.Change, q.Target = kind, ch, objTarget(oT)
		_, err := h.Plan(context.Background(), q)
		return err
	}
	cases := map[string]func(*fakeProv, ObjectDirectory) Provider{
		"no DeletedClassifier": func(p *fakeProv, d ObjectDirectory) Provider { return objProvPlain{p, d} },
		"classifier error": func(p *fakeProv, d ObjectDirectory) Provider {
			return objProv{fakeProv: p, dir: d, cd: func() (Verdict, error) { return Verdict{}, errors.New("x") }}
		},
		"tier0 verdict": func(p *fakeProv, d ObjectDirectory) Provider {
			return objProv{fakeProv: p, dir: d, cd: func() (Verdict, error) { return Verdict{Tier0: true, Bases: []Basis{tier0.C1}}, nil }}
		},
	}
	for name, mkp := range cases {
		t.Run(name, func(t *testing.T) {
			d, h := build(t, mkp)
			wantTier0(t, plan(h), connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
			a := applyReq(oT, ctxFor(oT, oP2))
			a.Kind, a.Change, a.Target = kind, ch, objTarget(oT)
			a.Precondition = &connectorv1.TargetPrecondition{Dc: testDC()}
			dg := step.Compute(client.DigestObjectRestore, authority.TargetRef{Connection: connID, GUID: oT.String(), NC: authority.NamingContextID(oNC.String())}, attrs)
			a.PlanDigest = dg[:]
			_, err := h.Apply(context.Background(), a)
			wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
			if d.writes != 0 {
				t.Fatal("wrote before the classification passed")
			}
		})
	}
	// Control: a clean verdict plans.
	_, h := build(t, func(p *fakeProv, d ObjectDirectory) Provider { return objProv{fakeProv: p, dir: d} })
	if err := plan(h); err != nil {
		t.Fatalf("clean verdict refused: %v", err)
	}
}

// TouchedLive for a move includes the old parent; an unreadable or deleted target refuses.
func TestMoveTouchedLive(t *testing.T) {
	op := objectOps()[connectorv1.WriteKind_WRITE_KIND_OBJECT_MOVE]
	r := newObjRig(t)
	ctx := context.Background()
	got, err := op.TouchedLive(ctx, r.dir, oT, moveChangeTo(oP2, oNC))
	if err != nil || len(got) != 1 || got[0] != oP1 {
		t.Fatalf("old parent: %v %v", got, err)
	}
	if _, err := op.TouchedLive(ctx, r.dir, mk(99), moveChangeTo(oP2, oNC)); err == nil {
		t.Fatal("unreadable target accepted")
	}
	r.dir.deleted[oT] = true
	if _, err := op.TouchedLive(ctx, r.dir, oT, moveChangeTo(oP2, oNC)); err == nil {
		t.Fatal("deleted target accepted")
	}
}
