package write

import (
	"context"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// fakeObjects is an in-memory ObjectDirectory: parents and RDN values of live objects.
type fakeObjects struct {
	parent   map[guidT]guidT
	rdn      map[guidT]string
	deleted  map[guidT]bool
	bin      bool
	taken    string // a name already in use under any parent
	writes   int
	classes  []string
	deadline error

	// The deleted-object reads (kind 6 step 7).
	target       *ad.Entry
	targetErr    error
	container    []byte
	containerErr error
	members      map[guidT][]string
	memberErr    error
	calls        []string // the order of the step-7 reads
	dnOf         map[guidT]dn.DN
}

func (f *fakeObjects) DeletedTarget(context.Context, guidT) (*ad.Entry, error) {
	f.calls = append(f.calls, "target")
	return f.target, f.targetErr
}

func (f *fakeObjects) DeletedContainer(context.Context, dn.DN) (dn.DN, []byte, error) {
	f.calls = append(f.calls, "container")
	return dn.DN{}, f.container, f.containerErr
}

func (f *fakeObjects) GroupMembers(_ context.Context, g guidT) ([]string, bool, error) {
	f.calls = append(f.calls, "members")
	return f.members[g], false, f.memberErr
}

func (f *fakeObjects) State(_ context.Context, id guidT, _ bool) (ad.ObjectState, error) {
	if _, ok := f.rdn[id]; !ok {
		return ad.ObjectState{}, ad.NewError(ad.CodeObjectNotFound)
	}
	cls := f.classes
	if cls == nil {
		cls = []string{"top", "person", "organizationalPerson", "user"}
	}
	attrs := map[string][][]byte{"objectClass": nil}
	for _, c := range cls {
		attrs["objectClass"] = append(attrs["objectClass"], []byte(c))
	}
	st := ad.ObjectState{GUID: id, Classes: cls, Deleted: f.deleted[id], Entry: ad.NewEntry("", attrs)}
	if !st.Deleted {
		st.Parent = f.parent[id]
		d, _ := dn.Child(dn.DN{}, dn.CN, f.rdn[id])
		st.DN = d
		if x, ok := f.dnOf[id]; ok {
			st.DN = x
		}
	}
	return st, nil
}
func (f *fakeObjects) RecycleBin(context.Context) (bool, error) { return f.bin, nil }
func (f *fakeObjects) Move(_ context.Context, r ad.MoveRequest) error {
	if f.parent[r.Object] != r.ExpectParent {
		return ad.NewError(ad.CodeTargetChanged)
	}
	f.parent[r.Object] = r.NewParent
	f.writes++
	return nil
}
func (f *fakeObjects) Rename(_ context.Context, r ad.RenameRequest) error {
	if r.NewValue == f.taken {
		return ad.NewError(ad.CodeNameInUse)
	}
	f.rdn[r.Object] = r.NewValue
	f.writes++
	return nil
}
func (f *fakeObjects) Restore(_ context.Context, r ad.RestoreRequest) error {
	delete(f.deleted, r.Object)
	f.parent[r.Object], f.rdn[r.Object] = r.NewParent, r.Value
	f.writes++
	return nil
}

type objProv struct {
	*fakeProv
	dir ObjectDirectory
	cd  func() (Verdict, error) // ClassifyDeleted's answer; nil is a clean verdict
}

// objProvPlain has an object directory but no DeletedClassifier.
type objProvPlain struct {
	*fakeProv
	dir ObjectDirectory
}

func (p objProvPlain) Objects() ObjectDirectory { return p.dir }

func (p objProv) Objects() ObjectDirectory { return p.dir }
func (p objProv) ClassifyDeleted(context.Context, guidT, guidT, []guidT) (Verdict, error) {
	if p.cd != nil {
		return p.cd()
	}
	return Verdict{}, nil
}

type objRig struct {
	h    *Handler
	prov *fakeProv
	dir  *fakeObjects
}

var (
	oT, oP1, oP2, oNC = mk(60), mk(61), mk(62), mk(63)
)

func newObjRig(t *testing.T) *objRig {
	t.Helper()
	run := passRun(nil)
	r := newRig(t, &run)
	r.prov.guard = &stubGuard{}
	d := &fakeObjects{parent: map[guidT]guidT{oT: oP1}, rdn: map[guidT]string{oT: "Jo, Smith", oP1: "A", oP2: "B"}, deleted: map[guidT]bool{}}
	h, err := New(objProv{fakeProv: r.prov, dir: d}, r.gate, WithRecorder(r.rec), WithClock(func() time.Time { return r.now }))
	if err != nil {
		t.Fatal(err)
	}
	return &objRig{h: h, prov: r.prov, dir: d}
}

func objTarget(id guidT) *connectorv1.WriteTarget {
	return &connectorv1.WriteTarget{Object: toWire(id), NcGuid: toWire(oNC)}
}

func moveChangeTo(np guidT, nc guidT) *connectorv1.WriteChange {
	return &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectMove{ObjectMove: &connectorv1.ObjectMove{
		NewParent: &connectorv1.WriteTarget{Object: toWire(np), NcGuid: toWire(nc)}}}}
}

func (r *objRig) plan(kind connectorv1.WriteKind, ch *connectorv1.WriteChange, ids ...guidT) (*connectorv1.PlanResponse, error) {
	q := planReq(oT, ctxFor(ids...))
	q.Kind, q.Change, q.Target = kind, ch, objTarget(oT)
	return r.h.Plan(context.Background(), q)
}

func (r *objRig) apply(kind connectorv1.WriteKind, ch *connectorv1.WriteChange, pre *connectorv1.TargetPrecondition, attrs []step.Attr, key string, ids ...guidT) (*connectorv1.ApplyResponse, error) {
	q := applyReq(oT, ctxFor(ids...))
	q.Kind, q.Change, q.Target = kind, ch, objTarget(oT)
	pre.Dc = testDC()
	q.Precondition = pre
	d := step.Compute(key, authority.TargetRef{Connection: connID, GUID: oT.String(), NC: authority.NamingContextID(oNC.String())}, attrs)
	q.PlanDigest = d[:]
	return r.h.Apply(context.Background(), q)
}

func moveAttrs(np guidT) []step.Attr {
	return []step.Attr{{Name: client.AttrNewParent, Values: []string{np.String()}}, {Name: client.AttrNewParentNC, Values: []string{oNC.String()}}}
}

func TestObjectKindsMatchClient(t *testing.T) {
	if DigestObjectMove != client.DigestObjectMove || DigestObjectRename != client.DigestObjectRename || DigestObjectRestore != client.DigestObjectRestore {
		t.Fatal("digest keys differ between the client and the connector")
	}
	if AttrNewParent != client.AttrNewParent || AttrNewParentNC != client.AttrNewParentNC || AttrNewRDN != client.AttrNewRDN || AttrRDN != client.AttrRDN {
		t.Fatal("digest attribute names differ between the client and the connector")
	}
}

func TestMoveHappyPathAndRetry(t *testing.T) {
	r := newObjRig(t)
	kind := connectorv1.WriteKind_WRITE_KIND_OBJECT_MOVE
	ch := moveChangeTo(oP2, oNC)
	p, err := r.plan(kind, ch, oT, oP1, oP2) // statements for the target, the old parent and the new parent
	if err != nil || p.GetNoOp() {
		t.Fatalf("plan: %v %v", p, err)
	}
	a, err := r.apply(kind, ch, p.Precondition, moveAttrs(oP2), client.DigestObjectMove, oT, oP1, oP2)
	if err != nil || a.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED {
		t.Fatalf("apply: %v %v", a, err)
	}
	if r.dir.parent[oT] != oP2 || r.dir.writes != 1 {
		t.Fatal("object not moved exactly once")
	}
	// Retried after success: Plan says no-op, Apply says ALREADY_APPLIED and writes nothing.
	p2, err := r.plan(kind, ch, oT, oP2, oP2)
	if err != nil || !p2.GetNoOp() {
		t.Fatalf("replan: %v %v", p2, err)
	}
	a, err = r.apply(kind, ch, p.Precondition, moveAttrs(oP2), client.DigestObjectMove, oT, oP2)
	if err != nil || a.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED || r.dir.writes != 1 {
		t.Fatalf("retry: %v %v writes=%d", a, err, r.dir.writes)
	}
}

// CC-WK-13: the old parent and the new parent are each checked; a missing statement or a Tier-0
// container on either side refuses before any write.
func TestMoveChecksBothParents(t *testing.T) {
	kind := connectorv1.WriteKind_WRITE_KIND_OBJECT_MOVE
	ch := moveChangeTo(oP2, oNC)
	for name, mark := range map[string]guidT{"new parent tier0": oP2, "old parent tier0": oP1} {
		r := newObjRig(t)
		r.prov.tier0[mark] = []Basis{tier0.C6}
		_, err := r.plan(kind, ch, oT, oP1, oP2)
		wantTier0(t, err, connectorv1.Tier0RefusalStage_TIER0_REFUSAL_STAGE_LIVE_REREAD)
		if r.dir.writes != 0 {
			t.Errorf("%s: wrote", name)
		}
	}
	r := newObjRig(t)
	if _, err := r.plan(kind, ch, oT, oP2); err == nil { // no statement for the old parent
		t.Fatal("old parent without a statement was accepted")
	}
}

func TestMoveCrossDomainAndStale(t *testing.T) {
	r := newObjRig(t)
	kind := connectorv1.WriteKind_WRITE_KIND_OBJECT_MOVE
	_, err := r.plan(kind, moveChangeTo(oP2, mk(64)), oT, oP1, oP2)
	if ce := connErr(t, err); ce.GetRejectedInput().GetRuleId() != "CrossDomainMoveUnsupported" {
		t.Fatalf("got %v", ce)
	}
	ch := moveChangeTo(oP2, oNC)
	p, err := r.plan(kind, ch, oT, oP1, oP2)
	if err != nil {
		t.Fatal(err)
	}
	r.dir.parent[oT] = mk(65) // a second writer moved it between Plan and Apply
	_, err = r.apply(kind, ch, p.Precondition, moveAttrs(oP2), client.DigestObjectMove, oT, mk(65), oP2)
	if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_TARGET_CHANGED {
		t.Fatalf("got %s %v", c, connErr(t, err))
	}
	if r.dir.writes != 0 {
		t.Fatal("wrote over a changed target")
	}
}

func TestMoveClassNotAllowed(t *testing.T) {
	r := newObjRig(t)
	r.dir.classes = []string{"top", "container"}
	_, err := r.plan(connectorv1.WriteKind_WRITE_KIND_OBJECT_MOVE, moveChangeTo(oP2, oNC), oT, oP1, oP2)
	if connErr(t, err).GetRejectedInput().GetRuleId() != "ClassNotAllowed" {
		t.Fatalf("got %v", err)
	}
}

func TestRenameSpecialCharsNameInUseAndRetry(t *testing.T) {
	r := newObjRig(t)
	kind := connectorv1.WriteKind_WRITE_KIND_OBJECT_RENAME
	const name = `#a,b+c"d\e<f>g;h=i `
	ch := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectRename{ObjectRename: &connectorv1.ObjectRename{NewRdnValue: name}}}
	attrs := []step.Attr{{Name: client.AttrNewRDN, Values: []string{name}}}
	p, err := r.plan(kind, ch, oT)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.apply(kind, ch, p.Precondition, attrs, client.DigestObjectRename, oT); err != nil || r.dir.rdn[oT] != name {
		t.Fatalf("rename: %v %q", err, r.dir.rdn[oT])
	}
	p, err = r.plan(kind, ch, oT)
	if err != nil || !p.GetNoOp() {
		t.Fatalf("replan: %v %v", p, err)
	}
	// A name taken under the parent.
	r2 := newObjRig(t)
	r2.dir.taken = "dup"
	ch2 := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectRename{ObjectRename: &connectorv1.ObjectRename{NewRdnValue: "dup"}}}
	p, err = r2.plan(kind, ch2, oT)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r2.apply(kind, ch2, p.Precondition, []step.Attr{{Name: client.AttrNewRDN, Values: []string{"dup"}}}, client.DigestObjectRename, oT)
	if connErr(t, err).GetRejectedInput().GetRuleId() != "NameInUse" {
		t.Fatalf("got %v", err)
	}
}

func TestRestoreNeedsRecycleBinAndRestores(t *testing.T) {
	r := newObjRig(t)
	kind := connectorv1.WriteKind_WRITE_KIND_OBJECT_RESTORE
	r.dir.deleted[oT] = true
	ch := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectRestore{ObjectRestore: &connectorv1.ObjectRestore{
		NewParent: &connectorv1.WriteTarget{Object: toWire(oP2), NcGuid: toWire(oNC)}, RdnValue: "Back"}}}
	attrs := []step.Attr{{Name: client.AttrNewParent, Values: []string{oP2.String()}}, {Name: client.AttrNewParentNC, Values: []string{oNC.String()}}, {Name: client.AttrRDN, Values: []string{"Back"}}}
	_, err := r.plan(kind, ch, oT, oP2)
	if c := connErr(t, err).GetCode(); c != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("bin off: %s", c)
	}
	r.dir.bin = true
	p, err := r.plan(kind, ch, oT, oP2)
	if err != nil || p.GetNoOp() {
		t.Fatalf("plan: %v %v", p, err)
	}
	a, err := r.apply(kind, ch, p.Precondition, attrs, client.DigestObjectRestore, oT, oP2)
	if err != nil || a.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED || r.dir.deleted[oT] {
		t.Fatalf("apply: %v %v", a, err)
	}
	a, err = r.apply(kind, ch, p.Precondition, attrs, client.DigestObjectRestore, oT, oP2)
	if err != nil || a.GetOutcome() != connectorv1.ApplyOutcome_APPLY_OUTCOME_ALREADY_APPLIED || r.dir.writes != 1 {
		t.Fatalf("retry: %v %v", a, err)
	}
}

// The digest the Apply recomputes is the one the client's Step carries, and a digest over other
// attributes is refused before the directory is touched.
func TestObjectDigestMismatchRefused(t *testing.T) {
	r := newObjRig(t)
	kind := connectorv1.WriteKind_WRITE_KIND_OBJECT_MOVE
	ch := moveChangeTo(oP2, oNC)
	p, _ := r.plan(kind, ch, oT, oP1, oP2)
	_, err := r.apply(kind, ch, p.Precondition, moveAttrs(mk(70)), client.DigestObjectMove, oT, oP1, oP2)
	if connErr(t, err).GetRejectedInput().GetRuleId() != "PlanDigestMismatch" || r.dir.writes != 0 {
		t.Fatalf("got %v", err)
	}
}
