package write

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// Handler: a restore of a deleted target refuses as tier0 before any write unless the provider can
// classify it and says clean.
func TestRestoreClassifyDeletedGate(t *testing.T) {
	kind := connectorv1.WriteKind_WRITE_KIND_OBJECT_RESTORE
	ch := &connectorv1.WriteChange{Change: &connectorv1.WriteChange_ObjectRestore{ObjectRestore: &connectorv1.ObjectRestore{
		NewParent: &connectorv1.WriteTarget{Object: toWire(oP2), NcGuid: toWire(oNC)}, RdnValue: "Back"}}}
	attrs := []step.Attr{{Name: client.AttrNewParent, Values: []string{oP2.String()}}, {Name: client.AttrNewParentNC, Values: []string{oNC.String()}}, {Name: client.AttrRDN, Values: []string{"Back"}}}
	build := func(t *testing.T, mkp func(*fakeProv, StructureDirectory) Provider) (*fakeObjects, *Handler) {
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
	cases := map[string]func(*fakeProv, StructureDirectory) Provider{
		"no DeletedClassifier": func(p *fakeProv, d StructureDirectory) Provider { return objProvPlain{p, d} },
		"classifier error": func(p *fakeProv, d StructureDirectory) Provider {
			return objProv{fakeProv: p, dir: d, cd: func() (Verdict, error) { return Verdict{}, errors.New("x") }}
		},
		"tier0 verdict": func(p *fakeProv, d StructureDirectory) Provider {
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
	// The two answers that are not tier0: the grant that is not proven names its right, and a target
	// that does not exist is OBJECT_NOT_FOUND (contract §8.10.3 kind 6 steps 1 and 2).
	for name, c := range map[string]struct {
		err  error
		want connectorv1.ErrorCode
	}{
		"rights":    {&DeletedRightsError{Domain: "DC=lab"}, connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS},
		"no bin":    {ErrNoRecycleBin, connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED},
		"not found": {ErrDeletedNotFound, connectorv1.ErrorCode_ERROR_CODE_OBJECT_NOT_FOUND},
	} {
		_, h := build(t, func(p *fakeProv, d StructureDirectory) Provider {
			return objProv{fakeProv: p, dir: d, cd: func() (Verdict, error) { return Verdict{Tier0: true}, c.err }}
		})
		ce := connErr(t, plan(h))
		if ce.GetCode() != c.want {
			t.Errorf("%s: got %s", name, ce.GetCode())
		}
		if name == "rights" && !strings.Contains(ce.GetMessage(), "List Contents on Deleted Objects of DC=lab") {
			t.Errorf("message does not name the right: %q", ce.GetMessage())
		}
	}
	// Control: a clean verdict plans.
	_, h := build(t, func(p *fakeProv, d StructureDirectory) Provider { return objProv{fakeProv: p, dir: d} })
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
