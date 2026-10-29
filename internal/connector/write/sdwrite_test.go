package write

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// fakeSDSession counts what reaches the directory: ApplyDACL's refusals must leave both at zero.
type fakeSDSession struct {
	id         ad.DCIdentity
	idCalls    int
	writeCalls int
	readCalls  int
	stored     sd.SD
	storedGUID guid.GUID
	readErr    error
}

type fakeAudit struct{ got []DACLDiverged }

func (f *fakeAudit) WriteDiverged(d DACLDiverged) { f.got = append(f.got, d) }

func (f *fakeSDSession) ReadDACL(context.Context, dn.ObjectRef) (guid.GUID, sd.SD, error) {
	f.readCalls++
	return f.storedGUID, f.stored, f.readErr
}

func (f *fakeSDSession) DCIdentity(context.Context) (ad.DCIdentity, error) {
	f.idCalls++
	return f.id, nil
}

func (f *fakeSDSession) WriteDACL(context.Context, dn.ObjectRef, sd.DACLWrite, ad.ReplaceSDFunc) error {
	f.writeCalls++
	return nil
}

func testGUID(t *testing.T, s string) guid.GUID {
	t.Helper()
	g, err := guid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// testDACLWrite plans a valid DACLWrite for object g over a hand-built base DACL.
func testDACLWrite(t *testing.T, g guid.GUID) sd.DACLWrite {
	t.Helper()
	w, _ := testDACLPlan(t, g)
	return w
}

// testDACLPlan also returns the base SD the plan was made on.
func testDACLPlan(t *testing.T, g guid.GUID) (sd.DACLWrite, sd.SD) {
	t.Helper()
	conn, err := sid.Parse("S-1-5-21-1-2-3-1105")
	if err != nil {
		t.Fatal(err)
	}
	everyone, _ := sid.Parse("S-1-1-0")
	sys, _ := sid.Parse("S-1-5-18")
	cb := conn.Bytes()
	ace := make([]byte, 8, 8+len(cb)) // ACCESS_ALLOWED, full control for the connector
	ace[2] = byte(8 + len(cb))
	binary.LittleEndian.PutUint32(ace[4:], 0xF01FF)
	ace = append(ace, cb...)
	acl := make([]byte, 8, 8+len(ace))
	acl[0] = 2
	binary.LittleEndian.PutUint16(acl[2:], uint16(8+len(ace)))
	binary.LittleEndian.PutUint16(acl[4:], 1)
	acl = append(acl, ace...)
	hdr := make([]byte, 20)
	hdr[0] = 1
	binary.LittleEndian.PutUint16(hdr[2:], 0x8004) // self-relative, DACL present
	binary.LittleEndian.PutUint32(hdr[16:], 20)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(20+len(acl)))
	raw := append(append(hdr, acl...), sys.Bytes()...)
	base, err := sd.Decode(sd.Raw(raw))
	if err != nil {
		t.Fatal(err)
	}
	w, _, err := sd.PlanDACL(base, sd.ACEDiff{Add: []sd.NewACE{{Trustee: everyone, Mask: sd.MaskReadProp}}}, nil,
		sd.ObjectCtx{ObjectGUID: g, Connector: sd.PrincipalFromToken(conn, []sid.SID{everyone})}, sd.PlanOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return w, base
}

func TestApplyDACLRefusals(t *testing.T) {
	a := testGUID(t, "11111111-0000-0000-0000-00000000000a")
	b := testGUID(t, "22222222-0000-0000-0000-00000000000b")
	dc1 := testGUID(t, "33333333-0000-0000-0000-000000000001")
	dc2 := testGUID(t, "33333333-0000-0000-0000-000000000002")
	tok := func(target, dc guid.GUID) Authorised {
		return Authorised{p: &pass{evaluated: []guid.GUID{target}, dc: dc, props: []string{"nTSecurityDescriptor"}}}
	}
	ref := dn.GUIDRef(b)

	cases := []struct {
		name string
		tok  Authorised
		w    sd.DACLWrite
		sess *fakeSDSession
		want string
	}{
		{"zero token", Authorised{}, testDACLWrite(t, b), &fakeSDSession{}, "not authorised"},
		{"token for another kind", Authorised{p: &pass{evaluated: []guid.GUID{b}, dc: dc1, props: []string{"member"}}}, testDACLWrite(t, b), &fakeSDSession{id: ad.DCIdentity{DSAGUID: dc1}}, "declares nTSecurityDescriptor"},
		{"zero write", tok(b, dc1), sd.DACLWrite{}, &fakeSDSession{}, "not from a planner"},
		{"token for another object", tok(a, dc1), testDACLWrite(t, b), &fakeSDSession{id: ad.DCIdentity{DSAGUID: dc1}}, "did not evaluate"},
		{"token not bound to a DC", tok(b, guid.GUID{}), testDACLWrite(t, b), &fakeSDSession{}, "not bound to a DC"},
		{"session bound to another DC", tok(b, dc1), testDACLWrite(t, b), &fakeSDSession{id: ad.DCIdentity{DSAGUID: dc2}}, "not bound to the DC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ApplyDACL(context.Background(), c.tok, c.sess, &fakeAudit{}, ref, c.w)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if c.sess.writeCalls != 0 {
				t.Fatal("a refused write reached the session")
			}
			if c.name != "session bound to another DC" && c.sess.idCalls != 0 {
				t.Fatal("session touched before the token checks passed")
			}
		})
	}

	// A matching token writes once and reads back once from the session.
	w, _ := testDACLPlan(t, b)
	stored, err := sd.Decode(w.Value())
	if err != nil {
		t.Fatal(err)
	}
	ok := &fakeSDSession{id: ad.DCIdentity{DSAGUID: dc1}, stored: stored, storedGUID: b}
	au := &fakeAudit{}
	if err := ApplyDACL(context.Background(), tok(b, dc1), ok, au, ref, w); err != nil || ok.writeCalls != 1 || ok.readCalls != 1 || len(au.got) != 0 {
		t.Fatalf("matching token: err=%v writes=%d reads=%d audits=%d", err, ok.writeCalls, ok.readCalls, len(au.got))
	}
	if err := ApplyDACL(context.Background(), tok(b, dc1), &fakeSDSession{id: ad.DCIdentity{DSAGUID: dc1}}, nil, ref, w); err == nil {
		t.Fatal("a nil auditor must be refused")
	}
}

// TestApplyDACLReadBack covers SD-R10: a divergent read-back is audited with the actual state, returned
// as sd.write_diverged and not retried; an unreadable read-back is an unknown-state error.
func TestApplyDACLReadBack(t *testing.T) {
	b := testGUID(t, "22222222-0000-0000-0000-00000000000b")
	dc1 := testGUID(t, "33333333-0000-0000-0000-000000000001")
	tok := Authorised{p: &pass{evaluated: []guid.GUID{b}, dc: dc1, props: []string{"nTSecurityDescriptor"}}}
	w, base := testDACLPlan(t, b)
	ref := dn.GUIDRef(b)

	div := &fakeSDSession{id: ad.DCIdentity{DSAGUID: dc1}, stored: base, storedGUID: b} // the DC kept the old DACL
	au := &fakeAudit{}
	err := ApplyDACL(context.Background(), tok, div, au, ref, w)
	if codec.Code(err) != sd.ErrWriteDiverged {
		t.Fatalf("err = %v, want %s", err, sd.ErrWriteDiverged)
	}
	if div.writeCalls != 1 || div.readCalls != 1 {
		t.Fatalf("no retry: writes=%d reads=%d", div.writeCalls, div.readCalls)
	}
	if len(au.got) != 1 || au.got[0].Object != b || au.got[0].DC != dc1 || au.got[0].Actual != sd.DigestDACL(base) ||
		au.got[0].PlannedBase != w.BaseDigest() || au.got[0].ActualACEs != len(base.DACL.ACEs) {
		t.Fatalf("audit = %+v", au.got)
	}
	planned, derr := sd.Decode(w.Value())
	if derr != nil {
		t.Fatal(derr)
	}
	if au.got[0].Planned != sd.DigestDACL(planned) || au.got[0].Planned == au.got[0].Actual {
		t.Fatalf("Planned digest = %x, want digest of planned DACL", au.got[0].Planned)
	}
	if au.got[0].Truncated || len(au.got[0].ACEs) != len(base.DACL.ACEs) || len(base.DACL.ACEs) == 0 {
		t.Fatalf("audited %d ACEs of %d (truncated=%v)", len(au.got[0].ACEs), len(base.DACL.ACEs), au.got[0].Truncated)
	}
	for i, e := range base.DACL.ACEs {
		g := au.got[0].ACEs[i]
		if g.Type != e.Type || g.Mask != e.Mask || g.Flags != e.Flags || g.Inherited != e.Inherited() || g.Trustee.String() != e.Trustee.String() {
			t.Fatalf("ACE %d audited as %+v, stored %+v", i, g, e)
		}
	}

	// A NULL DACL read back (everyone full control) must be told apart from an empty one (nobody).
	nullSD, emptySD := base, base
	nullSD.DACL = sd.ACL{Kind: sd.Null}
	emptySD.DACL = sd.ACL{Kind: sd.List, Revision: base.DACL.Revision}
	var recs [2]DACLDiverged
	for i, st := range []sd.SD{nullSD, emptySD} {
		au := &fakeAudit{}
		s := &fakeSDSession{id: ad.DCIdentity{DSAGUID: dc1}, stored: st, storedGUID: b}
		if err := ApplyDACL(context.Background(), tok, s, au, ref, w); codec.Code(err) != sd.ErrWriteDiverged || len(au.got) != 1 || s.writeCalls != 1 {
			t.Fatalf("kind case %d: err=%v audits=%d", i, err, len(au.got))
		}
		recs[i] = au.got[0]
		if len(recs[i].ACEs) != 0 || recs[i].ActualACEs != 0 {
			t.Fatalf("kind case %d: ACEs=%d", i, len(recs[i].ACEs))
		}
	}
	if recs[0].ActualKind != sd.Null || recs[1].ActualKind != sd.List || recs[0].PlannedKind != sd.List {
		t.Fatalf("kinds: null=%v empty=%v planned=%v", recs[0].ActualKind, recs[1].ActualKind, recs[0].PlannedKind)
	}
	if recs[0].Actual == recs[1].Actual {
		t.Fatal("NULL and empty DACL digests must differ")
	}

	for name, s := range map[string]*fakeSDSession{
		"read fails":   {id: ad.DCIdentity{DSAGUID: dc1}, readErr: errors.New("boom")},
		"other object": {id: ad.DCIdentity{DSAGUID: dc1}, stored: base, storedGUID: dc1},
	} {
		au := &fakeAudit{}
		if err := ApplyDACL(context.Background(), tok, s, au, ref, w); !errors.Is(err, ErrReadBack) || len(au.got) != 0 || s.writeCalls != 1 {
			t.Fatalf("%s: err=%v audits=%d writes=%d", name, err, len(au.got), s.writeCalls)
		}
	}
}

// TestApplyDACLTokenBindsDeclaredProperty drives the real guard: the token a kind receives records what
// that kind's PropertyWrite declared, so a token issued for another kind (here: a title update) cannot
// reach ApplyDACL, and one issued for a kind that declares nTSecurityDescriptor can.
func TestApplyDACLTokenBindsDeclaredProperty(t *testing.T) {
	for _, c := range []struct {
		name string
		pw   tier0.PropertyWrite
		ok   bool
	}{
		{"title kind", adUpdateTitle, false},
		{"DACL kind", tier0.PropertyWrite{Plane: tier0.PlaneAD, Kind: tier0.WriteUser, Op: tier0.OpUpdate, Keys: []string{"nTSecurityDescriptor"}}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := passRun(nil)
			r := newRig(t, &run)
			withTestOp(r)
			var tok Authorised
			op := r.h.ops[connectorv1.WriteKind(1)]
			op.PropertyWrite = declare(c.pw, nil)
			op.Apply = func(_ context.Context, a Authorised, _ *connectorv1.ApplyRequest) (*connectorv1.ApplyResponse, error) {
				tok = a
				return &connectorv1.ApplyResponse{Outcome: connectorv1.ApplyOutcome_APPLY_OUTCOME_APPLIED}, nil
			}
			r.h.ops[connectorv1.WriteKind(1)] = op
			tgt := mk(40)
			q := applyReq(tgt, ctxFor(tgt))
			q.Kind = 1
			if _, err := r.h.Apply(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			if got := tok.DeclaresProperty("ntsecuritydescriptor"); got != c.ok {
				t.Fatalf("DeclaresProperty = %v, want %v", got, c.ok)
			}
		})
	}
}
