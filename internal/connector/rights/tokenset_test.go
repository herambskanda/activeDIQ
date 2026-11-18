package rights

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

const (
	histSID  = "S-1-5-21-9-8-7-4242" // an account SID from before a migration
	histSID2 = "S-1-5-21-9-8-7-4243"
	extraGrp = domS + "-1200"
)

func sidsOf(t *testing.T, ts ...string) []sid.SID {
	t.Helper()
	var out []sid.SID
	for _, s := range ts {
		v, err := sid.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

func rawSIDs(t *testing.T, ts ...string) [][]byte {
	var out [][]byte
	for _, v := range sidsOf(t, ts...) {
		out = append(out, v.Bytes())
	}
	return out
}

// AC1: a clean check exports objectSid, every tokenGroups SID, the four implicit SIDs and every
// sIDHistory value, with the identity GUID and the domain SID.
func TestTokenSetHoldsTheWholeToken(t *testing.T) {
	w := newWorld(t)
	w.tokens = []string{dusSID, extraGrp}
	w.putRaw(w.id, "sIDHistory", rawSIDs(t, histSID, histSID2))
	r := w.run(t, ADInput{})
	if r.Verdict != v1.VerificationVerdict_VERIFICATION_VERDICT_PASS {
		t.Fatalf("verdict %v %v", r.Verdict, codes(r))
	}
	ts := r.Tokens
	want := append([]string{idSIDt, dusSID, extraGrp, histSID, histSID2}, implicitNetworkLogonSIDs...)
	if len(ts.SIDs) != len(want) {
		t.Fatalf("SIDs = %v, want %v", ts.SIDs, want)
	}
	for _, s := range sidsOf(t, want...) {
		if !ts.Has(s) {
			t.Errorf("token set lacks %s", s)
		}
	}
	if ts.IdentityGUID != w.idG {
		t.Errorf("IdentityGUID = %v, want %v", ts.IdentityGUID, w.idG)
	}
	if dom := sidsOf(t, domS)[0]; ts.DomainSID != dom {
		t.Errorf("DomainSID = %v, want %v", ts.DomainSID, dom)
	}
	if !ts.Complete {
		t.Error("a fully read token must be Complete")
	}
	for i := 1; i < len(ts.SIDs); i++ {
		if ts.SIDs[i-1].String() >= ts.SIDs[i].String() {
			t.Fatalf("SIDs must be sorted and unique: %v", ts.SIDs)
		}
	}
}

// The exported set is what the checks evaluated: a privileged SID in sIDHistory is in the access
// token, so step 1 sees the identity as a member of that group.
func TestSIDHistoryJoinsCheckTokens(t *testing.T) {
	w := newWorld(t)
	w.putRaw(w.id, "sIDHistory", rawSIDs(t, daSID))
	r := w.run(t, ADInput{})
	if r.Verdict == v1.VerificationVerdict_VERIFICATION_VERDICT_PASS {
		t.Fatalf("an identity whose sIDHistory is Domain Admins must not pass: %v", codes(r))
	}
	if !r.Tokens.Has(sidsOf(t, daSID)[0]) {
		t.Fatal("sIDHistory missing from the token set")
	}
}

func TestTokenSetIncompleteCases(t *testing.T) {
	t.Run("malformed sIDHistory value", func(t *testing.T) {
		w := newWorld(t)
		w.putRaw(w.id, "sIDHistory", [][]byte{{1, 2, 3}})
		r := w.run(t, ADInput{})
		if r.Tokens.Complete {
			t.Fatal("an undecodable sIDHistory must leave the set incomplete")
		}
		if sd.PrincipalFromSIDSet(r.Tokens.SIDs, r.Tokens.Complete).Incomplete() != true {
			t.Fatal("principal must be incomplete")
		}
	})
	t.Run("empty tokenGroups", func(t *testing.T) {
		w := newWorld(t)
		w.tokens = nil
		if r := w.run(t, ADInput{}); r.Tokens.Complete {
			t.Fatal("no tokenGroups: a real token always has a primary group")
		}
	})
}

// AC3: a deny ACE on a historic SID wins over an allow to Authenticated Users.
func TestPrincipalFromTokenSetDeniesOnHistoricSID(t *testing.T) {
	w := newWorld(t)
	w.putRaw(w.id, "sIDHistory", rawSIDs(t, histSID))
	r := w.run(t, ADInput{})
	obj := sdBytes(daSID,
		tace{deny: true, mask: dsReadProp, trustee: histSID},
		tace{mask: dsReadProp, trustee: "S-1-5-11"})
	s, err := sd.Decode(sd.Raw(obj))
	if err != nil {
		t.Fatal(err)
	}
	right := sd.Right{Mask: sd.MaskReadProp}
	got := sd.Grants(PrincipalFromTokenSet(r.Tokens), right, s)
	if got.Decision != sd.No || got.Incomplete {
		t.Fatalf("with sIDHistory: %v incomplete=%v, want No", got.Decision, got.Incomplete)
	}
	// Control: the same identity without the history (objectSid plus tokenGroups plus implicit SIDs
	// only) is allowed, which is the false Yes the export closes.
	w2 := newWorld(t)
	r2 := w2.run(t, ADInput{})
	if got := sd.Grants(PrincipalFromTokenSet(r2.Tokens), right, s); got.Decision != sd.Yes {
		t.Fatalf("control: %v, want Yes", got.Decision)
	}
}

func TestPrincipalFromTokenSetIncomplete(t *testing.T) {
	if !PrincipalFromTokenSet(TokenSet{}).Incomplete() {
		t.Fatal("the zero set is not a usable token")
	}
	ts := TokenSet{SIDs: sidsOf(t, idSIDt), Complete: false}
	if !PrincipalFromTokenSet(ts).Incomplete() {
		t.Fatal("Complete=false must give an Incomplete principal")
	}
}

// AC2 and the epoch rules, through the real stream.
func TestEpochTokenSetAccessor(t *testing.T) {
	ctx := context.Background()
	t.Run("no run yet", func(t *testing.T) {
		if _, ok := newEpochFix(t).state().TokenSet(); ok {
			t.Fatal("no run completed: ok must be false")
		}
	})
	t.Run("clean run records the set with its epoch", func(t *testing.T) {
		w := newWorld(t)
		w.putRaw(w.id, "sIDHistory", rawSIDs(t, histSID))
		ep := newEpochFix(t).state()
		req := request(w)
		if _, err := w.stream(t, ep, req); err != nil {
			t.Fatal(err)
		}
		ts, ok := ep.TokenSet()
		if !ok {
			t.Fatal("clean run: ok must be true")
		}
		if ts.Epoch != guidText(req.GetVerificationId()) || ts.IdentityGUID != w.idG || !ts.Complete || !ts.Has(sidsOf(t, histSID)[0]) {
			t.Fatalf("set %+v", ts)
		}
		// The accessor returns a copy.
		ts.SIDs[0] = sidsOf(t, "S-1-5-18")[0]
		if again, _ := ep.TokenSet(); again.Has(sidsOf(t, "S-1-5-18")[0]) {
			t.Fatal("accessor leaked its backing array")
		}
	})
	t.Run("a failed check in the next epoch clears it", func(t *testing.T) {
		w := newWorld(t)
		ep := newEpochFix(t).state()
		if _, err := w.stream(t, ep, request(w)); err != nil {
			t.Fatal(err)
		}
		if _, ok := ep.TokenSet(); !ok {
			t.Fatal("setup: clean run")
		}
		w.tokens = []string{dusSID, daSID} // the identity is now a Domain Admin: V7 refuses
		req := request(w)
		req.VerificationId = pbGuid(guidN(98))
		msgs, err := w.stream(t, ep, req)
		if err != nil {
			t.Fatal(err)
		}
		if v := msgs[len(msgs)-1].GetCompleted().GetVerdict(); v == v1.VerificationVerdict_VERIFICATION_VERDICT_PASS {
			t.Fatalf("setup: verdict %v, want a failed check", v)
		}
		if _, ok := ep.TokenSet(); ok {
			t.Fatal("failed check: ok must be false")
		}
	})
	t.Run("a new epoch with no clean check yet", func(t *testing.T) {
		w := newWorld(t)
		ep := newEpochFix(t).state()
		if _, err := w.stream(t, ep, request(w)); err != nil {
			t.Fatal(err)
		}
		// Another run completed without a set (as Complete does for a run that did not pass).
		if _, err := ep.Complete(ctx, "next", nil); err != nil {
			t.Fatal(err)
		}
		if _, ok := ep.TokenSet(); ok {
			t.Fatal("new epoch without a clean check: ok must be false")
		}
	})
	t.Run("a failed durable write drops the previous set", func(t *testing.T) {
		fx := newEpochFix(t)
		ep := fx.state()
		ts := TokenSet{SIDs: sidsOf(t, idSIDt), Complete: true}
		if _, err := ep.CompleteWithTokens(ctx, "e1", nil, &ts); err != nil {
			t.Fatal(err)
		}
		if _, ok := ep.TokenSet(); !ok {
			t.Fatal("setup")
		}
		ep.store = failingStore{}
		if _, err := ep.CompleteWithTokens(ctx, "e2", nil, &ts); err == nil {
			t.Fatal("setup: the save must fail")
		}
		if _, ok := ep.TokenSet(); ok {
			t.Fatal("after a failed Complete the old epoch's set must not stay readable")
		}
	})
	t.Run("restart", func(t *testing.T) {
		fx := newEpochFix(t)
		ts := TokenSet{SIDs: sidsOf(t, idSIDt), Complete: true}
		if _, err := fx.state().CompleteWithTokens(ctx, "e1", nil, &ts); err != nil {
			t.Fatal(err)
		}
		if _, ok := fx.state().TokenSet(); ok {
			t.Fatal("a restarted process has no set until a fresh run")
		}
	})
}

type failingStore struct{}

func (failingStore) Load() (*Baseline, error) { return nil, context.Canceled }
func (failingStore) Save(*Baseline) error     { return context.Canceled }
