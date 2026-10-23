package chain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// builder makes an in-memory chain the way the server does.
type builder struct {
	tenant [16]byte
	prev   Hash
	seq    uint64
	events []StoredEvent
	cps    []Checkpoint
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
}

func newBuilder(t *testing.T, tenant byte) *builder {
	t.Helper()
	b := &builder{tenant: [16]byte{15: tenant}}
	b.prev = Genesis(b.tenant)
	b.pub, b.priv = key(t)
	b.keyCreated(b.pub)
	return b
}

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func (b *builder) add(kind string, details ...Detail) uint64 {
	b.seq++
	env := Envelope{Tenant: b.tenant, Seq: b.seq, At: t0.Add(time.Duration(b.seq) * time.Second), Kind: kind, KindVersion: 1,
		Requester: Principal{ID: "p1", Kind: "human"}, Outcome: "success", Details: details}
	raw, err := env.Marshal()
	if err != nil {
		panic(err)
	}
	h := Link(b.tenant, b.seq, b.prev, BodyHash(raw))
	b.events = append(b.events, StoredEvent{Seq: b.seq, Envelope: raw, PrevHash: b.prev, Hash: h})
	b.prev = h
	return b.seq
}

func (b *builder) keyCreated(pub ed25519.PublicKey) {
	b.add(KindKeyCreated, Detail{"key_id", Fingerprint(pub)}, Detail{"public_key", hex.EncodeToString(pub)})
}

func (b *builder) checkpoint(priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	c := Checkpoint{Tenant: b.tenant, Seq: b.seq, Hash: b.prev, SignedAt: t0, KeyID: Fingerprint(pub)}
	if n := len(b.cps); n > 0 {
		c.PrevSeq, c.PrevHash = b.cps[n-1].Seq, b.cps[n-1].Hash
	}
	if err := c.Sign(priv); err != nil {
		panic(err)
	}
	b.cps = append(b.cps, c)
}

func (b *builder) bundle() Bundle {
	return Bundle{Format: BundleFormat, Tenant: FormatUUID(b.tenant), FromSeq: 1, ToSeq: b.seq,
		Events: append([]StoredEvent(nil), b.events...), Checkpoints: append([]Checkpoint(nil), b.cps...)}
}

func seeded(t *testing.T) *builder {
	b := newBuilder(t, 1)
	for range 5 {
		b.add("operation.step.applied")
	}
	b.checkpoint(b.priv, b.pub) // seq 6
	for range 4 {
		b.add("operation.step.applied")
	}
	b.checkpoint(b.priv, b.pub) // seq 10
	return b
}

func want(t *testing.T, r Result, st Status, seq uint64, reason string) {
	t.Helper()
	if r.Status != st || r.Seq != seq || r.Reason != reason {
		t.Fatalf("result = %s seq %d %q (%s); want %s seq %d %q", r.Status, r.Seq, r.Reason, r.Detail, st, seq, reason)
	}
}

func TestVerifyOKWithPinAndWithAnchor(t *testing.T) {
	b := seeded(t)
	r := Verify(b.bundle(), Options{Pinned: []string{Fingerprint(b.pub)}})
	want(t, r, OK, 0, "")
	if r.Events != 10 || r.Checkpoints != 2 || r.TailUnsigned != 0 {
		t.Fatalf("counts = %+v", r)
	}
	want(t, Verify(b.bundle(), Options{Anchors: []Checkpoint{b.cps[0]}}), OK, 0, "")
}

func TestVerifyWithoutTrustRootIsUnanchoredNeverOK(t *testing.T) {
	want(t, Verify(seeded(t).bundle(), Options{}), Unanchored, 0, "")
}

func TestVerifyTailUnsigned(t *testing.T) {
	b := seeded(t)
	b.add("x")
	b.add("y")
	r := Verify(b.bundle(), Options{Pinned: []string{Fingerprint(b.pub)}})
	want(t, r, OK, 0, "")
	if r.TailUnsigned != 2 {
		t.Fatalf("tail = %d; want 2", r.TailUnsigned)
	}
}

func pin(b *builder) Options { return Options{Pinned: []string{Fingerprint(b.pub)}} }

func TestTamperEditedEvent(t *testing.T) {
	b := seeded(t)
	bu := b.bundle()
	env, _ := ParseEnvelope(bu.Events[3].Envelope)
	env.Outcome = "failure"
	bu.Events[3].Envelope, _ = env.Marshal()
	want(t, Verify(bu, pin(b)), Failed, 4, ReasonHash)

	// The attacker recomputes every hash from the edit forward: the signed checkpoint still catches it.
	prev := bu.Events[2].Hash
	for i := 3; i < len(bu.Events); i++ {
		e, _ := ParseEnvelope(bu.Events[i].Envelope)
		bu.Events[i].PrevHash = prev
		prev = Link(b.tenant, e.Seq, prev, BodyHash(bu.Events[i].Envelope))
		bu.Events[i].Hash = prev
	}
	want(t, Verify(bu, pin(b)), Failed, 6, ReasonCheckpointHash)
}

func TestTamperDeletedEvent(t *testing.T) {
	b := seeded(t)
	bu := b.bundle()
	bu.Events = append(bu.Events[:4], bu.Events[5:]...)
	want(t, Verify(bu, pin(b)), Failed, 5, ReasonSeqGap)
}

func TestTamperReorderedEvents(t *testing.T) {
	b := seeded(t)
	bu := b.bundle()
	bu.Events[3], bu.Events[4] = bu.Events[4], bu.Events[3]
	r := Verify(bu, pin(b))
	want(t, r, Failed, 4, ReasonSeqGap)
}

func TestTamperDuplicatedEvent(t *testing.T) {
	b := seeded(t)
	bu := b.bundle()
	bu.Events = append(bu.Events[:5], append([]StoredEvent{bu.Events[4]}, bu.Events[5:]...)...)
	want(t, Verify(bu, pin(b)), Failed, 6, ReasonSeqOrder)
}

func TestTamperInsertedEvent(t *testing.T) {
	b := seeded(t)
	bu := b.bundle()
	extra := newBuilder(t, 1)
	extra.seq = 4 // forge a seq 5 event with no chain context
	extra.add("forged")
	bu.Events = append(bu.Events[:4], append([]StoredEvent{extra.events[len(extra.events)-1]}, bu.Events[4:]...)...)
	r := Verify(bu, pin(b))
	if r.Status != Failed {
		t.Fatalf("inserted event verified: %+v", r)
	}
}

func TestTamperSplicedFromAnotherTenant(t *testing.T) {
	b := seeded(t)
	o := newBuilder(t, 2)
	for range 5 {
		o.add("operation.step.applied")
	}
	bu := b.bundle()
	bu.Events[4] = o.events[4] // same seq, valid in tenant 2's chain
	want(t, Verify(bu, pin(b)), Failed, 5, ReasonWrongTenant)
}

func TestTamperNonCanonicalEnvelope(t *testing.T) {
	b := seeded(t)
	bu := b.bundle()
	bu.Events[2].Envelope = append(append([]byte(nil), bu.Events[2].Envelope...), 0)
	want(t, Verify(bu, pin(b)), Failed, 3, ReasonNonCanonical)
}

func TestCheckpointSignedByRetiredKey(t *testing.T) {
	b := newBuilder(t, 1)
	b.add("a")
	b.checkpoint(b.priv, b.pub) // seq 2, valid
	pub2, priv2 := key(t)
	b.add(KindKeyRetired, Detail{"key_id", Fingerprint(b.pub)}) // seq 3
	b.keyCreated(pub2)                                          // seq 4
	b.add("b")
	b.checkpoint(priv2, pub2) // seq 5, valid
	opts := Options{Pinned: []string{Fingerprint(b.pub)}}
	// No cross-signature: nothing trusted covers the new key's introduction (T-0229 adds it).
	want(t, Verify(b.bundle(), opts), Failed, 5, ReasonUntrustedKey)
	opts.Pinned = append(opts.Pinned, Fingerprint(pub2)) // pinning both is the operator's explicit choice
	want(t, Verify(b.bundle(), opts), OK, 0, "")

	b.add("c")
	b.checkpoint(b.priv, b.pub) // seq 6 signed by the retired key
	want(t, Verify(b.bundle(), opts), Failed, 6, ReasonKeyWindow)
}

func TestCheckpointWithUnknownKeyAndBadSignature(t *testing.T) {
	b := seeded(t)
	bu := b.bundle()
	bu.Checkpoints[0].KeyID = "00"
	want(t, Verify(bu, pin(b)), Failed, 6, ReasonUnknownKey)
	bu = b.bundle()
	bu.Checkpoints[1].Signature = append([]byte(nil), bu.Checkpoints[1].Signature...)
	bu.Checkpoints[1].Signature[0] ^= 1
	want(t, Verify(bu, pin(b)), Failed, 10, ReasonBadSignature)
}

// The chain rebuilt and re-signed under a fresh key: with no trust root the verifier says UNANCHORED,
// with the pinned fingerprint it fails, and an anchor from before the rewrite exposes it too.
func TestWholeChainRebuiltUnderFreshKey(t *testing.T) {
	real := seeded(t)
	forged := newBuilder(t, 1) // same tenant, fresh key
	for range 5 {
		forged.add("operation.step.applied")
	}
	forged.checkpoint(forged.priv, forged.pub)
	for range 4 {
		forged.add("operation.step.applied")
	}
	forged.checkpoint(forged.priv, forged.pub)
	want(t, Verify(forged.bundle(), Options{}), Unanchored, 0, "")
	want(t, Verify(forged.bundle(), pin(real)), Failed, 6, ReasonUntrustedKey)
	want(t, Verify(forged.bundle(), Options{Anchors: real.cps[1:]}), Failed, 10, ReasonAnchorMismatch)
	want(t, Verify(forged.bundle(), Options{Anchors: real.cps}), Failed, 6, ReasonAnchorMismatch)
}

func TestPartialExportStartsAtCheckpoint(t *testing.T) {
	b := seeded(t)
	bu := b.bundle()
	bu.FromSeq = 7
	bu.Events = bu.Events[6:]
	bu.Keys = []KeyInfo{{KeyID: Fingerprint(b.pub), PublicKey: b.pub, CreatedSeq: 1}}
	want(t, Verify(bu, pin(b)), OK, 0, "")
	bu.Checkpoints = bu.Checkpoints[1:]
	want(t, Verify(bu, pin(b)), Failed, 7, ReasonNoStart)
}

func TestBundleJSONRoundTrip(t *testing.T) {
	b := seeded(t)
	var buf limitedBuf
	if err := WriteBundle(&buf, b.bundle()); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBundle(&buf)
	if err != nil {
		t.Fatal(err)
	}
	want(t, Verify(got, pin(b)), OK, 0, "")
}

func TestEnvelopeRoundTrip(t *testing.T) {
	e := Envelope{Tenant: [16]byte{1}, Seq: 7, At: t0, EventID: "e1", Kind: "k", KindVersion: 1,
		Requester: Principal{"p", "human"}, Via: []Principal{{"t", "api_token"}}, Connection: "c", TargetGUID: "g", TargetClass: "user",
		Operation: "op", Item: 0, Step: 0, HasStep: true, Outcome: "success", PlanHash: "ph",
		Changes: []Change{{"mail", false, 1, 1}, {"unicodePwd", true, 0, 0}}, Details: []Detail{{"a", "1"}, {"b", "2"}}}
	raw, err := e.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := got.Marshal()
	if string(again) != string(raw) || got.Seq != 7 || !got.HasStep || len(got.Changes) != 2 || !got.Changes[1].Secret || got.Via[0].ID != "t" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	e.Details = []Detail{{"b", "1"}, {"a", "2"}}
	if _, err := e.Marshal(); err == nil {
		t.Fatal("unsorted details accepted")
	}
}

func TestGenesisAndLinkBindTenantAndSeq(t *testing.T) {
	a, b := [16]byte{1}, [16]byte{2}
	if Genesis(a) == Genesis(b) {
		t.Fatal("genesis ignores the tenant")
	}
	body := BodyHash([]byte("x"))
	if Link(a, 1, Genesis(a), body) == Link(b, 1, Genesis(a), body) || Link(a, 1, Genesis(a), body) == Link(a, 2, Genesis(a), body) {
		t.Fatal("link ignores tenant or seq")
	}
}

type limitedBuf struct{ b []byte }

func (l *limitedBuf) Write(p []byte) (int, error) { l.b = append(l.b, p...); return len(p), nil }
func (l *limitedBuf) Read(p []byte) (int, error) {
	if len(l.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, l.b)
	l.b = l.b[n:]
	return n, nil
}

// Deleting the newest events, with or without the checkpoints that covered them, must not verify.
func TestTailTruncationFails(t *testing.T) {
	b := seeded(t)
	for _, tc := range []struct {
		name string
		mut  func(*Bundle)
	}{
		{"events dropped, claims kept", func(bu *Bundle) { bu.Events = bu.Events[:6] }},
		{"events and tail checkpoint dropped, claims kept", func(bu *Bundle) { bu.Events = bu.Events[:6]; bu.Checkpoints = bu.Checkpoints[:1] }},
		{"all of it rewritten to look shorter", func(bu *Bundle) { bu.Events = bu.Events[:6]; bu.Checkpoints = bu.Checkpoints[:1]; bu.ToSeq = 6 }},
		{"no events at all", func(bu *Bundle) { bu.Events, bu.Checkpoints, bu.ToSeq = nil, nil, 0; bu.FromSeq = 1 }},
		{"events dropped, range says empty", func(bu *Bundle) { bu.Events = nil }},
	} {
		bu := b.bundle()
		tc.mut(&bu)
		anchors := []Checkpoint{b.cps[1]} // the SIEM holds the newest checkpoint
		for _, opts := range []Options{{Anchors: anchors}, {Pinned: []string{Fingerprint(b.pub)}, Anchors: anchors}} {
			if r := Verify(bu, opts); r.Status != Failed {
				t.Errorf("%s: %s (%s); want FAILED", tc.name, r.Status, r.Detail)
			}
		}
	}
	// Against a pin alone, the claimed range still catches every case that leaves ToSeq alone.
	bu := b.bundle()
	bu.Events = bu.Events[:6]
	bu.Checkpoints = bu.Checkpoints[:1]
	want(t, Verify(bu, pin(b)), Failed, 6, ReasonTruncated)
	bu = b.bundle()
	bu.Checkpoints = bu.Checkpoints[:1]
	bu.Events = bu.Events[:6]
	bu.ToSeq = 6
	want(t, Verify(bu, Options{Pinned: []string{Fingerprint(b.pub)}, Anchors: b.cps[1:]}), Failed, 10, ReasonTruncated)
}

// A key the chain introduces after the last trusted checkpoint does not extend trust.
func TestForgedKeyAfterPinnedCheckpointIsNotTrusted(t *testing.T) {
	b := seeded(t)
	evil, evilPriv := key(t)
	b.keyCreated(evil) // seq 11, appended by someone with write access
	b.add("forged")
	b.checkpoint(evilPriv, evil) // seq 12
	want(t, Verify(b.bundle(), pin(b)), Failed, 12, ReasonUntrustedKey)
	// Under anchors only, trust starts from the anchored checkpoint's key.
	want(t, Verify(b.bundle(), Options{Anchors: b.cps[:1]}), Failed, 12, ReasonUntrustedKey)
}

func (b *builder) rotate(t *testing.T, oldPriv ed25519.PrivateKey, newPub ed25519.PublicKey, cross bool) {
	b.add(KindKeyRetired, Detail{"key_id", Fingerprint(oldPriv.Public().(ed25519.PublicKey))})
	d := []Detail{{"key_id", Fingerprint(newPub)}, {"public_key", hex.EncodeToString(newPub)}}
	if cross {
		id, sig, err := CrossSign(b.tenant, oldPriv, newPub)
		if err != nil {
			t.Fatal(err)
		}
		d = []Detail{{DetailCrossSignature, hex.EncodeToString(sig)}, d[0], d[1], {DetailSignedBy, id}}
	}
	b.add(KindKeyCreated, d...)
}

// The scenario of the second security re-review: a key injected while the genuine one is current gets
// covered by the server's next checkpoint, and later signs a rebuilt tail. It must not be trusted.
func TestInjectedKeyCoveredByGenuineCheckpointIsNotTrusted(t *testing.T) {
	b := seeded(t) // genuine cp@10
	evil, evilPriv := key(t)
	b.keyCreated(evil) // 11, injected
	b.add("x")         // 12
	b.checkpoint(b.priv, b.pub)
	b.add("y")
	b.checkpoint(evilPriv, evil)
	want(t, Verify(b.bundle(), pin(b)), Failed, 13, ReasonUntrustedKey)
}

// The production Rotate order (retire, create, no cross-signature) with only K1 pinned is not OK.
func TestRotationWithoutCrossSignatureIsNotTrusted(t *testing.T) {
	b := seeded(t)
	pub2, priv2 := key(t)
	b.rotate(t, b.priv, pub2, false)
	b.add("x")
	b.checkpoint(priv2, pub2)
	r := Verify(b.bundle(), pin(b))
	if r.Status == OK || r.Reason != ReasonUntrustedKey {
		t.Fatalf("got %+v", r)
	}
}

func TestCrossSignedRotationIsTrusted(t *testing.T) {
	b := seeded(t)
	pub2, priv2 := key(t)
	b.rotate(t, b.priv, pub2, true)
	b.add("x")
	b.checkpoint(priv2, pub2)
	want(t, Verify(b.bundle(), pin(b)), OK, 0, "")
}

func TestForgedCrossSignatureFails(t *testing.T) {
	b := seeded(t)
	evil, evilPriv := key(t)
	// Signed by the attacker's own key but claiming the genuine key as signer, then by a wrong statement.
	b.rotate(t, evilPriv, evil, true)
	b.add("x")
	b.checkpoint(evilPriv, evil)
	r := Verify(b.bundle(), pin(b))
	if r.Status != Failed {
		t.Fatalf("got %+v", r)
	}
	// A cross-signature naming the genuine signer with a bad signature.
	b2 := seeded(t)
	b2.add(KindKeyCreated, Detail{DetailCrossSignature, hex.EncodeToString(make([]byte, 64))}, Detail{"key_id", Fingerprint(evil)},
		Detail{"public_key", hex.EncodeToString(evil)}, Detail{DetailSignedBy, Fingerprint(b2.pub)})
	want(t, Verify(b2.bundle(), pin(b2)), Failed, 11, ReasonKeyEvent)
}

func TestManifestKeyWithoutChainEvidenceFails(t *testing.T) {
	b := seeded(t)
	evil, evilPriv := key(t)
	b.add("x")
	b.checkpoint(evilPriv, evil)
	bu := b.bundle()
	bu.Keys = []KeyInfo{{KeyID: Fingerprint(evil), PublicKey: evil, CreatedSeq: 1}}
	want(t, Verify(bu, pin(b)), Failed, 1, ReasonKeyMismatch)
	// Partial export: a manifest key claimed before the boundary is trusted only under a trusted checkpoint.
	bu = b.bundle()
	bu.FromSeq, bu.Events = 7, bu.Events[6:]
	bu.Keys = []KeyInfo{{KeyID: Fingerprint(b.pub), PublicKey: b.pub, CreatedSeq: 1}, {KeyID: Fingerprint(evil), PublicKey: evil, CreatedSeq: 1}}
	want(t, Verify(bu, pin(b)), Failed, 11, ReasonUntrustedKey)
}
