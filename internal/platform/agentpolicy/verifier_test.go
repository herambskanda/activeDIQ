package agentpolicy_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

type key struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   string
}

func newKey() key {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return key{pub, priv, agentpolicy.KeyID(pub)}
}

func ks(tid tenant.ID, seq uint64, signer key, active key, retiring ...key) agentpolicy.SignedKeyset {
	k := agentpolicy.Keyset{Tenant: tid, Seq: seq, IssuedAt: t0, SignerKeyID: signer.id}
	k.Keys = append(k.Keys, agentpolicy.KeysetKey{KeyID: active.id, Public: active.pub, State: agentpolicy.KeyActive})
	for _, r := range retiring {
		k.Keys = append(k.Keys, agentpolicy.KeysetKey{KeyID: r.id, Public: r.pub, State: agentpolicy.KeyRetiring, RetireAfter: t0.Add(agentpolicy.OverlapWindow)})
	}
	// order by key id
	for i := range k.Keys {
		for j := i + 1; j < len(k.Keys); j++ {
			if k.Keys[j].KeyID < k.Keys[i].KeyID {
				k.Keys[i], k.Keys[j] = k.Keys[j], k.Keys[i]
			}
		}
	}
	sk, err := agentpolicy.SignKeyset(k, signer.priv)
	if err != nil {
		panic(err)
	}
	return sk
}

func pol() agentpolicy.AddcPolicy {
	return agentpolicy.AddcPolicy{
		Password: agentpolicy.PasswordRules{MinLength: 12, MaxLength: 128, MinClasses: 3},
		Events: agentpolicy.EventRules{CollectionEnabled: true, Channels: []agentpolicy.Channel{agentpolicy.ChannelSecurity},
			EventIDs: []uint32{4624}, MaxEventsPerSecond: 10, BatchMaxBytes: 1024, OutboxMaxBytes: 4096},
	}
}

func sign(tid tenant.ID, k key, seq uint64, life time.Duration) agentpolicy.SignedPolicy {
	b, err := pol().Encode()
	if err != nil {
		panic(err)
	}
	sp, err := agentpolicy.SignPolicy(agentpolicy.PolicyHeader{Tenant: tid, Kind: agentpolicy.KindADDC, Seq: seq, IssuedAt: t0, NotAfter: t0.Add(life), KeyID: k.id}, b, k.priv)
	if err != nil {
		panic(err)
	}
	return sp
}

func anchored(t *testing.T, tid tenant.ID, k key) *agentpolicy.Verifier {
	t.Helper()
	v, err := agentpolicy.NewVerifier(tid, agentpolicy.KindADDC)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Anchor(ks(tid, 1, k, k)); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestP1WrongTenantRefused(t *testing.T) {
	a, b, k := tenant.New(), tenant.New(), newKey()
	v := anchored(t, a, k)
	if _, err := v.ApplyPolicy(sign(b, k, 1, time.Hour), t0); !errors.Is(err, agentpolicy.ErrWrongTenant) {
		t.Fatalf("%v", err)
	}
	if err := v.ApplyKeyset(ks(b, 2, k, k)); err == nil {
		t.Fatal("keyset of another tenant accepted")
	}
}

func TestP2ReplayAndRollbackRefusedAcrossRestart(t *testing.T) {
	a, k := tenant.New(), newKey()
	v := anchored(t, a, k)
	for _, seq := range []uint64{5} {
		if _, err := v.ApplyPolicy(sign(a, k, seq, time.Hour), t0); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := v.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	r, err := agentpolicy.RestoreVerifier(a, agentpolicy.KindADDC, snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{5, 4, 1} {
		if _, err := r.ApplyPolicy(sign(a, k, seq, time.Hour), t0); !errors.Is(err, agentpolicy.ErrReplay) {
			t.Fatalf("seq %d after restart: %v", seq, err)
		}
	}
	if _, err := r.ApplyPolicy(sign(a, k, 6, time.Hour), t0); err != nil {
		t.Fatalf("next: %v", err)
	}
}

func TestP3ExpiredRefusedInstalledKept(t *testing.T) {
	a, k := tenant.New(), newKey()
	v := anchored(t, a, k)
	if _, err := v.ApplyPolicy(sign(a, k, 1, time.Hour), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ApplyPolicy(sign(a, k, 2, time.Hour), t0.Add(2*time.Hour)); !errors.Is(err, agentpolicy.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, ok := v.Installed(); !ok || v.PolicySeq() != 1 {
		t.Fatal("installed policy dropped or sequence moved")
	}
	// The signer refuses an over-long lifetime; a forged one (signed by hand) is refused by the agent.
	b, _ := pol().Encode()
	h := agentpolicy.PolicyHeader{Tenant: a, Kind: agentpolicy.KindADDC, Seq: 3, IssuedAt: t0, NotAfter: t0.Add(agentpolicy.MaxLifetime + time.Second), KeyID: k.id}
	if _, err := agentpolicy.SignPolicy(h, b, k.priv); err == nil {
		t.Fatal("signer signed an over-long lifetime")
	}
	forged := agentpolicy.SignedPolicy{Header: h, Body: b, Signature: ed25519.Sign(k.priv, agentpolicy.PolicySigningBytes(h, b))}
	if _, err := v.ApplyPolicy(forged, t0); !errors.Is(err, agentpolicy.ErrLifetime) {
		t.Fatalf("lifetime: %v", err)
	}
}

func TestP4UnknownKeyIDRefused(t *testing.T) {
	a, k, other := tenant.New(), newKey(), newKey()
	v := anchored(t, a, k)
	if _, err := v.ApplyPolicy(sign(a, other, 1, time.Hour), t0); !errors.Is(err, agentpolicy.ErrUnknownKey) {
		t.Fatalf("%v", err)
	}
	// Right key id, wrong signature.
	sp := sign(a, k, 1, time.Hour)
	sp.Signature[0] ^= 1
	if _, err := v.ApplyPolicy(sp, t0); !errors.Is(err, agentpolicy.ErrBadSignature) {
		t.Fatalf("%v", err)
	}
}

func TestP5KeysetSignedByUnknownKeyRefused(t *testing.T) {
	a, k, evil := tenant.New(), newKey(), newKey()
	v := anchored(t, a, k)
	if err := v.ApplyKeyset(ks(a, 2, evil, evil)); !errors.Is(err, agentpolicy.ErrUnknownSigner) {
		t.Fatalf("%v", err)
	}
	if v.KeysetSeq() != 1 {
		t.Fatal("keyset moved")
	}
}

func TestP6OldKeyAcceptedDuringOverlapRefusedAfterDrop(t *testing.T) {
	a, old, fresh := tenant.New(), newKey(), newKey()
	v := anchored(t, a, old)
	if err := v.ApplyKeyset(ks(a, 2, old, fresh, old)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ApplyPolicy(sign(a, old, 1, time.Hour), t0); err != nil {
		t.Fatalf("old key in overlap: %v", err)
	}
	if err := v.ApplyKeyset(ks(a, 3, fresh, fresh)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ApplyPolicy(sign(a, old, 2, time.Hour), t0); !errors.Is(err, agentpolicy.ErrUnknownKey) {
		t.Fatalf("old key after drop: %v", err)
	}
	if err := v.ApplyKeyset(ks(a, 3, fresh, fresh)); !errors.Is(err, agentpolicy.ErrKeysetReplay) {
		t.Fatalf("keyset replay: %v", err)
	}
}

func TestP7AnchorOnlyReplaceableByReenrol(t *testing.T) {
	a, k, k2 := tenant.New(), newKey(), newKey()
	v := anchored(t, a, k)
	if _, err := v.ApplyPolicy(sign(a, k, 1, time.Hour), t0); err != nil {
		t.Fatal(err)
	}
	if err := v.Anchor(ks(a, 1, k2, k2)); !errors.Is(err, agentpolicy.ErrAlreadyAnchored) {
		t.Fatalf("%v", err)
	}
	v.Reenroll()
	if _, ok := v.Installed(); !ok {
		t.Fatal("re-enrolment dropped the installed policy")
	}
	if err := v.Anchor(ks(a, 1, k2, k2)); err != nil {
		t.Fatalf("anchor after re-enrol: %v", err)
	}
	if _, err := v.ApplyPolicy(sign(a, k2, 1, time.Hour), t0); err != nil {
		t.Fatalf("sequence floor not reset: %v", err)
	}
}

func TestPolicyRoundTripAndBounds(t *testing.T) {
	a, k := tenant.New(), newKey()
	sp := sign(a, k, 1, time.Hour)
	back, err := agentpolicy.ParseSignedPolicy(sp.Marshal())
	if err != nil || back.Header != sp.Header {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := agentpolicy.ParseSignedPolicy(append(sp.Marshal(), 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	bad := pol()
	bad.Events.EventIDs = []uint32{4740, 4624}
	if _, err := bad.Encode(); !errors.Is(err, agentpolicy.ErrOutOfBounds) {
		t.Fatalf("unsorted ids: %v", err)
	}
	bad = pol()
	bad.Password.BannedTerms = []string{""}
	if _, err := bad.Encode(); !errors.Is(err, agentpolicy.ErrOutOfBounds) {
		t.Fatalf("empty banned term: %v", err)
	}
	// Domain separation: a keyset signature is not a policy signature.
	if string(agentpolicy.PolicyDomain) == string(agentpolicy.KeysetDomain) {
		t.Fatal("domains equal")
	}
}
