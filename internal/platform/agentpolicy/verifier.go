package agentpolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Refusals of the Verifier. They name the rule, never the document. Each is one fitness case of
// ADR-0007 (P1 to P7).
var (
	ErrWrongTenant     = errors.New("agentpolicy: document is for another tenant")                      // P1
	ErrWrongKind       = errors.New("agentpolicy: document is for another agent kind")                  // P1
	ErrReplay          = errors.New("agentpolicy: sequence is not above the highest seen")              // P2
	ErrExpired         = errors.New("agentpolicy: document is past its not_after")                      // P3
	ErrLifetime        = errors.New("agentpolicy: document is valid for longer than the maximum")       // P3
	ErrUnknownKey      = errors.New("agentpolicy: key_id is not in the keyset")                         // P4 / P6
	ErrBadSignature    = errors.New("agentpolicy: signature does not verify")                           //
	ErrUnknownSigner   = errors.New("agentpolicy: keyset is signed by a key outside the keyset")        // P5
	ErrKeysetReplay    = errors.New("agentpolicy: keyset sequence is not above the current one")        //
	ErrAlreadyAnchored = errors.New("agentpolicy: keyset anchor is set; only re-enrolment replaces it") // P7
	ErrNotAnchored     = errors.New("agentpolicy: no keyset anchor yet")                                //
)

// Applied is what an agent records on the DC and reports to the server as an audit event whenever it
// applies a policy or a keyset (ADR-0007 decision 8): a hostile policy leaves a trace on the DC.
type Applied struct {
	What     string // "policy" or "keyset"
	Seq      uint64
	KeyID    string
	BodyHash [32]byte // policy body hash, or the hash of the keyset's signing bytes
}

// State is what an agent persists between restarts. It is the whole of the verifier's memory, so
// P2 (replay across restart) and P7 (the anchor) are properties of this value.
type State struct {
	Anchored  bool
	KeysetSeq uint64
	Keys      []KeysetKey
	// HighestPolicySeq is the highest policy_seq ever accepted.
	HighestPolicySeq uint64
	// Installed is the policy in force. It stays in force until replaced, however long the agent has
	// been offline and whatever its not_after says (ADR-0007 decision 3).
	Installed *AddcPolicy
}

// Verifier applies ADR-0007 decision 2, 4 and 5 for one agent: one tenant (from its certificate SAN)
// and one kind. It is not safe for concurrent use; the agent host serialises policy application.
type Verifier struct {
	tenant tenant.ID
	kind   string
	st     State
	// OnApplied, when set, is called after each document is accepted and persisted in memory.
	OnApplied func(Applied)
}

// NewVerifier returns a verifier for an agent just enrolled: no anchor, nothing installed.
func NewVerifier(tid tenant.ID, kind string) (*Verifier, error) {
	if tid.IsZero() || !ValidKind(kind) {
		return nil, ErrMalformed
	}
	return &Verifier{tenant: tid, kind: kind}, nil
}

// RestoreVerifier rebuilds a verifier from Snapshot output.
func RestoreVerifier(tid tenant.ID, kind string, snapshot []byte) (*Verifier, error) {
	v, err := NewVerifier(tid, kind)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(snapshot, &v.st); err != nil {
		return nil, ErrMalformed
	}
	return v, nil
}

// Snapshot is the state to persist in the data directory after every accepted document.
func (v *Verifier) Snapshot() ([]byte, error) { return json.Marshal(v.st) }

// Installed returns the policy in force, if any.
func (v *Verifier) Installed() (AddcPolicy, bool) {
	if v.st.Installed == nil {
		return AddcPolicy{}, false
	}
	return *v.st.Installed, true
}

// KeysetSeq is the sequence of the keyset the agent holds, for GetStatus.
func (v *Verifier) KeysetSeq() uint64 { return v.st.KeysetSeq }

// PolicySeq is the highest policy sequence the agent has accepted, for GetStatus.
func (v *Verifier) PolicySeq() uint64 { return v.st.HighestPolicySeq }

// Reenroll resets the anchor: the only way to replace it (P7). A new certificate has been issued, so
// the next keyset delivered on the authenticated channel is trusted on first use again. The installed
// policy stays in force until replaced; the sequence floor is reset because recovery from a restored
// or replaced server legitimately restarts it.
func (v *Verifier) Reenroll() {
	v.st.Anchored, v.st.KeysetSeq, v.st.Keys, v.st.HighestPolicySeq = false, 0, nil, 0
}

// Anchor accepts the first keyset after enrolment (trust on first use inside the channel enrolment
// authenticated, TM-D24). It must be well formed and signed by a key it lists. A second call is
// refused whatever it carries.
func (v *Verifier) Anchor(sk SignedKeyset) error {
	if v.st.Anchored {
		return ErrAlreadyAnchored
	}
	if err := sk.Keyset.validate(); err != nil {
		return err
	}
	if sk.Tenant != v.tenant.String() {
		return ErrWrongTenant
	}
	key, ok := findKey(sk.Keys, sk.SignerKeyID)
	if !ok {
		return ErrUnknownSigner
	}
	if !ed25519.Verify(key.Public, KeysetSigningBytes(sk.Keyset), sk.Signature) {
		return ErrBadSignature
	}
	v.st.Anchored, v.st.KeysetSeq, v.st.Keys = true, sk.Seq, cloneKeys(sk.Keys)
	v.applied(Applied{What: "keyset", Seq: sk.Seq, KeyID: sk.SignerKeyID, BodyHash: sha256.Sum256(KeysetSigningBytes(sk.Keyset))})
	return nil
}

// ApplyKeyset accepts the next link of the chain: a keyset signed by a key already held (P5), for
// this tenant, with a higher sequence. The keyset replaces the held one whole, which is how a
// retiring key is dropped (P6).
func (v *Verifier) ApplyKeyset(sk SignedKeyset) error {
	if !v.st.Anchored {
		return ErrNotAnchored
	}
	if err := sk.Keyset.validate(); err != nil {
		return err
	}
	if sk.Tenant != v.tenant.String() {
		return ErrWrongTenant
	}
	signer, ok := findKey(v.st.Keys, sk.SignerKeyID)
	if !ok {
		return ErrUnknownSigner
	}
	if !ed25519.Verify(signer.Public, KeysetSigningBytes(sk.Keyset), sk.Signature) {
		return ErrBadSignature
	}
	if sk.Seq <= v.st.KeysetSeq {
		return ErrKeysetReplay
	}
	v.st.KeysetSeq, v.st.Keys = sk.Seq, cloneKeys(sk.Keys)
	v.applied(Applied{What: "keyset", Seq: sk.Seq, KeyID: sk.SignerKeyID, BodyHash: sha256.Sum256(KeysetSigningBytes(sk.Keyset))})
	return nil
}

// ApplyPolicy verifies a policy at time now and, if it passes, installs it. Nothing is installed on
// any refusal. The order is: shape and bounds are not looked at before the cheap identity checks, so
// a document for another tenant is refused without parsing its body.
func (v *Verifier) ApplyPolicy(sp SignedPolicy, now time.Time) (AddcPolicy, error) {
	if !v.st.Anchored {
		return AddcPolicy{}, ErrNotAnchored
	}
	h := sp.Header
	if h.Tenant != v.tenant.String() {
		return AddcPolicy{}, ErrWrongTenant
	}
	if h.Kind != v.kind {
		return AddcPolicy{}, ErrWrongKind
	}
	key, ok := findKey(v.st.Keys, h.KeyID)
	if !ok {
		return AddcPolicy{}, ErrUnknownKey
	}
	if !ed25519.Verify(key.Public, PolicySigningBytes(h, sp.Body), sp.Signature) {
		return AddcPolicy{}, ErrBadSignature
	}
	if h.Seq <= v.st.HighestPolicySeq {
		return AddcPolicy{}, ErrReplay
	}
	if !h.NotAfter.After(h.IssuedAt) || h.NotAfter.Sub(h.IssuedAt) > MaxLifetime {
		return AddcPolicy{}, ErrLifetime
	}
	if now.After(h.NotAfter) {
		return AddcPolicy{}, ErrExpired
	}
	pol, err := DecodeAddcPolicy(sp.Body)
	if err != nil {
		return AddcPolicy{}, err
	}
	v.st.HighestPolicySeq, v.st.Installed = h.Seq, &pol
	v.applied(Applied{What: "policy", Seq: h.Seq, KeyID: h.KeyID, BodyHash: sha256.Sum256(sp.Body)})
	return pol, nil
}

func (v *Verifier) applied(a Applied) {
	if v.OnApplied != nil {
		v.OnApplied(a)
	}
}

func findKey(keys []KeysetKey, id string) (KeysetKey, bool) {
	for _, k := range keys {
		if k.KeyID == id {
			return k, true
		}
	}
	return KeysetKey{}, false
}

func cloneKeys(in []KeysetKey) []KeysetKey {
	out := make([]KeysetKey, len(in))
	for i, k := range in {
		k.Public = append(ed25519.PublicKey(nil), k.Public...)
		out[i] = k
	}
	return out
}
