package agentpolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// Domain-separation prefixes. A signature over a policy can never verify as a keyset, or as anything
// else signed with the same key. The policy prefix is fixed by ADR-0007 decision 1; the keyset prefix
// is its sibling.
const (
	PolicyDomain = "activediq.agentpolicy.v1\x00"
	KeysetDomain = "activediq.agentkeyset.v1\x00"
)

// Limits.
const (
	// MaxLifetime is the longest a policy may be valid for acceptance (ADR-0007 decision 2).
	MaxLifetime = 30 * 24 * time.Hour
	// MaxKeys bounds a keyset: the active key and the keys still overlapping.
	MaxKeys = 4
	// OverlapWindow is how long a retiring key stays in the keyset: the longest not_after already
	// issued (ADR-0007 decision 4).
	OverlapWindow = MaxLifetime

	maxKeyIDLen = 40
	maxDocBytes = maxBodyBytes + 1<<10
)

// Agent kinds a policy can be for. They are the component kinds of the certificate SAN.
const (
	KindADDC       = "addc"
	KindFileServer = "fileserver"
)

// ValidKind reports whether k is a kind that takes a policy.
func ValidKind(k string) bool { return k == KindADDC || k == KindFileServer }

// KeyID derives a key's ID from its public key, so an ID cannot name a different key than the one it
// was computed from.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "k-" + hex.EncodeToString(h[:8])
}

// PolicyHeader is the signed part of a policy besides the body (ADR-0007 decision 2).
type PolicyHeader struct {
	Tenant   string // canonical tenant text; compared with the Verifier's tenant, never minted into an ID
	Kind     string
	Seq      uint64 // strictly increasing per tenant and kind
	IssuedAt time.Time
	NotAfter time.Time
	KeyID    string
}

// SignedPolicy is a policy document on the wire: a header, the canonical body and a signature over
// PolicyDomain, the header and the body's hash.
type SignedPolicy struct {
	Header    PolicyHeader
	Body      []byte
	Signature []byte
}

func (h PolicyHeader) encode(e *enc) {
	e.str(h.Tenant)
	e.str(h.Kind)
	e.u64(h.Seq)
	e.u64(uint64(h.IssuedAt.Unix()))
	e.u64(uint64(h.NotAfter.Unix()))
	e.str(h.KeyID)
}

// PolicySigningBytes are the exact bytes a policy signature covers.
func PolicySigningBytes(h PolicyHeader, body []byte) []byte {
	e := enc{b: []byte(PolicyDomain)}
	h.encode(&e)
	sum := sha256.Sum256(body)
	e.bytes(sum[:])
	return e.b
}

// Marshal returns the wire form of the document.
func (p SignedPolicy) Marshal() []byte {
	var e enc
	p.Header.encode(&e)
	e.bytes(p.Body)
	e.bytes(p.Signature)
	return e.b
}

// ParseSignedPolicy parses the wire form. It checks shape only; Verifier checks trust.
func ParseSignedPolicy(b []byte) (SignedPolicy, error) {
	if len(b) > maxDocBytes {
		return SignedPolicy{}, ErrMalformed
	}
	d := dec{b: b}
	var p SignedPolicy
	var err error
	p.Header, err = decodeHeader(&d)
	if err != nil {
		return SignedPolicy{}, err
	}
	p.Body = d.bytes(maxBodyBytes)
	p.Signature = d.bytes(ed25519.SignatureSize)
	if err := d.done(); err != nil {
		return SignedPolicy{}, err
	}
	return p, nil
}

// tenant reads the tenant text of a document. It is never turned into a tenant.ID: the Verifier compares
// it with its own tenant's text, so document bytes cannot mint an identity.
func (d *dec) tenant() string { return d.str(36) }

func decodeHeader(d *dec) (PolicyHeader, error) {
	var h PolicyHeader
	h.Tenant = d.tenant()
	h.Kind = d.str(16)
	h.Seq = d.u64()
	h.IssuedAt = time.Unix(int64(d.u64()), 0).UTC()
	h.NotAfter = time.Unix(int64(d.u64()), 0).UTC()
	h.KeyID = d.str(maxKeyIDLen)
	return h, d.err
}

// KeyState is where a key is in its life in a keyset.
type KeyState uint8

// Key states. A dropped key is simply absent from the next keyset.
const (
	KeyActive KeyState = iota + 1
	KeyRetiring
)

// KeysetKey is one public key in a keyset.
type KeysetKey struct {
	KeyID  string
	Public ed25519.PublicKey
	State  KeyState
	// RetireAfter is when the server will publish a keyset without this retiring key. It is
	// informative to the agent: only a keyset drops a key (ADR-0007 decision 4). Zero for active.
	RetireAfter time.Time
}

// Keyset is the set of public keys an agent trusts for a tenant.
type Keyset struct {
	Tenant   string // canonical tenant text; compared with the Verifier's tenant, never minted into an ID
	Seq      uint64
	IssuedAt time.Time
	// SignerKeyID names the key, already in the previous keyset (or in this one for the first),
	// that signed this document.
	SignerKeyID string
	// Keys is sorted by KeyID, has exactly one active key and at most MaxKeys entries.
	Keys []KeysetKey
}

// SignedKeyset is a keyset document on the wire.
type SignedKeyset struct {
	Keyset
	Signature []byte
}

// ErrKeyset is returned for a keyset that is not well formed.
var ErrKeyset = errors.New("agentpolicy: keyset is not well formed")

// validate checks the keyset's own shape: sorted, one active, IDs derived from keys.
func (k Keyset) validate() error {
	if k.Tenant == "" || k.Seq == 0 || len(k.Keys) == 0 || len(k.Keys) > MaxKeys || len(k.SignerKeyID) > maxKeyIDLen {
		return ErrKeyset
	}
	active := 0
	for i, key := range k.Keys {
		if len(key.Public) != ed25519.PublicKeySize || key.KeyID != KeyID(key.Public) || (i > 0 && k.Keys[i-1].KeyID >= key.KeyID) {
			return ErrKeyset
		}
		switch key.State {
		case KeyActive:
			active++
			if !key.RetireAfter.IsZero() {
				return ErrKeyset
			}
		case KeyRetiring:
			if key.RetireAfter.IsZero() {
				return ErrKeyset
			}
		default:
			return ErrKeyset
		}
	}
	if active != 1 {
		return ErrKeyset
	}
	return nil
}

func (k Keyset) encode(e *enc) {
	e.str(k.Tenant)
	e.u64(k.Seq)
	e.u64(uint64(k.IssuedAt.Unix()))
	e.str(k.SignerKeyID)
	e.u32(uint32(len(k.Keys)))
	for _, key := range k.Keys {
		e.str(key.KeyID)
		e.bytes(key.Public)
		e.u8(uint8(key.State))
		var ra uint64
		if !key.RetireAfter.IsZero() {
			ra = uint64(key.RetireAfter.Unix())
		}
		e.u64(ra)
	}
}

// KeysetSigningBytes are the exact bytes a keyset signature covers.
func KeysetSigningBytes(k Keyset) []byte {
	e := enc{b: []byte(KeysetDomain)}
	k.encode(&e)
	return e.b
}

// Marshal returns the wire form of the document.
func (s SignedKeyset) Marshal() []byte {
	var e enc
	s.Keyset.encode(&e)
	e.bytes(s.Signature)
	return e.b
}

// ParseSignedKeyset parses the wire form and checks the keyset's shape. Trust is the Verifier's.
func ParseSignedKeyset(b []byte) (SignedKeyset, error) {
	if len(b) > 4<<10 {
		return SignedKeyset{}, ErrMalformed
	}
	d := dec{b: b}
	var s SignedKeyset
	s.Tenant = d.tenant()
	s.Seq = d.u64()
	s.IssuedAt = time.Unix(int64(d.u64()), 0).UTC()
	s.SignerKeyID = d.str(maxKeyIDLen)
	n := d.u32()
	if d.err == nil && n > MaxKeys {
		return SignedKeyset{}, ErrKeyset
	}
	for i := uint32(0); i < n && d.err == nil; i++ {
		var key KeysetKey
		key.KeyID = d.str(maxKeyIDLen)
		key.Public = ed25519.PublicKey(d.bytes(ed25519.PublicKeySize))
		key.State = KeyState(d.u8())
		if ra := d.u64(); ra != 0 {
			key.RetireAfter = time.Unix(int64(ra), 0).UTC()
		}
		s.Keys = append(s.Keys, key)
	}
	s.Signature = d.bytes(ed25519.SignatureSize)
	if err := d.done(); err != nil {
		return SignedKeyset{}, err
	}
	if err := s.Keyset.validate(); err != nil {
		return SignedKeyset{}, err
	}
	return s, nil
}

func (k Keyset) sign(priv ed25519.PrivateKey) SignedKeyset {
	return SignedKeyset{Keyset: k, Signature: ed25519.Sign(priv, KeysetSigningBytes(k))}
}

// SignKeyset builds the signed document. It validates the keyset first, so a malformed chain link is
// never produced.
func SignKeyset(k Keyset, priv ed25519.PrivateKey) (SignedKeyset, error) {
	if err := k.validate(); err != nil {
		return SignedKeyset{}, err
	}
	return k.sign(priv), nil
}

// SignPolicy builds a signed policy document for an already-validated, encoded body. The header's
// KeyID must be the ID of priv's public key.
func SignPolicy(h PolicyHeader, body []byte, priv ed25519.PrivateKey) (SignedPolicy, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || h.KeyID != KeyID(pub) || !ValidKind(h.Kind) || h.Tenant == "" || h.Seq == 0 ||
		!h.NotAfter.After(h.IssuedAt) || h.NotAfter.Sub(h.IssuedAt) > MaxLifetime {
		return SignedPolicy{}, ErrMalformed
	}
	return SignedPolicy{Header: h, Body: body, Signature: ed25519.Sign(priv, PolicySigningBytes(h, body))}, nil
}
