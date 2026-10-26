package chain

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"time"
)

// BundleFormat names the export bundle (ADR-0005 rule 11).
const BundleFormat = "adq-audit-export/1"

// MaxBundleBytes bounds what ReadBundle will parse, so a hostile file cannot exhaust the verifier.
const MaxBundleBytes = 1 << 30

// MarshalText renders a hash as hex.
func (h Hash) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(h[:])), nil }

// UnmarshalText reads a hex hash.
func (h *Hash) UnmarshalText(b []byte) error {
	if hex.DecodedLen(len(b)) != HashSize {
		return errors.New("chain: hash must be 64 hex characters")
	}
	_, err := hex.Decode(h[:], b)
	return err
}

// StoredEvent is one chained event as exported: its canonical envelope and the two hashes the server
// computed. The verifier recomputes both and trusts neither.
type StoredEvent struct {
	Seq      uint64 `json:"seq"`
	Envelope []byte `json:"envelope"`
	PrevHash Hash   `json:"prev_hash"`
	Hash     Hash   `json:"hash"`
}

// KeyInfo is a checkpoint key as the manifest lists it. CreatedSeq and RetiredSeq (0 when current) are
// its window in the chain; where the chain events are in the bundle they must agree.
type KeyInfo struct {
	KeyID      string `json:"key_id"`
	PublicKey  []byte `json:"public_key"`
	CreatedSeq uint64 `json:"created_seq"`
	RetiredSeq uint64 `json:"retired_seq,omitzero"`
}

// Bundle is adq-audit-export/1 without its personal side file (personal values arrive with the
// personal store).
type Bundle struct {
	Format      string        `json:"format"`
	Tenant      string        `json:"tenant"`
	FromSeq     uint64        `json:"from_seq"`
	ToSeq       uint64        `json:"to_seq"`
	Keys        []KeyInfo     `json:"keys"`
	Events      []StoredEvent `json:"events"`
	Checkpoints []Checkpoint  `json:"checkpoints"`
}

type checkpointWire struct {
	Tenant    string    `json:"tenant"`
	Seq       uint64    `json:"seq"`
	Hash      Hash      `json:"hash"`
	SignedAt  time.Time `json:"signed_at"`
	KeyID     string    `json:"key_id"`
	PrevSeq   uint64    `json:"prev_seq"`
	PrevHash  Hash      `json:"prev_hash"`
	Signature []byte    `json:"signature"`
}

// MarshalJSON writes the tenant as a UUID string.
func (c Checkpoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(checkpointWire{FormatUUID(c.Tenant), c.Seq, c.Hash, c.SignedAt.UTC(), c.KeyID, c.PrevSeq, c.PrevHash, c.Signature})
}

// UnmarshalJSON reads what MarshalJSON writes.
func (c *Checkpoint) UnmarshalJSON(b []byte) error {
	var w checkpointWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	t, err := ParseUUID(w.Tenant)
	if err != nil {
		return err
	}
	*c = Checkpoint{t, w.Seq, w.Hash, w.SignedAt, w.KeyID, w.PrevSeq, w.PrevHash, w.Signature}
	return nil
}

// FormatUUID renders 16 bytes in the canonical 8-4-4-4-12 form.
func FormatUUID(u [16]byte) string {
	h := hex.EncodeToString(u[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// ParseUUID reads the canonical form.
func ParseUUID(s string) ([16]byte, error) {
	var u [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, errors.New("chain: not a UUID")
	}
	h := s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	if _, err := hex.Decode(u[:], []byte(h)); err != nil {
		return u, errors.New("chain: not a UUID")
	}
	return u, nil
}

// WriteBundle writes the bundle as JSON.
func WriteBundle(w io.Writer, b Bundle) error {
	b.Format = BundleFormat
	// v1 parity: HTML escaping on, nil slices as null, one trailing newline.
	out, err := json.Marshal(b, jsontext.WithIndent(" "), jsontext.EscapeForHTML(true), json.FormatNilSliceAsNull(true), json.FormatNilMapAsNull(true), json.Deterministic(true))
	if err != nil {
		return err
	}
	_, err = w.Write(append(out, '\n'))
	return err
}

// ReadBundle parses a bundle, refusing unknown fields, trailing data and anything over MaxBundleBytes.
func ReadBundle(r io.Reader) (Bundle, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBundleBytes+1))
	if err != nil {
		return Bundle{}, err
	}
	if len(data) > MaxBundleBytes {
		return Bundle{}, errors.New("chain: bundle too large")
	}
	var b Bundle
	// json.Unmarshal rejects trailing data itself.
	if err := json.Unmarshal(data, &b, json.RejectUnknownMembers(true)); err != nil {
		return Bundle{}, fmt.Errorf("chain: bundle: %w", err)
	}
	return b, nil
}

// key returns the public key, or nil when malformed.
func (k KeyInfo) key() ed25519.PublicKey {
	if len(k.PublicKey) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(k.PublicKey)
}
