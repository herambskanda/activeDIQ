package chain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit/canon"
)

// Checkpoint is a signed statement of the chain head at Seq (DM-81). PrevSeq and PrevHash name the
// previous checkpoint (zero and the zero hash for the first), so checkpoints chain too.
type Checkpoint struct {
	Tenant    [16]byte
	Seq       uint64
	Hash      Hash
	SignedAt  time.Time
	KeyID     string
	PrevSeq   uint64
	PrevHash  Hash
	Signature []byte
}

// Statement returns the bytes that are signed: the domain string, then adq-canon/1 of
// {tenant_id, seq, hash, signed_at, key_id, prev_checkpoint_seq, prev_checkpoint_hash}.
func (c Checkpoint) Statement() ([]byte, error) {
	var e canon.Encoder
	e.UUID(1, c.Tenant)
	e.Uint(2, c.Seq)
	e.Bytes(3, c.Hash[:])
	e.Time(4, c.SignedAt)
	e.String(5, c.KeyID)
	e.Uint(6, c.PrevSeq)
	e.Bytes(7, c.PrevHash[:])
	body, err := e.Result()
	if err != nil {
		return nil, err
	}
	return append([]byte(checkpointDomain+"\x00"), body...), nil
}

// Sign fills in the signature.
func (c *Checkpoint) Sign(key ed25519.PrivateKey) error {
	st, err := c.Statement()
	if err != nil {
		return err
	}
	c.Signature = ed25519.Sign(key, st)
	return nil
}

// ErrBadSignature is returned by VerifySignature.
var ErrBadSignature = errors.New("chain: checkpoint signature does not verify")

// VerifySignature checks the signature against pub.
func (c Checkpoint) VerifySignature(pub ed25519.PublicKey) error {
	st, err := c.Statement()
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, st, c.Signature) {
		return ErrBadSignature
	}
	return nil
}

// Fingerprint is the key identifier an operator pins out of band: hex SHA-256 of the raw public key.
// It is also the key_id.
func Fingerprint(pub ed25519.PublicKey) string {
	s := sha256.Sum256(pub)
	return hex.EncodeToString(s[:])
}

const crossSignDomain = "adq-audit-key-crosssign/1"

// Detail keys of a key.created event that carries a cross-signature.
const (
	DetailSignedBy       = "signed_by"
	DetailCrossSignature = "cross_signature"
)

// CrossSignStatement is what the outgoing key signs to vouch for its successor: the domain string, then
// adq-canon/1 of {tenant_id, signer key_id, new key_id, new public key}. The created seq is not covered:
// the chainer assigns it at commit, after the signature exists. A replay can only re-introduce the same
// successor key, which the outgoing key already vouched for.
func CrossSignStatement(tenant [16]byte, signerID, newID string, newPub ed25519.PublicKey) ([]byte, error) {
	var e canon.Encoder
	e.UUID(1, tenant)
	e.String(2, signerID)
	e.String(3, newID)
	e.Bytes(4, newPub)
	body, err := e.Result()
	if err != nil {
		return nil, err
	}
	return append([]byte(crossSignDomain+"\x00"), body...), nil
}

// CrossSign signs the statement with the outgoing key.
func CrossSign(tenant [16]byte, signer ed25519.PrivateKey, newPub ed25519.PublicKey) (signerID string, sig []byte, err error) {
	signerID = Fingerprint(signer.Public().(ed25519.PublicKey))
	st, err := CrossSignStatement(tenant, signerID, Fingerprint(newPub), newPub)
	if err != nil {
		return "", nil, err
	}
	return signerID, ed25519.Sign(signer, st), nil
}
