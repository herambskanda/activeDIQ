// Package keystest is a fake KMS for tests (TM-F-SEAL): it models the contract real KMS profiles give
// keys.Provider — Encrypt/Decrypt with an encryption context that must match exactly on decrypt, key
// rotation by key id, and an outage switch. It is for tests only.
package keystest

import (
	"crypto/rand"
	"errors"
	"sync"

	"github.com/skenzeriq/activediq/internal/platform/keys"
)

// KMS is an in-memory fake key-management service. Its "ciphertext" is an opaque handle into the
// fake, so it can only be decrypted by asking the fake with the same encryption context.
type KMS struct {
	mu      sync.Mutex
	keyID   string
	store   map[string]entry
	down    bool
	Unwraps int // number of successful decrypt calls (TM-TB5-T3 metric test hook)
}

type entry struct {
	keyID   string
	context string
	pt      []byte
}

// New returns a fake KMS whose current key is keyID.
func New(keyID string) *KMS { return &KMS{keyID: keyID, store: map[string]entry{}} }

// SetDown simulates an outage: every call fails with keys.ProviderUnavailable.
func (k *KMS) SetDown(down bool) { k.mu.Lock(); k.down = down; k.mu.Unlock() }

// Rotate makes id the key used for new wraps; older handles still decrypt under their own key id.
func (k *KMS) Rotate(id string) { k.mu.Lock(); k.keyID = id; k.mu.Unlock() }

func (k *KMS) Ref() keys.KEKRef {
	k.mu.Lock()
	defer k.mu.Unlock()
	return keys.KEKRef{Provider: "fakekms", KeyID: k.keyID}
}

func ctxString(req keys.WrapRequest) string {
	return req.Tenant.String() + "|" + string([]byte{byte(req.Version >> 24), byte(req.Version >> 16), byte(req.Version >> 8), byte(req.Version)})
}

func (k *KMS) Wrap(req keys.WrapRequest, plaintext []byte) ([]byte, keys.KEKRef, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.down {
		return nil, keys.KEKRef{}, &keys.Error{Code: keys.ProviderUnavailable}
	}
	h := make([]byte, 16)
	if _, err := rand.Read(h); err != nil {
		return nil, keys.KEKRef{}, err
	}
	k.store[string(h)] = entry{keyID: k.keyID, context: ctxString(req), pt: append([]byte(nil), plaintext...)}
	return h, keys.KEKRef{Provider: "fakekms", KeyID: k.keyID}, nil
}

func (k *KMS) Unwrap(req keys.WrapRequest, ref keys.KEKRef, wrapped []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.down {
		return nil, &keys.Error{Code: keys.ProviderUnavailable}
	}
	e, ok := k.store[string(wrapped)]
	if !ok || e.keyID != ref.KeyID || e.context != ctxString(req) {
		return nil, errors.New("fakekms: InvalidCiphertext / encryption context mismatch")
	}
	k.Unwraps++
	return append([]byte(nil), e.pt...), nil
}
