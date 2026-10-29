package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// The passphrase keystore (keys-custody-design §2, K6): kek.keystore.json holds a random 32-byte KEK
// sealed under a key derived from the operator's passphrase with Argon2id. The KEK is independent of the
// passphrase, so a passphrase change re-seals this file and re-wraps no DEK. This file is pure format and
// crypto; reading the passphrase and the file safely is the composition root's job.

// Keystore constants.
const (
	// KeystoreFile is the keystore's file name inside the KEK directory.
	KeystoreFile = "kek.keystore.json"
	// KeystoreFormat is the only format version this build reads and writes.
	KeystoreFormat = 1
	// KDFArgon2id is the only key-derivation algorithm.
	KDFArgon2id = "argon2id"
	// MaxKeystoreBytes bounds what a loader reads: a keystore is a few hundred bytes.
	MaxKeystoreBytes = 16 << 10

	saltSize      = 16
	maxKeyIDBytes = 64
)

// Argon2id bounds the loader enforces, so a doctored file can neither downgrade the KDF nor exhaust
// memory (design §2). m is in KiB.
const (
	MinKDFMemoryKiB = 19 << 10
	MaxKDFMemoryKiB = 1 << 20
	MinKDFTime      = 2
	MaxKDFTime      = 10
	MinKDFLanes     = 1
	MaxKDFLanes     = 16
)

// KDFParams are the Argon2id cost parameters; M is in KiB. The zero value means DefaultKDF.
type KDFParams struct {
	M uint32 `json:"m"`
	T uint32 `json:"t"`
	P uint8  `json:"p"`
}

// DefaultKDF is 64 MiB, 3 passes, 4 lanes.
var DefaultKDF = KDFParams{M: 64 << 10, T: 3, P: 4}

// FloorKDF is the cheapest parameter set the loader accepts (tests only; never a production default).
var FloorKDF = KDFParams{M: MinKDFMemoryKiB, T: MinKDFTime, P: MinKDFLanes}

func (k KDFParams) valid() bool {
	return k.M >= MinKDFMemoryKiB && k.M <= MaxKDFMemoryKiB &&
		k.T >= MinKDFTime && k.T <= MaxKDFTime && k.P >= MinKDFLanes && k.P <= MaxKDFLanes
}

type keystoreKDF struct {
	Alg  string `json:"alg"`
	M    uint32 `json:"m"`
	T    uint32 `json:"t"`
	P    uint8  `json:"p"`
	Salt []byte `json:"salt"` // base64 in JSON
}

type keystoreFile struct {
	Format    int         `json:"format"`
	KDF       keystoreKDF `json:"kdf"`
	KeyID     string      `json:"key_id"`
	SealedKEK []byte      `json:"sealed_kek"` // nonce | AES-256-GCM(KEK) | tag, base64 in JSON
}

// CreateKeystore generates a random KEK and key id, seals the KEK under passphrase, and returns the file's
// bytes plus the key id (not a secret). The KEK itself is never returned. A zero kdf means DefaultKDF.
func CreateKeystore(passphrase secret.Secret, kdf KDFParams) (file []byte, keyID string, err error) {
	if kdf == (KDFParams{}) {
		kdf = DefaultKDF
	}
	if passphrase.IsEmpty() || !kdf.valid() {
		return nil, "", newErr(InvalidKey)
	}
	kek := make([]byte, DEKSize)
	defer clear(kek)
	salt := make([]byte, saltSize)
	id := make([]byte, 8)
	for _, b := range [][]byte{kek, salt, id} {
		if _, err := rand.Read(b); err != nil {
			return nil, "", &Error{Code: EntropyFailure, err: err}
		}
	}
	f := keystoreFile{Format: KeystoreFormat, KeyID: "pp-" + hex.EncodeToString(id),
		KDF: keystoreKDF{Alg: KDFArgon2id, M: kdf.M, T: kdf.T, P: kdf.P, Salt: salt}}
	aead, err := keystoreAEAD(passphrase, f.KDF)
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, nonceSize, nonceSize+DEKSize+tagSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", &Error{Code: EntropyFailure, err: err}
	}
	f.SealedKEK = aead.Seal(nonce, nonce, kek, keystoreAAD(f))
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, "", newErr(MalformedBlob)
	}
	return append(out, '\n'), f.KeyID, nil
}

// OpenKeystore unlocks file with passphrase and returns the LocalProvider over its KEK. A wrong passphrase,
// a doctored or corrupt file and an out-of-range KDF are all the same *Error{UnwrapFailed}: the result is no
// oracle for which one it was.
func OpenKeystore(file []byte, passphrase secret.Secret) (*LocalProvider, error) {
	f, ok := parseKeystore(file)
	if !ok || passphrase.IsEmpty() {
		return nil, newErr(UnwrapFailed)
	}
	aead, err := keystoreAEAD(passphrase, f.KDF)
	if err != nil {
		return nil, newErr(UnwrapFailed)
	}
	kek, err := aead.Open(nil, f.SealedKEK[:nonceSize], f.SealedKEK[nonceSize:], keystoreAAD(f))
	if err != nil {
		return nil, newErr(UnwrapFailed)
	}
	defer clear(kek)
	p, err := NewLocalProvider(f.KeyID, secret.FromBytes(kek))
	if err != nil {
		return nil, newErr(UnwrapFailed)
	}
	return p, nil
}

func parseKeystore(file []byte) (keystoreFile, bool) {
	var f keystoreFile
	if len(file) == 0 || len(file) > MaxKeystoreBytes {
		return f, false
	}
	dec := json.NewDecoder(bytes.NewReader(file))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, false
	}
	if _, err := dec.Token(); err == nil || !errors.Is(err, io.EOF) {
		return f, false // trailing data
	}
	k := KDFParams{M: f.KDF.M, T: f.KDF.T, P: f.KDF.P}
	switch {
	case f.Format != KeystoreFormat, f.KDF.Alg != KDFArgon2id, !k.valid(),
		len(f.KDF.Salt) < saltSize, len(f.KDF.Salt) > 64,
		!validKeyID(f.KeyID), len(f.SealedKEK) != nonceSize+DEKSize+tagSize:
		return f, false
	}
	return f, true
}

func validKeyID(s string) bool {
	if s == "" || len(s) > maxKeyIDBytes {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

func keystoreAEAD(passphrase secret.Secret, kdf keystoreKDF) (cipher.AEAD, error) {
	var key []byte
	passphrase.Expose(func(b []byte) { key = argon2.IDKey(b, kdf.Salt, kdf.T, kdf.M, kdf.P, DEKSize) })
	defer clear(key)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, newErr(InvalidKey)
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, newErr(InvalidKey)
	}
	return a, nil
}

// keystoreAAD binds format, KDF parameters, salt and key id to the sealed KEK: editing any of them fails
// the unlock.
func keystoreAAD(f keystoreFile) []byte {
	out := []byte("diq.keystore.v1")
	put := func(b []byte) { out = append(out, byte(len(b)>>8), byte(len(b))); out = append(out, b...) }
	put([]byte{byte(f.Format)})
	put([]byte(f.KDF.Alg))
	put([]byte{byte(f.KDF.M >> 24), byte(f.KDF.M >> 16), byte(f.KDF.M >> 8), byte(f.KDF.M),
		byte(f.KDF.T >> 24), byte(f.KDF.T >> 16), byte(f.KDF.T >> 8), byte(f.KDF.T), f.KDF.P})
	put(f.KDF.Salt)
	put([]byte(f.KeyID))
	return out
}
