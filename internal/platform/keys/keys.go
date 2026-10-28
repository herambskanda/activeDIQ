// Package keys is the key hierarchy of TM-D7 (threat-model §9.2) and DM-02: a KEK held by a
// profile's key provider wraps one data-encryption key (DEK) per tenant and version, and every
// sealed value is an AEAD blob under a DEK whose associated data binds (tenant, table, row, column,
// key version).
//
// Two operations are all a caller gets:
//
//   - Seal / Open on a DEK, with a Context naming where the value lives. A blob copied to another
//     tenant, table, row or column, or opened under another key version, fails to open with a typed
//     *Error and no plaintext. Open reports every authentication failure as the same code, so it is
//     no oracle for which component differed.
//   - WrapDEK / UnwrapDEK through a Provider. The tenant ID is the provider's encryption context
//     (KMS profiles) and is also bound into the local wrap's associated data, so a wrapped DEK moved
//     to another tenant fails to unwrap.
//
// The plaintext DEK exists only in memory (DM-02.I3): DEK holds it in a secret.Secret, so it prints
// as [REDACTED] and cannot be serialised. Persisting DM-02 rows (version, wrapped_dek, kek_ref,
// state) is the caller's migration, not this package's; callers call Seal/Open inside the tenant's
// WithTenantTx.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Error codes. They are stable; API problem types and the corpus key on them. An Error never carries
// plaintext, key material, a blob or a context value.
const (
	InvalidContext      = "InvalidContext"      // a Context component is empty, oversize or the tenant is zero
	InvalidKey          = "InvalidKey"          // a DEK is missing, wrong length or has version 0
	KeyVersionMismatch  = "KeyVersionMismatch"  // the DEK's version is not the version in the Context or blob
	MalformedBlob       = "MalformedBlob"       // not a sealed blob (too short, unknown format)
	OpenFailed          = "OpenFailed"          // authentication failed: tampering or a different Context/key
	UnwrapFailed        = "UnwrapFailed"        // a wrapped DEK did not authenticate for this tenant/version/KEK
	ProviderUnavailable = "ProviderUnavailable" // the key provider could not be reached; fail closed
	EntropyFailure      = "EntropyFailure"      // the random source failed
)

// Error is a failure with a stable code.
type Error struct {
	Code string
	err  error // underlying cause, for errors.Is/As on provider errors; never printed
}

func (e *Error) Error() string { return "keys: " + e.Code }
func (e *Error) Unwrap() error { return e.err }

func newErr(code string) error { return &Error{Code: code} }

// Code returns the stable code of err, or "" when err is not a keys error.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// DEKSize is the DEK length in bytes (AES-256).
const DEKSize = 32

const (
	maxComponent = 256 // longest table, row or column in a Context
	nonceSize    = 12
	tagSize      = 16
	blobFormat   = 1
	blobHeader   = 1 + 4 + nonceSize // format, key version, nonce
)

// DEK is one version of a tenant's data-encryption key. Version starts at 1.
type DEK struct {
	Version uint32
	key     secret.Secret
}

// NewDEK generates a fresh random DEK of the given version.
func NewDEK(version uint32) (DEK, error) {
	if version == 0 {
		return DEK{}, newErr(InvalidKey)
	}
	b := make([]byte, DEKSize)
	// secret.FromBytes copies b; clear our copy so the plaintext DEK does not linger in the heap.
	defer clear(b)
	if _, err := rand.Read(b); err != nil {
		return DEK{}, &Error{Code: EntropyFailure, err: err}
	}
	return DEK{Version: version, key: secret.FromBytes(b)}, nil
}

// DEKFromBytes builds a DEK from unwrapped key bytes. It takes ownership of b and zeroes it.
func DEKFromBytes(version uint32, b []byte) (DEK, error) {
	defer clear(b)
	if version == 0 || len(b) != DEKSize {
		return DEK{}, newErr(InvalidKey)
	}
	return DEK{Version: version, key: secret.FromBytes(b)}, nil
}

// Destroy zeroes the key material of every copy of d.
func (d *DEK) Destroy() { d.key.Destroy() }

// Context names where a sealed value lives. All components are bound into the AEAD associated data.
// Row is the row's identifier in its canonical text form (a UUID or the composite key rendered by the
// owning table's code).
type Context struct {
	Tenant tenant.ID
	Table  string
	Row    string
	Column string
	// Version is the DEK version the value is (to be) sealed under (DM-02.I2).
	Version uint32
}

func (c Context) validate() error {
	if c.Tenant.IsZero() || c.Version == 0 {
		return newErr(InvalidContext)
	}
	for _, s := range []string{c.Table, c.Row, c.Column} {
		if s == "" || len(s) > maxComponent {
			return newErr(InvalidContext)
		}
	}
	return nil
}

// aad encodes the context unambiguously: a domain tag, then each component length-prefixed.
func (c Context) aad() []byte {
	t := c.Tenant.String()
	out := make([]byte, 0, 16+len(t)+len(c.Table)+len(c.Row)+len(c.Column)+16)
	out = append(out, "diq.seal.v1"...)
	for _, s := range []string{t, c.Table, c.Row, c.Column} {
		out = append(out, byte(len(s)>>8), byte(len(s)))
		out = append(out, s...)
	}
	return append(out, byte(c.Version>>24), byte(c.Version>>16), byte(c.Version>>8), byte(c.Version))
}

func aeadFor(d DEK) (cipher.AEAD, error) {
	var a cipher.AEAD
	var bad bool
	d.key.Expose(func(b []byte) {
		if len(b) != DEKSize {
			bad = true
			return
		}
		blk, err := aes.NewCipher(b)
		if err != nil {
			bad = true
			return
		}
		a, err = cipher.NewGCM(blk)
		bad = err != nil
	})
	if bad || d.Version == 0 {
		return nil, newErr(InvalidKey)
	}
	return a, nil
}

// Seal encrypts plaintext under dek, bound to ctx. The DEK's version must equal ctx.Version. The blob
// is format || version || nonce || ciphertext||tag; it carries the key version so a re-seal job can
// pick the key (BlobVersion), but the version is also authenticated through ctx, so rewriting the
// header cannot redirect a blob.
func Seal(dek DEK, ctx Context, plaintext []byte) ([]byte, error) {
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	if dek.Version != ctx.Version {
		return nil, newErr(KeyVersionMismatch)
	}
	a, err := aeadFor(dek)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, blobHeader, blobHeader+len(plaintext)+tagSize)
	blob[0] = blobFormat
	blob[1], blob[2], blob[3], blob[4] = byte(ctx.Version>>24), byte(ctx.Version>>16), byte(ctx.Version>>8), byte(ctx.Version)
	if _, err := rand.Read(blob[5:blobHeader]); err != nil {
		return nil, &Error{Code: EntropyFailure, err: err}
	}
	return a.Seal(blob, blob[5:blobHeader], plaintext, ctx.aad()), nil
}

// BlobVersion reads the (unauthenticated) key version from a sealed blob so the caller can fetch the
// right DEK. Open still authenticates it.
func BlobVersion(blob []byte) (uint32, error) {
	if len(blob) < blobHeader+tagSize || blob[0] != blobFormat {
		return 0, newErr(MalformedBlob)
	}
	return uint32(blob[1])<<24 | uint32(blob[2])<<16 | uint32(blob[3])<<8 | uint32(blob[4]), nil
}

// Open authenticates and decrypts blob. Any difference in tenant, table, row, column or key version,
// any modified byte and any wrong key gives OpenFailed (or KeyVersionMismatch for a plain version
// disagreement the caller can fix by fetching the right DEK) and nil plaintext.
func Open(dek DEK, ctx Context, blob []byte) ([]byte, error) {
	if err := ctx.validate(); err != nil {
		return nil, err
	}
	bv, err := BlobVersion(blob)
	if err != nil {
		return nil, err
	}
	if dek.Version != ctx.Version || bv != ctx.Version {
		return nil, newErr(KeyVersionMismatch)
	}
	a, err := aeadFor(dek)
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, blob[5:blobHeader], blob[blobHeader:], ctx.aad())
	if err != nil {
		return nil, newErr(OpenFailed)
	}
	return pt, nil
}

// KEKRef names the KEK that wrapped a DEK version (DM-02 kek_ref: provider, key id). It is pinned per
// DEK version (TM-TB5-T2).
type KEKRef struct {
	Provider string
	KeyID    string
}

// WrapRequest is what a Provider is asked to wrap or unwrap. Tenant is the encryption context; Version
// is the DEK version the wrapped bytes are stored under. Providers bind both.
//
// Domain separation: a request is either a tenant wrap (Tenant set, Purpose empty) or a platform wrap
// (Purpose set, Tenant zero) for a per-install secret that belongs to no tenant, such as the API TLS key.
// Setting both or neither is invalid, and a blob wrapped in one domain never unwraps in the other: a
// provider binds Purpose into its AEAD data or KMS encryption context in place of the tenant ID.
type WrapRequest struct {
	Tenant  tenant.ID
	Purpose string
	Version uint32
}

// Valid reports whether exactly one of Tenant and Purpose is set (Version is the caller's concern).
func (r WrapRequest) Valid() bool { return r.Tenant.IsZero() != (r.Purpose == "") }

// Context is the stable string a provider binds as its encryption context: the tenant ID for tenant
// wraps, "platform:<purpose>" for platform wraps. The two namespaces cannot collide (a tenant ID is a UUID).
func (r WrapRequest) Context() string {
	if r.Purpose != "" {
		return "platform:" + r.Purpose
	}
	return r.Tenant.String()
}

// WrapPlatform wraps a per-install platform secret (no tenant) for purpose, e.g. "api-tls".
func WrapPlatform(p Provider, purpose string, version uint32, plaintext []byte) ([]byte, KEKRef, error) {
	req := WrapRequest{Purpose: purpose, Version: version}
	if !req.Valid() || version == 0 {
		return nil, KEKRef{}, newErr(InvalidContext)
	}
	wrapped, ref, err := p.Wrap(req, plaintext)
	if err != nil {
		return nil, KEKRef{}, providerErr(err, ProviderUnavailable)
	}
	return wrapped, ref, nil
}

// UnwrapPlatform recovers a platform secret wrapped by WrapPlatform. The caller zeroes the result.
func UnwrapPlatform(p Provider, purpose string, version uint32, ref KEKRef, wrapped []byte) ([]byte, error) {
	req := WrapRequest{Purpose: purpose, Version: version}
	if !req.Valid() || version == 0 {
		return nil, newErr(InvalidContext)
	}
	b, err := p.Unwrap(req, ref, wrapped)
	if err != nil {
		clear(b)
		return nil, providerErr(err, UnwrapFailed)
	}
	return b, nil
}

// Provider is the key-provider adapter (EP-12): the one place the KEK lives. KMS-style providers pass
// Tenant as the provider's encryption context; local providers bind it into the AEAD associated data.
// Implementations must fail closed, return ProviderUnavailable for transport/outage errors (not
// UnwrapFailed, which signals a bad blob or context), and never fall back to plaintext.
type Provider interface {
	// Ref identifies the KEK currently used for new wraps.
	Ref() KEKRef
	// Wrap encrypts a plaintext DEK. The caller owns and zeroes plaintext.
	Wrap(req WrapRequest, plaintext []byte) (wrapped []byte, ref KEKRef, err error)
	// Unwrap decrypts a wrapped DEK under the KEK named by ref, bound to req.
	Unwrap(req WrapRequest, ref KEKRef, wrapped []byte) ([]byte, error)
}

// WrapDEK wraps dek for tenant t through p and returns the bytes to store with the KEK reference.
func WrapDEK(p Provider, t tenant.ID, dek DEK) ([]byte, KEKRef, error) {
	if t.IsZero() {
		return nil, KEKRef{}, newErr(InvalidContext)
	}
	var wrapped []byte
	var ref KEKRef
	var err error
	dek.key.Expose(func(b []byte) {
		if len(b) != DEKSize || dek.Version == 0 {
			err = newErr(InvalidKey)
			return
		}
		wrapped, ref, err = p.Wrap(WrapRequest{Tenant: t, Version: dek.Version}, b)
	})
	if err != nil {
		return nil, KEKRef{}, providerErr(err, ProviderUnavailable)
	}
	return wrapped, ref, nil
}

// UnwrapDEK recovers the DEK of version v for tenant t. A wrapped DEK taken from another tenant or
// version fails with UnwrapFailed and yields no key.
func UnwrapDEK(p Provider, t tenant.ID, v uint32, ref KEKRef, wrapped []byte) (DEK, error) {
	if t.IsZero() || v == 0 {
		return DEK{}, newErr(InvalidContext)
	}
	b, err := p.Unwrap(WrapRequest{Tenant: t, Version: v}, ref, wrapped)
	if err != nil {
		clear(b)
		countUnwrap(t, OutcomeFailure)
		return DEK{}, providerErr(err, UnwrapFailed)
	}
	d, derr := DEKFromBytes(v, b)
	if derr != nil {
		countUnwrap(t, OutcomeFailure)
		return DEK{}, newErr(UnwrapFailed)
	}
	countUnwrap(t, OutcomeSuccess)
	return d, nil
}

// providerErr keeps a provider's own *Error code and wraps anything else under def. The cause stays
// reachable with errors.Is/As for operators but is not part of Error().
func providerErr(err error, def string) error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Code: def, err: err}
}

// LocalProvider wraps DEKs with an AES-256-GCM KEK held in memory: the passphrase-keystore and
// test-profile adapter. Tenant and DEK version are bound into the associated data, as are the KEK
// reference, so a wrapped DEK substituted across tenants, versions or KEKs fails (TM-TB5-T2).
type LocalProvider struct {
	ref  KEKRef
	aead cipher.AEAD
}

// NewLocalProvider builds a provider from a 32-byte KEK. keyID names it in KEKRef.
func NewLocalProvider(keyID string, kek secret.Secret) (*LocalProvider, error) {
	var a cipher.AEAD
	bad := true
	kek.Expose(func(b []byte) {
		if len(b) != DEKSize {
			return
		}
		blk, err := aes.NewCipher(b)
		if err != nil {
			return
		}
		a, err = cipher.NewGCM(blk)
		bad = err != nil
	})
	if bad || keyID == "" {
		return nil, newErr(InvalidKey)
	}
	return &LocalProvider{ref: KEKRef{Provider: "local", KeyID: keyID}, aead: a}, nil
}

func (p *LocalProvider) Ref() KEKRef { return p.ref }

func wrapAAD(req WrapRequest, ref KEKRef) []byte {
	out := []byte("diq.wrap.v1") // tenant wraps keep their original AAD so stored blobs still open
	ctx := req.Tenant.String()
	if req.Purpose != "" {
		out = []byte("diq.wrap.platform.v1")
		ctx = req.Purpose
	}
	for _, s := range []string{ctx, ref.Provider, ref.KeyID} {
		out = append(out, byte(len(s)>>8), byte(len(s)))
		out = append(out, s...)
	}
	return append(out, byte(req.Version>>24), byte(req.Version>>16), byte(req.Version>>8), byte(req.Version))
}

func (p *LocalProvider) Wrap(req WrapRequest, plaintext []byte) ([]byte, KEKRef, error) {
	if !req.Valid() {
		return nil, KEKRef{}, newErr(InvalidContext)
	}
	nonce := make([]byte, nonceSize, nonceSize+len(plaintext)+tagSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, KEKRef{}, &Error{Code: EntropyFailure, err: err}
	}
	return p.aead.Seal(nonce, nonce, plaintext, wrapAAD(req, p.ref)), p.ref, nil
}

func (p *LocalProvider) Unwrap(req WrapRequest, ref KEKRef, wrapped []byte) ([]byte, error) {
	if !req.Valid() {
		return nil, newErr(InvalidContext)
	}
	if ref != p.ref {
		return nil, fmt.Errorf("kek %q not held by this provider: %w", ref.KeyID, newErr(UnwrapFailed))
	}
	if len(wrapped) < nonceSize+tagSize {
		return nil, newErr(UnwrapFailed)
	}
	pt, err := p.aead.Open(nil, wrapped[:nonceSize], wrapped[nonceSize:], wrapAAD(req, ref))
	if err != nil {
		return nil, newErr(UnwrapFailed)
	}
	return pt, nil
}
