package dial

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

// Limits of a CA bundle (TM-D24 rule D3).
const (
	MaxBundleBytes = 64 << 10
	MaxBundleCerts = 8
)

// Errors. None carries input bytes.
var (
	// ErrPin: the pin is not "sha256:" followed by 64 lower-case hex digits.
	ErrPin = errors.New("dial: malformed CA pin")
	// ErrBundle: the CA bundle violates rule D3 (or lacks the pinned CA). Nothing was persisted.
	ErrBundle = errors.New("dial: CA bundle is not acceptable")
	// ErrUntrustedServer: the server did not present the pinned CA, or its chain does not verify
	// against it. The token was not sent.
	ErrUntrustedServer = errors.New("dial: server is not signed by the pinned installation CA")
)

// Pin is the SHA-256 of an installation CA's SubjectPublicKeyInfo.
type Pin [sha256.Size]byte

const pinPrefix = "sha256:"

// ParsePin reads the "sha256:<hex>" form carried by the enrollment material.
func ParsePin(s string) (Pin, error) {
	var p Pin
	h, ok := cutPrefix(s, pinPrefix)
	if !ok || len(h) != 2*len(p) {
		return p, ErrPin
	}
	for i := 0; i < len(h); i++ {
		if c := h[i]; !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return p, ErrPin
		}
	}
	if _, err := hex.Decode(p[:], []byte(h)); err != nil {
		return p, ErrPin
	}
	return p, nil
}

func cutPrefix(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
		return "", false
	}
	return s[len(prefix):], true
}

// String returns the "sha256:<hex>" form.
func (p Pin) String() string { return pinPrefix + hex.EncodeToString(p[:]) }

// Matches reports whether c's SubjectPublicKeyInfo is the pinned one.
func (p Pin) Matches(c *x509.Certificate) bool {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return subtle.ConstantTimeCompare(sum[:], p[:]) == 1
}

func isCA(c *x509.Certificate) bool {
	return c.BasicConstraintsValid && c.IsCA && c.KeyUsage&x509.KeyUsageCertSign != 0
}

var pemBegin = []byte("-----BEGIN ")

// ParseBundle reads ca_bundle_pem strictly (TM-D24 rule D3): CERTIFICATE blocks only, no headers,
// nothing but whitespace around or between them, 1 to MaxBundleCerts of them, at most MaxBundleBytes
// in all, each a CA, one matching the pin. x509.CertPool.AppendCertsFromPEM is deliberately not used
// on the raw bytes: it silently skips blocks it does not like.
func ParseBundle(bundle []byte, pin Pin) ([]*x509.Certificate, error) {
	if len(bundle) == 0 || len(bundle) > MaxBundleBytes {
		return nil, ErrBundle
	}
	var certs []*x509.Certificate
	pinned := false
	rest := bytes.TrimSpace(bundle)
	for len(rest) > 0 {
		// pem.Decode skips any text before the next BEGIN line, so require the block to start here.
		if !bytes.HasPrefix(rest, pemBegin) {
			return nil, ErrBundle
		}
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil || blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 || len(certs) == MaxBundleCerts {
			return nil, ErrBundle
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil || !isCA(c) {
			return nil, ErrBundle
		}
		pinned = pinned || pin.Matches(c)
		certs = append(certs, c)
		rest = bytes.TrimSpace(rest)
	}
	if len(certs) == 0 || !pinned {
		return nil, ErrBundle
	}
	return certs, nil
}

// Pool returns a non-nil pool holding exactly certs.
func Pool(certs []*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func pinOf(c *x509.Certificate) Pin { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }
