// Package pin verifies the SSPR server by SPKI hash only. System roots, hostnames and
// chain building are deliberately not consulted: the only trust anchor is the pin set
// installed by the MSI/GPO (spec section 5). TLS 1.3 only.
package pin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

var ErrUnpinned = errors.New("pin: server certificate matches no pinned key")
var ErrNoPins = errors.New("pin: empty pin set (provider must be inert)")

type Hash [sha256.Size]byte

// SPKIHash is SHA-256 over the DER SubjectPublicKeyInfo.
func SPKIHash(c *x509.Certificate) Hash { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

// Config returns a TLS client config that accepts a server only if some certificate it
// presents (leaf or any intermediate) has an SPKI hash in pins. Pinning an intermediate
// lets the server rotate leaves; pin sets carry a backup key (spec section 5).
func Config(pins []Hash) (*tls.Config, error) {
	if len(pins) == 0 {
		return nil, ErrNoPins
	}
	set := make(map[Hash]struct{}, len(pins))
	for _, p := range pins {
		set[p] = struct{}{}
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// InsecureSkipVerify disables the default verifier ONLY so that VerifyPeerCertificate
		// is the sole decision; it is not "no verification" (pin check below always runs).
		InsecureSkipVerify: true, //nolint:gosec // pin verification replaces chain verification
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			for _, der := range raw {
				c, err := x509.ParseCertificate(der)
				if err != nil {
					continue
				}
				if _, ok := set[SPKIHash(c)]; ok {
					return nil
				}
			}
			return ErrUnpinned
		},
	}, nil
}
