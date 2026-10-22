package unicodepwd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
)

// Link is what the connector exposes about one live directory connection. Generation changes on
// every reconnect; ConnectionState reports the TLS state (false when the connection is not TLS:
// plain 389, or StartTLS not completed).
type Link interface {
	Generation() uint64
	ConnectionState() (tls.ConnectionState, bool)
}

// SecureConn is the proof that the connection carrying a unicodePwd value is encrypted and
// authenticated. It can be obtained only from Acquire, from LDAPS or completed StartTLS whose chain
// was verified to the configured trust anchors and whose certificate names the DC's FQDN. The zero
// value proves nothing. It is bound to one connection generation (PW-17).
//
// SASL GSSAPI with sealing is not a source until spike old T-0023 proves go-ldap negotiates the
// confidentiality layer ([UNVERIFIED], safe-primitives §5.6).
type SecureConn struct {
	link Link
	gen  uint64
	fqdn string
}

// Acquire derives a SecureConn from link by re-reading its TLS state: TLS 1.2 or later, handshake
// complete, a verified chain, and the leaf naming fqdn (the inventory host). A plain connection is
// EncryptionRequired; anything else that fails verification is TLSVerificationFailed. There is no
// fallback to a weaker transport, so there is nothing to retry on.
func Acquire(link Link, fqdn string) (SecureConn, error) {
	if link == nil {
		return SecureConn{}, codec.New(EncryptionRequired)
	}
	c := SecureConn{link: link, gen: link.Generation(), fqdn: fqdn}
	if err := c.verifyState(); err != nil {
		return SecureConn{}, err
	}
	return c, nil
}

// Verify re-checks the connection at send time: same generation, same verified TLS state. A zero
// SecureConn is EncryptionRequired; a reconnect since Acquire is SecureConnStale.
func (c SecureConn) Verify() error {
	if c.link == nil {
		return codec.New(EncryptionRequired)
	}
	if c.link.Generation() != c.gen {
		return codec.New(SecureConnStale)
	}
	return c.verifyState()
}

func (c SecureConn) verifyState() error {
	st, ok := c.link.ConnectionState()
	if !ok {
		return codec.New(EncryptionRequired)
	}
	if !st.HandshakeComplete || st.Version < tls.VersionTLS12 || len(st.VerifiedChains) == 0 || len(st.PeerCertificates) == 0 {
		return codec.New(TLSVerificationFailed)
	}
	if c.fqdn == "" || st.PeerCertificates[0].VerifyHostname(c.fqdn) != nil {
		return codec.New(TLSVerificationFailed)
	}
	return nil
}

// ClassifyHandshake maps a failed LDAPS or StartTLS handshake to TLSVerificationFailed when the
// peer's certificate was refused (unknown authority, wrong name, expired). Other errors (network)
// pass through. Neither is a reason to retry on plain 389 or with verification off (PW-18).
func ClassifyHandshake(err error) error {
	if err == nil {
		return nil
	}
	var cve *tls.CertificateVerificationError
	var hn x509.HostnameError
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	if errors.As(err, &cve) || errors.As(err, &hn) || errors.As(err, &ua) || errors.As(err, &ci) {
		return codec.New(TLSVerificationFailed)
	}
	return err
}
