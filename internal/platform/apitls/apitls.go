// Package apitls makes the API listener's TLS identity: a per-install self-signed certificate that is
// generated on first boot, kept beside the install's state and reused afterwards, with its SHA-256
// fingerprint exposed so the admin can pin it on first connect (TM-TB1-T2, TM-F-HOST).
//
// There is no plaintext fallback. With a directory the certificate and key persist across restarts;
// with none (loopback development and tests only) the identity lives in memory for one process.
package apitls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// File names inside the identity directory.
const (
	CertFile = "api-cert.pem"
	KeyFile  = "api-key.pem"
)

const (
	validity    = 2 * 365 * 24 * time.Hour
	renewWithin = 30 * 24 * time.Hour
)

// Identity is a loaded or generated certificate.
type Identity struct {
	Certificate tls.Certificate
	// Fingerprint is the colon-separated upper-case hex SHA-256 of the DER certificate, the form
	// browsers and openssl print.
	Fingerprint string
}

// TLSConfig returns the server configuration: TLS 1.2 minimum, the identity as the only certificate.
func (i Identity) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{i.Certificate},
		NextProtos:   []string{"h2", "http/1.1"},
	}
}

// Fingerprint returns the SHA-256 fingerprint of a DER certificate.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// LoadOrGenerate returns the install's identity. dir empty means an in-memory identity. Otherwise
// the certificate and key are read from dir. A new pair is generated only when the certificate file
// does not exist (first boot, or a crash between the key and certificate writes) or the pair is
// within 30 days of expiry, which is renewed with a WARN log of both fingerprints. Anything else
// wrong with the directory or files (ownership, permissions, symlinks, unreadable, corrupt,
// mismatched pair) fails with an error naming the file and leaves it untouched: the server's
// identity never changes silently. addr is the listen address; its host, "localhost", the loopback
// addresses and the machine's host name become SANs. now is injected for tests.
func LoadOrGenerate(dir, addr string, now time.Time) (Identity, error) {
	var old string
	if dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return Identity{}, fmt.Errorf("apitls: identity directory: %w", err)
		}
		if err := checkDir(dir); err != nil {
			return Identity{}, err
		}
		id, renew, err := load(dir, now)
		if err != nil {
			return Identity{}, err
		}
		if !renew && id.Fingerprint != "" {
			return id, nil
		}
		old = id.Fingerprint
	}
	certPEM, keyPEM, err := generate(addr, now)
	if err != nil {
		return Identity{}, err
	}
	if dir != "" {
		if err := store(dir, certPEM, keyPEM); err != nil {
			return Identity{}, err
		}
	}
	id, err := parse(certPEM, keyPEM)
	if err == nil && old != "" {
		slog.Warn("apitls: API certificate renewed; admins who pinned the old fingerprint must re-pin",
			"old_tls_cert_sha256", old, "new_tls_cert_sha256", id.Fingerprint)
	}
	return id, err
}

func parse(certPEM, keyPEM []byte) (Identity, error) {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Identity{}, fmt.Errorf("apitls: certificate and key: %w", err)
	}
	return Identity{Certificate: c, Fingerprint: Fingerprint(c.Certificate[0])}, nil
}

// load reads the persisted pair. A missing certificate file is not an error: it returns the zero
// Identity and renew=false, and the caller generates. renew=true means a valid pair near expiry.
func load(dir string, now time.Time) (id Identity, renew bool, err error) {
	certPath, keyPath := filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)
	if _, err := os.Lstat(certPath); errors.Is(err, fs.ErrNotExist) {
		return Identity{}, false, nil
	}
	if err := checkFile(certPath, false); err != nil {
		return Identity{}, false, err
	}
	if err := checkFile(keyPath, true); err != nil {
		return Identity{}, false, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return Identity{}, false, fmt.Errorf("apitls: read %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return Identity{}, false, fmt.Errorf("apitls: read %s: %w", keyPath, err)
	}
	id, err = parse(certPEM, keyPEM)
	if err != nil {
		return Identity{}, false, fmt.Errorf("apitls: %s and %s are not a valid pair: %w", certPath, keyPath, errors.Unwrap(err))
	}
	leaf, err := x509.ParseCertificate(id.Certificate.Certificate[0])
	if err != nil {
		return Identity{}, false, fmt.Errorf("apitls: parse %s: %w", certPath, err)
	}
	return id, now.Add(renewWithin).After(leaf.NotAfter), nil
}

func generate(addr string, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("apitls: key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, fmt.Errorf("apitls: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"activeDIQ"}, CommonName: "activeDIQ API (per-install)"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	tmpl.DNSNames, tmpl.IPAddresses = sans(addr)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("apitls: certificate: %w", err)
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("apitls: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), nil
}

// sans collects the names the certificate answers to, de-duplicated.
func sans(addr string) (dns []string, ips []net.IP) {
	seenDNS := map[string]bool{}
	seenIP := map[netip.Addr]bool{}
	addName := func(h string) {
		if h == "" {
			return
		}
		if a, err := netip.ParseAddr(h); err == nil {
			if a.IsUnspecified() || seenIP[a] {
				return
			}
			seenIP[a] = true
			ips = append(ips, net.IP(a.AsSlice()))
			return
		}
		if !seenDNS[h] {
			seenDNS[h] = true
			dns = append(dns, h)
		}
	}
	addName("localhost")
	addName("127.0.0.1")
	addName("::1")
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addName(host)
	}
	if h, err := os.Hostname(); err == nil {
		addName(h)
	}
	return dns, ips
}

func store(dir string, certPEM, keyPEM []byte) error {
	// Key first: a crash between the two leaves a key with no certificate, which regenerates.
	if err := writeAtomic(filepath.Join(dir, KeyFile), keyPEM, 0o600); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, CertFile), certPEM, 0o644)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("apitls: write: %w", err)
	}
	tmp := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("apitls: write: %w", err)
	}
	if err := f.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return errors.Join(errors.New("apitls: write"), err)
	}
	return nil
}
