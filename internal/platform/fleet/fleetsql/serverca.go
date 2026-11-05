package fleetsql

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
)

// The installation server CA (ADR-0008 items 1, 3, 6, 7 and security obligations 1 to 3 and 7). One CA
// for the whole installation signs ServerAuth leaves for the gateway and nothing else; component
// identities stay under the per-tenant CAs (ca.go). Its pin is the one pin every tenant's enrolment
// material carries (ServerPin). Its private key is sealed under the installation DEK and is unsealed
// only inside SignServerLeaf (and at creation, when it is generated in memory).

var _ = tablekind.Declare(tablekind.Table{Name: "public.fleet_server_ca", Entity: "DM-12", Kind: tablekind.Platform, Sealed: []string{"sealed_key"}})

const (
	serverCATable  = "fleet_server_ca"
	serverCAColumn = "sealed_key"
	// serverCAReason is the consumer the installation-key audit event records.
	serverCAReason = "fleet.server_ca"

	// ServerLeafTTL is the lifetime of a gateway ServerAuth leaf (ADR-0008 item 6); renewal at two thirds of it.
	ServerLeafTTL = 30 * 24 * time.Hour
	// serverCAForbidWindow: no issuance this close to the CA's own not_after (obligation 3).
	serverCAForbidWindow = 90 * 24 * time.Hour
	// serverCAAlertWindow: an alert is raised this close to the CA's not_after (obligation 3).
	serverCAAlertWindow = 365 * 24 * time.Hour
	maxServerNames      = 8
	maxDNSNameBytes     = 253
	// maxServerLeavesPerHour caps issuance per node (obligation 2): renewal and restarts need a handful.
	maxServerLeavesPerHour = 12
)

// Errors of the server CA. None carries key material, stored bytes or SQL.
var (
	// ErrServerNames: the requested names are not exactly names of the configured fleet endpoints.
	ErrServerNames = errors.New("fleetsql: server leaf names are not acceptable")
	// ErrServerCAUnavailable: the server CA is missing, inactive, unreadable or failed validation.
	ErrServerCAUnavailable = errors.New("fleetsql: the server CA is unavailable")
	// ErrServerCAExpiring: the server CA is too close to its own expiry to sign (obligation 3).
	ErrServerCAExpiring = errors.New("fleetsql: the server CA is too close to expiry to issue")
	// ErrServerLeafRate: this node has issued its hourly cap of server leaves.
	ErrServerLeafRate = errors.New("fleetsql: server leaf issuance rate cap reached")
	// ErrServerLeafInvalid: the produced leaf did not pass the post-issuance checks; nothing is returned.
	ErrServerLeafInvalid = errors.New("fleetsql: issued server leaf failed verification")
)

// Server CA alert kinds.
const (
	AlertServerCAMaterial AlertKind = "fleet.server_ca.material_invalid"
	AlertServerCAExpiring AlertKind = "fleet.server_ca.expiring"
)

// InstallationKeySource gives the installation DEK (*keys.InstallationKeys). The caller destroys it.
type InstallationKeySource interface {
	DEK(ctx context.Context, tx store.Tx, version uint32, reason string) (keys.DEK, error)
}

// ServerCertEvent is what is recorded for every server leaf issued (`fleet.server_cert.issued`). There is
// no key material in it.
type ServerCertEvent struct {
	Kind      string // "fleet.server_cert.issued"
	At        time.Time
	Names     []string
	Serial    string // hex
	NotAfter  time.Time
	CASPKIPin string
}

// ServerCertAuditor records server leaf issuance in the installation audit trail. There is no tenant to
// chain it in, so the composition root adapts the platform audit sink. A failed record fails the issuance:
// there is no unaudited server certificate.
type ServerCertAuditor interface {
	RecordServerCert(ctx context.Context, ev ServerCertEvent) error
}

// serverCA is a loaded, validated server CA row.
type serverCA struct {
	id        string
	active    bool
	cert      *x509.Certificate
	sealedKey []byte
	version   uint32
}

// validServerCACert is the shape ADR-0008 item 1 and obligation 1 demand: a CA, MaxPathLen 0, CertSign
// only, ServerAuth as the only EKU, ECDSA P-384.
func validServerCACert(c *x509.Certificate) bool {
	if !c.BasicConstraintsValid || !c.IsCA || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		return false
	}
	if c.KeyUsage != x509.KeyUsageCertSign {
		return false
	}
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(c.UnknownExtKeyUsage) != 0 {
		return false
	}
	k, ok := c.PublicKey.(*ecdsa.PublicKey)
	return ok && k.Curve == elliptic.P384()
}

// loadServerCAs reads and validates every active and retired server CA row, active first. A row that does
// not validate fails the whole read, as for tenant CAs.
func (e *Enroller) loadServerCAs(ctx context.Context, tx store.Tx) ([]serverCA, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, cert_der, spki_sha256, sealed_key, key_version, state
		FROM public.fleet_server_ca WHERE state IN ('active', 'retired') ORDER BY (state = 'active') DESC, created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("fleetsql: read server CA: %w", err)
	}
	defer rows.Close()
	var out []serverCA
	bad := false
	for rows.Next() {
		var (
			c       serverCA
			der, h  []byte
			version int32
			state   string
		)
		if err := rows.Scan(&c.id, &der, &h, &c.sealedKey, &version, &state); err != nil {
			return nil, fmt.Errorf("fleetsql: read server CA: %w", err)
		}
		cert, exposure, perr := parseStoredServerCert(der)
		if exposure {
			e.Alerts.Raise(ctx, Alert{Kind: AlertCAKeyExposure})
		}
		if perr != nil {
			bad = true
			continue
		}
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if len(h) != 32 || string(h) != string(sum[:]) || version <= 0 || (state == "active") != (len(c.sealedKey) > 0) {
			bad = true
			continue
		}
		c.cert, c.version, c.active = cert, uint32(version), state == "active"
		out = append(out, c)
		if len(out) > maxBundleCerts {
			bad = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("fleetsql: read server CA: %w", err)
	}
	if bad {
		e.Alerts.Raise(ctx, Alert{Kind: AlertServerCAMaterial})
		return nil, errCAIntegrity
	}
	return out, nil
}

func parseStoredServerCert(der []byte) (c *x509.Certificate, exposure bool, err error) {
	if len(der) == 0 || len(der) > maxBundleBytes {
		return nil, false, errCAIntegrity
	}
	if hasPEMMarker(der) {
		return nil, containsPrivateKeyMarker(der), errCAIntegrity
	}
	c, err = x509.ParseCertificate(der)
	if err != nil || !validServerCACert(c) {
		return nil, false, errCAIntegrity
	}
	return c, false, nil
}

func serverCAContext(rowID string, version uint32) keys.InstallationContext {
	return keys.InstallationContext{Table: serverCATable, Row: rowID, Column: serverCAColumn, Version: version}
}

func (e *Enroller) readyServer() error {
	if e == nil || e.InstallationKeys == nil || e.Alerts == nil || e.ServerAudit == nil || e.Enrollment == nil {
		return ErrNotConfigured
	}
	return e.Enrollment.ready()
}

// ensureServerCA returns the active server CA, creating the installation's first one when there is none.
// Creation is idempotent under concurrency: the partial unique index admits one active CA, the loser re-reads.
func (e *Enroller) ensureServerCA(ctx context.Context, tx store.Tx) (serverCA, error) {
	cas, err := e.loadServerCAs(ctx, tx)
	if err != nil {
		return serverCA{}, err
	}
	if len(cas) == 0 {
		if _, err := createServerCA(ctx, tx, e.InstallationKeys, e.now()); err != nil {
			return serverCA{}, err
		}
		if cas, err = e.loadServerCAs(ctx, tx); err != nil {
			return serverCA{}, err
		}
	}
	if len(cas) == 0 || !cas[0].active {
		e.Alerts.Raise(ctx, Alert{Kind: AlertServerCAMaterial})
		return serverCA{}, errCAIntegrity
	}
	return cas[0], nil
}

// createServerCA generates the server CA key and certificate, seals the key under the installation DEK
// and inserts the row as the active server CA. ON CONFLICT DO NOTHING: a concurrent creator wins.
func createServerCA(ctx context.Context, tx store.Tx, ks InstallationKeySource, now time.Time) (*x509.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("fleetsql: generate server CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "activeDIQ fleet server CA", Organization: []string{"activeDIQ"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("fleetsql: create server CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil || !validServerCACert(cert) {
		return nil, fmt.Errorf("fleetsql: create server CA certificate: %w", errCAIntegrity)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("fleetsql: encode server CA key: %w", err)
	}
	defer clear(pkcs8)
	dek, err := ks.DEK(ctx, tx, 0, serverCAReason)
	if err != nil {
		return nil, fmt.Errorf("%w: installation data key: %w", ErrServerCAUnavailable, err)
	}
	defer dek.Destroy()
	var rowID string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&rowID); err != nil {
		return nil, fmt.Errorf("fleetsql: create server CA: %w", err)
	}
	sealed, err := keys.SealInstallation(dek, serverCAContext(rowID, dek.Version), pkcs8)
	if err != nil {
		return nil, fmt.Errorf("fleetsql: seal server CA key: %w", err)
	}
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if _, err := tx.Exec(ctx, `INSERT INTO public.fleet_server_ca (id, cert_der, spki_sha256, sealed_key, key_version, not_after)
		VALUES ($1::uuid, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`, rowID, der, pin[:], sealed, int32(dek.Version), cert.NotAfter); err != nil {
		return nil, fmt.Errorf("fleetsql: store server CA: %w", err)
	}
	return cert, nil
}

// serverSigner unseals the server CA's private key for one signature. Only SignServerLeaf may call it
// (fitness-fleet-ca-scope FCS-1). The plaintext PKCS#8 is zeroised before it returns; the caller drops
// the returned key straight after signing and never stores it. Every unseal is audited by the
// installation key source.
func (e *Enroller) serverSigner(ctx context.Context, tx store.Tx, c serverCA) (crypto.Signer, error) {
	version, err := keys.BlobVersion(c.sealedKey)
	if err != nil || version != c.version {
		return nil, ErrServerCAUnavailable
	}
	dek, err := e.InstallationKeys.DEK(ctx, tx, version, serverCAReason)
	if err != nil {
		return nil, fmt.Errorf("%w: installation data key: %w", ErrServerCAUnavailable, err)
	}
	defer dek.Destroy()
	pt, err := keys.OpenInstallation(dek, serverCAContext(c.id, version), c.sealedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrServerCAUnavailable, err)
	}
	defer clear(pt)
	k, err := x509.ParsePKCS8PrivateKey(pt)
	if err != nil {
		return nil, ErrServerCAUnavailable
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, ErrServerCAUnavailable
	}
	// The unsealed key must be the key the certificate names, or the row was tampered with.
	if !samePublic(s.Public(), c.cert.PublicKey) {
		e.Alerts.Raise(ctx, Alert{Kind: AlertServerCAMaterial})
		return nil, errCAIntegrity
	}
	return s, nil
}

// ServerPin returns the "sha256:<hex>" pin of the installation server CA's public key (TM-D24 D1): one
// value for the whole installation, the same for every tenant's enrolment material. It creates the CA the
// first time. The table is registered-global, so any transaction may call it.
func (e *Enroller) ServerPin(ctx context.Context, tx store.Tx) (string, error) {
	if err := e.readyServer(); err != nil {
		return "", err
	}
	c, err := e.ensureServerCA(ctx, tx)
	if err != nil {
		return "", serverPublicErr(err)
	}
	return PinOf(c.cert), nil
}

func serverPublicErr(err error) error {
	if errors.Is(err, errCAIntegrity) {
		return ErrServerCAUnavailable
	}
	return err
}

// allowedServerNames normalises the configured fleet endpoint hosts into the allow-list.
func (e *Enroller) allowedServerNames() map[string]bool {
	out := map[string]bool{}
	for _, ep := range e.Endpoints {
		if n, err := normaliseServerName(ep.Host); err == nil {
			out[n] = true
		}
	}
	return out
}

// normaliseServerName lowercases, IDNA-converts (to the A-label form) and validates one DNS name or IP
// address. A wildcard, an empty or trailing-dot name, an over-long name, and a loopback, link-local,
// unspecified or multicast address are refused (ADR-0008 item 7, obligation 3).
func normaliseServerName(s string) (string, error) {
	if s == "" || strings.TrimSpace(s) != s {
		return "", ErrServerNames
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() {
			return "", ErrServerNames
		}
		return a.Unmap().String(), nil
	}
	if strings.ContainsAny(s, "*:/@ \t\r\n\x00") || strings.HasSuffix(s, ".") || strings.HasPrefix(s, ".") {
		return "", ErrServerNames
	}
	n, err := idna.Lookup.ToASCII(strings.ToLower(s))
	if err != nil || n == "" || len(n) > maxDNSNameBytes {
		return "", ErrServerNames
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", ErrServerNames
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", ErrServerNames
			}
		}
	}
	return n, nil
}

// serverLeafLimiter caps issuance per node per hour.
type serverLeafLimiter struct {
	mu    sync.Mutex
	times []time.Time
}

func (l *serverLeafLimiter) take(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.times[:0]
	for _, t := range l.times {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	l.times = kept
	if len(l.times) >= maxServerLeavesPerHour {
		return false
	}
	l.times = append(l.times, now)
	return true
}

// SignServerLeaf mints the gateway's ServerAuth certificate (ADR-0008 item 7), the only way one is made.
// names must each be one of the configured fleet endpoints. The leaf key is generated here (ECDSA P-256),
// lives in the returned tls.Certificate only, and is never persisted. No RPC reaches this method and it
// takes no principal and no key or CSR: the composer calls it at start and the renewal timer after that.
// The returned certificate chain is exactly [leaf, server CA] (ADR-0008 item 4).
func (e *Enroller) SignServerLeaf(ctx context.Context, names []string) (tls.Certificate, error) {
	if err := e.readyServer(); err != nil {
		return tls.Certificate{}, err
	}
	sans, err := e.checkServerNames(names)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := e.now()
	if !e.serverLimiter.take(now) {
		return tls.Certificate{}, ErrServerLeafRate
	}
	var out tls.Certificate
	err = e.Enrollment.DB.WithPlatform(ctx, "fleet: sign the gateway's server leaf with the installation server CA", func(ctx context.Context, tx store.Tx) error {
		c, err := e.ensureServerCA(ctx, tx)
		if err != nil {
			return err
		}
		if now.Add(serverCAForbidWindow).After(c.cert.NotAfter) {
			e.Alerts.Raise(ctx, Alert{Kind: AlertServerCAExpiring})
			return ErrServerCAExpiring
		}
		if now.Add(serverCAAlertWindow).After(c.cert.NotAfter) {
			e.Alerts.Raise(ctx, Alert{Kind: AlertServerCAExpiring})
		}
		signer, err := e.serverSigner(ctx, tx, c)
		if err != nil {
			return err
		}
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("fleetsql: generate server leaf key: %w", err)
		}
		serial, err := newSerial()
		if err != nil {
			return err
		}
		notAfter := now.Add(ServerLeafTTL)
		if notAfter.After(c.cert.NotAfter) {
			notAfter = c.cert.NotAfter
		}
		ski := sha256.Sum256(elliptic.Marshal(elliptic.P256(), leafKey.X, leafKey.Y)) //nolint:staticcheck // SKI input only
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			NotBefore:             now.Add(-clockSkew),
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  false,
			DNSNames:              sans.dns,
			IPAddresses:           sans.ips,
			SubjectKeyId:          ski[:20],
			SignatureAlgorithm:    x509.ECDSAWithSHA384,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &leafKey.PublicKey, signer)
		if err != nil {
			return fmt.Errorf("fleetsql: sign server leaf: %w", err)
		}
		leaf, err := verifyServerLeaf(der, c.cert, leafKey, sans, now)
		if err != nil {
			return err
		}
		if err := e.ServerAudit.RecordServerCert(ctx, ServerCertEvent{Kind: "fleet.server_cert.issued", At: now,
			Names: sans.all, Serial: leaf.SerialNumber.Text(16), NotAfter: leaf.NotAfter, CASPKIPin: PinOf(c.cert)}); err != nil {
			return fmt.Errorf("fleetsql: audit server leaf: %w", err)
		}
		out = tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: leafKey, Leaf: leaf}
		return nil
	})
	if err != nil {
		return tls.Certificate{}, serverPublicErr(err)
	}
	return out, nil
}

type serverSANs struct {
	all []string
	dns []string
	ips []net.IP
}

// checkServerNames validates names against the configured endpoint set.
func (e *Enroller) checkServerNames(names []string) (serverSANs, error) {
	var s serverSANs
	if len(names) == 0 || len(names) > maxServerNames {
		return s, ErrServerNames
	}
	allowed := e.allowedServerNames()
	seen := map[string]bool{}
	for _, raw := range names {
		n, err := normaliseServerName(raw)
		if err != nil || !allowed[n] {
			return serverSANs{}, ErrServerNames
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		s.all = append(s.all, n)
		if a, err := netip.ParseAddr(n); err == nil {
			s.ips = append(s.ips, a.AsSlice())
		} else {
			s.dns = append(s.dns, n)
		}
	}
	return s, nil
}

// verifyServerLeaf is the post-issuance check of ADR-0008 item 7: the leaf parses back, has the exact
// shape, verifies to the CA for ServerAuth for every requested name, and certifies the generated key.
func verifyServerLeaf(der []byte, ca *x509.Certificate, key *ecdsa.PrivateKey, sans serverSANs, now time.Time) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrServerLeafInvalid
	}
	switch {
	case leaf.IsCA, len(leaf.URIs) != 0, len(leaf.EmailAddresses) != 0, leaf.Subject.String() != "",
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0,
		leaf.KeyUsage != x509.KeyUsageDigitalSignature,
		leaf.SignatureAlgorithm != x509.ECDSAWithSHA384,
		len(leaf.SubjectKeyId) == 0 || string(leaf.AuthorityKeyId) != string(ca.SubjectKeyId),
		leaf.NotAfter.After(now.Add(ServerLeafTTL)) || leaf.NotAfter.After(ca.NotAfter),
		leaf.NotBefore.Before(now.Add(-clockSkew - time.Second)),
		leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() > 128,
		!samePublic(&key.PublicKey, leaf.PublicKey):
		return nil, ErrServerLeafInvalid
	}
	for _, n := range sans.all {
		if strings.Contains(n, "*") || leaf.VerifyHostname(n) != nil {
			return nil, ErrServerLeafInvalid
		}
	}
	if len(leaf.DNSNames)+len(leaf.IPAddresses) != len(sans.all) {
		return nil, ErrServerLeafInvalid
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now}); err != nil {
		return nil, ErrServerLeafInvalid
	}
	return leaf, nil
}
