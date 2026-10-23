package fleetsql

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.fleet_ca", Entity: "DM-12", Kind: tablekind.Tenant})

// The sealed CA key's place in the AEAD associated data (TM-D7): moving the blob to another tenant,
// row or column fails to open.
const (
	caTable  = "fleet_ca"
	caColumn = "sealed_key"
)

// CA and bundle limits (TM-D24 rule D: 1 to 8 certificates, at most 64 KiB).
const (
	maxBundleCerts = 8
	maxBundleBytes = 64 << 10
	caLifetime     = 10 * 365 * 24 * time.Hour
)

// Errors of the CA. None carries key material, stored bytes or SQL.
var (
	errCAIntegrity = errors.New("fleetsql: installation CA material failed validation") // suspected TM-A11 exposure or corruption; callers answer with the generic error
	errCAUnusable  = errors.New("fleetsql: installation CA is unavailable")
)

// KeySource gives the tenant's data-encryption key (TM-D7) under which the CA private key is sealed.
// version 0 asks for the current version. The caller destroys the key when done. It is the same port
// the audit checkpointer takes.
type KeySource interface {
	DEK(ctx context.Context, tx store.Tx, id tenant.ID, version uint32) (keys.DEK, error)
}

// Alert is an installation alert (TM-D24 rule D2). It names what happened and for which tenant, and
// carries no stored bytes.
type Alert struct {
	Kind   AlertKind
	Tenant tenant.ID
}

// AlertKind is the machine reason of an Alert.
type AlertKind string

// Alert kinds.
const (
	// AlertCAMaterial: stored CA material did not validate (not a CA certificate, trailing bytes, PEM
	// or a private-key block, too many, pinned CA missing). Enroll was refused.
	AlertCAMaterial AlertKind = "fleet.ca.material_invalid"
	// AlertCAKeyExposure: stored CA material contained a private-key block, a suspected TM-A11 exposure.
	AlertCAKeyExposure AlertKind = "fleet.ca.suspected_key_exposure"
)

// Alerter raises installation alerts. Raise must not block on the network; an implementation queues.
type Alerter interface {
	Raise(ctx context.Context, a Alert)
}

// ca is a loaded, validated CA row.
type ca struct {
	id        string
	active    bool
	cert      *x509.Certificate
	sealedKey []byte
	version   uint32
	pin       [32]byte
}

// PinOf returns the "sha256:<hex>" pin of a certificate's SubjectPublicKeyInfo (TM-D24 D1).
func PinOf(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(h[:])
}

func validCACert(c *x509.Certificate) bool {
	return c.BasicConstraintsValid && c.IsCA && c.KeyUsage&x509.KeyUsageCertSign != 0
}

// parseStoredCert parses one stored DER certificate strictly: x509.ParseCertificate refuses trailing
// data, and anything that looks like PEM (a header or a private-key block) is refused first and
// reported as a suspected key exposure.
func parseStoredCert(der []byte) (c *x509.Certificate, exposure bool, err error) {
	if len(der) == 0 || len(der) > maxBundleBytes {
		return nil, false, errCAIntegrity
	}
	if hasPEMMarker(der) {
		return nil, containsPrivateKeyMarker(der), errCAIntegrity
	}
	c, err = x509.ParseCertificate(der)
	if err != nil || !validCACert(c) {
		return nil, false, errCAIntegrity
	}
	return c, false, nil
}

func hasPEMMarker(b []byte) bool {
	return bytes.Contains(b, []byte("-----BEGIN")) || containsPrivateKeyMarker(b)
}

func containsPrivateKeyMarker(b []byte) bool { return bytes.Contains(b, []byte("PRIVATE KEY")) }

// loadCAs reads and validates every CA row of the tenant, active one first. Any row that does not
// validate fails the whole read: a bundle is never served with the bad entry dropped (TM-D24 D2).
func loadCAs(ctx context.Context, tx store.Tx, alert func(AlertKind)) ([]ca, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, cert_der, spki_sha256, sealed_key, key_version, state
		FROM public.fleet_ca ORDER BY (state = 'active') DESC, created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("fleetsql: read CA: %w", err)
	}
	defer rows.Close()
	var out []ca
	bad := false
	for rows.Next() {
		var (
			c       ca
			der, h  []byte
			version int32
			state   string
		)
		if err := rows.Scan(&c.id, &der, &h, &c.sealedKey, &version, &state); err != nil {
			return nil, fmt.Errorf("fleetsql: read CA: %w", err)
		}
		cert, exposure, perr := parseStoredCert(der)
		if exposure {
			alert(AlertCAKeyExposure)
		}
		if perr != nil {
			bad = true
			continue
		}
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		if len(h) != 32 || string(h) != string(sum[:]) || version <= 0 {
			bad = true
			continue
		}
		c.cert, c.version, c.pin, c.active = cert, uint32(version), sum, state == "active"
		out = append(out, c)
		if len(out) > maxBundleCerts {
			bad = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("fleetsql: read CA: %w", err)
	}
	if bad {
		alert(AlertCAMaterial)
		return nil, errCAIntegrity
	}
	return out, nil
}

// bundlePEM builds ca_bundle_pem from parsed certificates, re-encoded as header-free CERTIFICATE
// blocks. Stored bytes never pass through (TM-D24 D2).
func bundlePEM(cas []ca) ([]byte, error) {
	if len(cas) == 0 || len(cas) > maxBundleCerts {
		return nil, errCAIntegrity
	}
	var out []byte
	for _, c := range cas {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})...)
	}
	if len(out) > maxBundleBytes {
		return nil, errCAIntegrity
	}
	return out, nil
}

func caContext(tid tenant.ID, rowID string, version uint32) keys.Context {
	return keys.Context{Tenant: tid, Table: caTable, Row: rowID, Column: caColumn, Version: version}
}

// ensureCA returns the tenant's CA rows, creating the first one when there is none. Creation is
// idempotent under concurrency: the partial unique index admits one active CA, the loser re-reads.
func (e *Enroller) ensureCA(ctx context.Context, tx store.Tx, tid tenant.ID) ([]ca, error) {
	alert := func(k AlertKind) { e.Alerts.Raise(ctx, Alert{Kind: k, Tenant: tid}) }
	cas, err := loadCAs(ctx, tx, alert)
	if err != nil || len(cas) > 0 {
		return cas, err
	}
	if err := e.createCA(ctx, tx, tid); err != nil {
		return nil, err
	}
	return loadCAs(ctx, tx, alert)
}

func (e *Enroller) createCA(ctx context.Context, tx store.Tx, tid tenant.ID) error {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("fleetsql: generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return err
	}
	now := e.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "activeDIQ fleet CA", Organization: []string{"activeDIQ"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("fleetsql: create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("fleetsql: create CA certificate: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("fleetsql: encode CA key: %w", err)
	}
	defer clear(pkcs8)
	dek, err := e.Keys.DEK(ctx, tx, tid, 0)
	if err != nil {
		return fmt.Errorf("%w: tenant data key: %w", errCAUnusable, err)
	}
	defer dek.Destroy()
	var rowID string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&rowID); err != nil {
		return fmt.Errorf("fleetsql: create CA: %w", err)
	}
	sealed, err := keys.Seal(dek, caContext(tid, rowID, dek.Version), pkcs8)
	if err != nil {
		return fmt.Errorf("fleetsql: seal CA key: %w", err)
	}
	pin := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	_, err = tx.Exec(ctx, `INSERT INTO public.fleet_ca (tenant_id, id, cert_der, spki_sha256, sealed_key, key_version, not_after)
		VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1::uuid, $2, $3, $4, $5, $6)
		ON CONFLICT DO NOTHING`, rowID, der, pin[:], sealed, int32(dek.Version), cert.NotAfter)
	if err != nil {
		return fmt.Errorf("fleetsql: store CA: %w", err)
	}
	return nil
}

// signer unseals the CA's private key. The key lives only for the signature that needs it.
func (e *Enroller) signer(ctx context.Context, tx store.Tx, tid tenant.ID, c ca) (crypto.Signer, error) {
	version, err := keys.BlobVersion(c.sealedKey)
	if err != nil || version != c.version {
		return nil, errCAUnusable
	}
	dek, err := e.Keys.DEK(ctx, tx, tid, version)
	if err != nil {
		return nil, fmt.Errorf("%w: tenant data key: %w", errCAUnusable, err)
	}
	defer dek.Destroy()
	pt, err := keys.Open(dek, caContext(tid, c.id, version), c.sealedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCAUnusable, err)
	}
	defer clear(pt)
	k, err := x509.ParsePKCS8PrivateKey(pt)
	if err != nil {
		return nil, errCAUnusable
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errCAUnusable
	}
	// The unsealed key must be the key the certificate names, or the row was tampered with.
	if !samePublic(s.Public(), c.cert.PublicKey) {
		return nil, errCAIntegrity
	}
	return s, nil
}

func samePublic(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	x, ok := a.(eq)
	return ok && x.Equal(b)
}

func newSerial() (*big.Int, error) {
	// 127 random bits: positive, unique with overwhelming probability, and short enough that its hex
	// form fits components.cert_serial.
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("fleetsql: no entropy: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// CSR rules. The request proves possession of a key; everything else in it is ignored (the SAN is
// the token's, never the request's).
const maxCSRBytes = 8 << 10

// ParseCSR checks a PKCS#10 request and returns its public key. It accepts ECDSA P-256 and P-384,
// Ed25519 and RSA of at least 3072 bits, and requires a valid self-signature.
func ParseCSR(der []byte) (crypto.PublicKey, error) {
	if len(der) == 0 || len(der) > maxCSRBytes {
		return nil, ErrCSR
	}
	req, err := x509.ParseCertificateRequest(der) // rejects trailing data
	if err != nil || req.CheckSignature() != nil {
		return nil, ErrCSR
	}
	switch k := req.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, ErrCSR
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if k.N.BitLen() < 3072 {
			return nil, ErrCSR
		}
	default:
		return nil, ErrCSR
	}
	return req.PublicKey, nil
}

// TenantCAs returns the CA certificates of one tenant, active and retired, for the gateway's check
// that a client certificate was signed by the CA of the tenant its SAN names (TM-Q8). It never
// creates a CA, and returns an error rather than a partial list when stored material is bad.
func (e *Enroller) TenantCAs(ctx context.Context, tid tenant.ID) ([]*x509.Certificate, error) {
	if err := e.ready(); err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	err := e.Enrollment.DB.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
		cas, err := loadCAs(ctx, tx, func(k AlertKind) { e.Alerts.Raise(ctx, Alert{Kind: k, Tenant: tid}) })
		if err != nil {
			return err
		}
		for _, c := range cas {
			out = append(out, c.cert)
		}
		return nil
	})
	if err != nil {
		return nil, publicErr(err)
	}
	return out, nil
}
