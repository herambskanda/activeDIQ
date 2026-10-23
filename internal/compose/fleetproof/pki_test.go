package fleetproof

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const compID = "11111111-2222-4333-8444-555555555555"

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newAuthority(t *testing.T, cn string) authority {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 0, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return authority{c, k}
}

func (a authority) sign(t *testing.T, tpl *x509.Certificate, pub any) []byte {
	t.Helper()
	tpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	if tpl.NotBefore.IsZero() {
		tpl.NotBefore, tpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, pub, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// serverCert is a TLS server certificate for localhost signed by a, with the CA appended to the
// chain as an installation server presents it.
func (a authority) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := a.sign(t, &x509.Certificate{
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, k.Public())
	return tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: k}
}

// clientCert is a component certificate for (tid, comp) signed by a.
func (a authority) clientCert(t *testing.T, tid tenant.ID, comp string) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := a.sign(t, &x509.Certificate{
		URIs:        fleet.URIs(tid, "connector", comp),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, k.Public())
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
