package connector_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/skenzeriq/activediq/internal/compose/connector"
	"github.com/skenzeriq/activediq/internal/connector/rights"
	"github.com/skenzeriq/activediq/internal/connector/write"
	v1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

type nopBase struct{}

func (nopBase) Append(string, []write.Mark) error { return nil }

type stubDir struct{ rights.ADDirectory }

func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, usage x509.ExtKeyUsage, isCA bool) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true, IsCA: isCA}
	if isCA {
		tpl.KeyUsage |= x509.KeyUsageCertSign
		tpl.ExtKeyUsage = nil
	}
	parent, pk := tpl, k
	if ca != nil {
		parent, pk = ca, caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &k.PublicKey, pk)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: c}
}

func TestNewServerRequiresMTLS(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	der, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, srvCert := issue(t, ca, caKey, "server", x509.ExtKeyUsageServerAuth, false)
	_, cliCert := issue(t, ca, caKey, "client", x509.ExtKeyUsageClientAuth, false)

	gate, _ := write.NewGateBook(nopBase{}, nil)
	h, err := rights.NewVerifyHandler(rights.VerifyConfig{Dir: stubDir{}, Epoch: rights.NewEpochState(nil, nil, nil),
		Directory: &v1.DirectoryIdentity{}, Gate: gate, OnLocalRecordFailed: gate.CloseLocalRecordFailed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connector.NewServer(srvCert, x509.NewCertPool(), h); err == nil {
		t.Fatal("empty client CA pool accepted")
	}
	if _, err := connector.NewServer(srvCert, pool, nil); err == nil {
		t.Fatal("nil handler accepted")
	}
	srv, err := connector.NewServer(srvCert, pool, h)
	if err != nil {
		t.Fatal(err)
	}
	lis, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	call := func(creds credentials.TransportCredentials) error {
		cc, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(creds))
		if err != nil {
			return err
		}
		defer cc.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		st, err := v1.NewConnectorClient(cc).VerifyConnection(ctx, &v1.VerifyConnectionRequest{})
		if err != nil {
			return err
		}
		_, err = st.Recv()
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	base := func(certs ...tls.Certificate) credentials.TransportCredentials {
		return credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, Certificates: certs})
	}
	// No client certificate: the handshake is refused, the handler is never reached.
	if err := call(base()); status.Code(err) != codes.Unavailable {
		t.Fatalf("no client cert: %v", err)
	}
	// A certificate from an untrusted CA is refused.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "other"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true}
	oder, _ := x509.CreateCertificate(rand.Reader, otherTpl, otherTpl, &otherKey.PublicKey, otherKey)
	other, _ := x509.ParseCertificate(oder)
	_, rogue := issue(t, other, otherKey, "rogue", x509.ExtKeyUsageClientAuth, false)
	if err := call(base(rogue)); status.Code(err) != codes.Unavailable {
		t.Fatalf("rogue client reached the handler: %v", err)
	}
	// A trusted client reaches the handler (an empty request is a fixed INVALID_ARGUMENT refusal).
	err = call(base(cliCert))
	if status.Code(err) == codes.Unavailable || err == nil {
		t.Fatalf("trusted client: %v", err)
	}
}
