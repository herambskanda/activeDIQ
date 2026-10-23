package dial

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func newCA(t *testing.T, cn string) authority {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return authority{c, k, der}
}

func (a authority) sign(t *testing.T, tpl *x509.Certificate, pub any) []byte {
	t.Helper()
	tpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tpl.NotBefore, tpl.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, pub, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (a authority) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.der})
}

func (a authority) pin() Pin { return pinOf(a.cert) }

// serve starts a TLS 1.3 server presenting chain (leaf signed by signer, plus extra certificates).
func serve(t *testing.T, signer authority, withCA bool) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := signer.sign(t, &x509.Certificate{DNSNames: []string{"localhost"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}, k.Public())
	chain := [][]byte{der}
	if withCA {
		chain = append(chain, signer.der)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: k}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.(*tls.Conn).Handshake() }()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return net.JoinHostPort("localhost", port)
}

type issuer struct {
	ca     authority
	calls  atomic.Int32
	tamper func(*Response)
	tid    tenant.ID
}

func (i *issuer) exchange(ctx context.Context, creds credentials.TransportCredentials, addr, token string, csr []byte) (Response, error) {
	i.calls.Add(1)
	req, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return Response{}, err
	}
	der := i.ca.sign(nil2t, &x509.Certificate{
		URIs:        fleet.URIs(i.tid, "connector", "11111111-2222-4333-8444-555555555555"),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, req.PublicKey)
	r := Response{LeafDER: der, CABundlePEM: i.ca.pem(), Endpoints: []Endpoint{{Host: "fleet.example", Port: 8443}}}
	if i.tamper != nil {
		i.tamper(&r)
	}
	return r, nil
}

var nil2t *testing.T

func setup(t *testing.T) (*issuer, Material, string) {
	t.Helper()
	nil2t = t
	ca := newCA(t, "installation CA")
	addr := serve(t, ca, true)
	return &issuer{ca: ca, tid: tenant.New()}, Material{Address: addr, Token: "tok", Pin: ca.pin().String()}, filepath.Join(t.TempDir(), "state")
}

func assertNothingPersisted(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(dir); err == nil {
		ents, _ := os.ReadDir(dir)
		if len(ents) != 0 {
			t.Fatalf("persisted %d files after a failed enrolment", len(ents))
		}
	}
}

func TestEnrollPinsAndPersists(t *testing.T) {
	iss, m, dir := setup(t)
	st, err := Enroll(context.Background(), m, dir, iss.exchange)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.CA) != 1 || !st.Pin.Matches(st.CA[0]) || len(st.Endpoints) != 1 {
		t.Fatalf("state = %+v", st)
	}
	if runtimeUnix() {
		fi, _ := os.Stat(filepath.Join(dir, KeyFile))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("key mode %o", fi.Mode().Perm())
		}
		di, _ := os.Stat(dir)
		if di.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %o", di.Mode().Perm())
		}
	}
	keyPEM, _ := os.ReadFile(filepath.Join(dir, KeyFile))
	for _, f := range []string{CAFile, LeafFile, PinFile, EndpointsFile} {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		if strings.Contains(string(b), "PRIVATE KEY") {
			t.Fatalf("%s holds key material", f)
		}
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Fatal("key not persisted")
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("reload: %v", err)
	}
}

func TestEnrollRefusesUnpinnedServers(t *testing.T) {
	good := newCA(t, "installation CA")
	other := newCA(t, "attacker CA")
	// self-signed server certificate: the CA is the leaf's own issuer, but is not the pinned key.
	cases := map[string]string{
		"different CA (MITM)":    serve(t, other, true),
		"CA withheld from chain": serve(t, good, false),
	}
	for name, addr := range cases {
		t.Run(name, func(t *testing.T) {
			iss := &issuer{ca: good, tid: tenant.New()}
			dir := filepath.Join(t.TempDir(), "state")
			_, err := Enroll(context.Background(), Material{Address: addr, Token: "secret-token", Pin: good.pin().String()}, dir, iss.exchange)
			if !errors.Is(err, ErrUntrustedServer) {
				t.Fatalf("err = %v, want ErrUntrustedServer", err)
			}
			if iss.calls.Load() != 0 {
				t.Fatal("the token was sent to an unpinned server")
			}
			if strings.Contains(err.Error(), "secret-token") {
				t.Fatal("token in error")
			}
			assertNothingPersisted(t, dir)
		})
	}
}

func TestSelfSignedServerRefused(t *testing.T) {
	good := newCA(t, "installation CA")
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}})
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = c.(*tls.Conn).Handshake() }()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	iss := &issuer{ca: good, tid: tenant.New()}
	_, err := Enroll(context.Background(), Material{Address: net.JoinHostPort("localhost", port), Token: "t", Pin: good.pin().String()}, filepath.Join(t.TempDir(), "s"), iss.exchange)
	if !errors.Is(err, ErrUntrustedServer) || iss.calls.Load() != 0 {
		t.Fatalf("err = %v calls = %d", err, iss.calls.Load())
	}
}

func TestRetryNeverFallsBack(t *testing.T) {
	good, other := newCA(t, "installation CA"), newCA(t, "attacker CA")
	iss := &issuer{ca: good, tid: tenant.New()}
	m := Material{Address: serve(t, other, true), Token: "t", Pin: good.pin().String()}
	for i := 0; i < 3; i++ {
		if _, err := Enroll(context.Background(), m, filepath.Join(t.TempDir(), "s"), iss.exchange); !errors.Is(err, ErrUntrustedServer) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if iss.calls.Load() != 0 {
		t.Fatal("a retry reached the exchange")
	}
}

func TestEnrollRejectsBadResponses(t *testing.T) {
	other := newCA(t, "other")
	cases := map[string]func(*Response, *issuer){
		"bundle without pinned CA": func(r *Response, i *issuer) { r.CABundlePEM = other.pem() },
		"leaf from another CA": func(r *Response, i *issuer) {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			r.LeafDER = other.sign(t, &x509.Certificate{URIs: fleet.URIs(i.tid, "agent", "11111111-2222-4333-8444-555555555555"), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, k.Public())
		},
		"leaf without identity": func(r *Response, i *issuer) {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			r.LeafDER = i.ca.sign(t, &x509.Certificate{DNSNames: []string{"x"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, k.Public())
		},
		"leaf for a key we do not hold": func(r *Response, i *issuer) {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			r.LeafDER = i.ca.sign(t, &x509.Certificate{URIs: fleet.URIs(i.tid, "agent", "11111111-2222-4333-8444-555555555555"), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, k.Public())
		},
		"no endpoints": func(r *Response, i *issuer) { r.Endpoints = nil },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			iss, m, dir := setup(t)
			iss.tamper = func(r *Response) { tamper(r, iss) }
			if _, err := Enroll(context.Background(), m, dir, iss.exchange); err == nil {
				t.Fatal("accepted")
			}
			assertNothingPersisted(t, dir)
		})
	}
}

func TestParseBundleCorpus(t *testing.T) {
	a, b := newCA(t, "a"), newCA(t, "b")
	pin := a.pin()
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	notCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.sign(t, &x509.Certificate{}, leafKey.Public())})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	hdr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"X": "y"}, Bytes: a.der})
	var nine []byte
	for i := 0; i < 9; i++ {
		nine = append(nine, a.pem()...)
	}
	ok := map[string][]byte{
		"one":        a.pem(),
		"two":        append(append([]byte{}, b.pem()...), a.pem()...),
		"whitespace": append(append([]byte("\n  \t"), a.pem()...), "\n\n  "...),
		"eight":      nine[:len(a.pem())*8],
	}
	for n, in := range ok {
		if _, err := ParseBundle(in, pin); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	bad := map[string][]byte{
		"empty":              nil,
		"no pinned CA":       b.pem(),
		"garbage before":     append([]byte("junk\n"), a.pem()...),
		"garbage after":      append(append([]byte{}, a.pem()...), "junk"...),
		"garbage between":    append(append(append([]byte{}, a.pem()...), "junk\n"...), b.pem()...),
		"private key block":  append(append([]byte{}, a.pem()...), privPEM...),
		"header":             hdr,
		"not a CA":           append(append([]byte{}, notCA...), a.pem()...),
		"nine certs":         nine,
		"over 64KiB":         append(a.pem(), make([]byte, MaxBundleBytes)...),
		"DER not PEM":        a.der,
		"truncated":          a.pem()[:len(a.pem())-40],
		"wrong block type":   pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: a.der}),
		"cert with trailing": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: append(append([]byte{}, a.der...), 0)}),
	}
	for n, in := range bad {
		if _, err := ParseBundle(in, pin); !errors.Is(err, ErrBundle) {
			t.Errorf("%s: err = %v, want ErrBundle", n, err)
		}
	}
}

func TestParsePin(t *testing.T) {
	good := "sha256:" + strings.Repeat("ab", 32)
	if _, err := ParsePin(good); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"", "sha256:", "sha1:" + strings.Repeat("ab", 20), "sha256:" + strings.Repeat("AB", 32), "sha256:" + strings.Repeat("ab", 31), good + "0", " " + good} {
		if _, err := ParsePin(s); !errors.Is(err, ErrPin) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestClientTLSNeverUsesHostRoots(t *testing.T) {
	c := clientTLS(Pool(nil), "h", nil)
	if c.RootCAs == nil || c.InsecureSkipVerify || c.MinVersion < tls.VersionTLS13 {
		t.Fatalf("%+v", c)
	}
	if _, err := Credentials(nil, "h", nil); err == nil {
		t.Fatal("empty CA set accepted")
	}
}

func TestLoadRefusesUnsafeState(t *testing.T) {
	if !runtimeUnix() {
		t.Skip("unix permissions")
	}
	iss, m, dir := setup(t)
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, KeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrState) {
		t.Fatalf("loose key accepted: %v", err)
	}
	os.Chmod(filepath.Join(dir, KeyFile), 0o600)
	if err := os.WriteFile(filepath.Join(dir, CAFile), append(iss.ca.pem(), "junk"...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrState) {
		t.Fatalf("tampered bundle accepted: %v", err)
	}
}

func runtimeUnix() bool { return filepath.Separator == '/' }
