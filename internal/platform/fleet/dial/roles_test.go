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
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// serveChain presents a leaf signed by leafSigner followed by extra certificates (DER).
func serveChain(t *testing.T, leafSigner authority, extra ...[]byte) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := leafSigner.sign(t, &x509.Certificate{DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}, k.Public())
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{{Certificate: append([][]byte{der}, extra...), PrivateKey: k}}})
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
	return net.JoinHostPort("127.0.0.1", port)
}

// ADR-0008 AC1: a leaf signed by a tenant CA and presented as the server is refused, both by Enroll
// (the token is never sent) and by DialOut, even when the tenant CA is in the client's bundle.
func TestTenantSignedServerRefused(t *testing.T) {
	if !runtimeUnix() {
		t.Skip("unix only")
	}
	srv, tenantCA := newCA(t, "installation server CA"), newCA(t, "tenant client CA")
	// The attacker's chain: leaf by the tenant CA, the tenant CA, and even the real server CA.
	addr := serveChain(t, tenantCA, tenantCA.der, srv.der)
	iss := &issuer{ca: tenantCA, srv: srv, tid: tenant.New()}
	dir := filepath.Join(tempParent(t), "state")
	_, err := Enroll(context.Background(), Material{Address: addr, Token: "secret-token", Pin: srv.pin().String()}, dir, iss.exchange)
	if err == nil {
		t.Fatal("tenant-signed server accepted by Enroll")
	}
	if iss.calls.Load() != 0 {
		t.Fatal("token sent to a tenant-signed server")
	}
	assertNothingPersisted(t, dir)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafDER := tenantCA.sign(t, &x509.Certificate{URIs: fleet.URIs(tenant.New(), "connector", "11111111-2222-4333-8444-555555555555"), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, leafKey.Public())
	st := &State{Pin: srv.pin(), Roots: []*x509.Certificate{srv.cert}, ClientCAs: []*x509.Certificate{tenantCA.cert}, Leaf: tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}
	cc, err := DialOut(addr, st)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = cc.Invoke(ctx, "/x.Y/Z", &emptypb.Empty{}, &emptypb.Empty{})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v, want a certificate failure", err)
	}
}

// ADR-0008 AC2: with a bundle of server CA and tenant CA, the roots are only the pinned CA, and the
// issued leaf is checked against the tenant CA for ClientAuth — not against the server CA.
func TestBundleRolesSplit(t *testing.T) {
	srv, tenantCA := newCA(t, "installation server CA"), newCA(t, "tenant client CA")
	b, err := ParseBundle(append(tenantCA.pem(), srv.pem()...), srv.pin())
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Roots) != 1 || !srv.pin().Matches(b.Roots[0]) || len(b.ClientCAs) != 1 || srv.pin().Matches(b.ClientCAs[0]) {
		t.Fatalf("roles = %d roots, %d client CAs", len(b.Roots), len(b.ClientCAs))
	}
	creds, err := Credentials(b.Roots, "localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = creds
	cfg := clientTLS(Pool(b.Roots), "localhost", nil)
	if n := len(cfg.RootCAs.Subjects()); n != 1 { //nolint:staticcheck // counting the test pool only
		t.Fatalf("RootCAs holds %d certificates, want 1", n)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uris := fleet.URIs(tenant.New(), "connector", "11111111-2222-4333-8444-555555555555")
	tpl := func() *x509.Certificate {
		return &x509.Certificate{URIs: uris, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	}
	byTenant, _ := x509.ParseCertificate(tenantCA.sign(t, tpl(), key.Public()))
	if err := checkLeaf(byTenant, key, b.ClientCAs); err != nil {
		t.Fatalf("tenant-signed leaf: %v", err)
	}
	bySrv, _ := x509.ParseCertificate(srv.sign(t, tpl(), key.Public()))
	if err := checkLeaf(bySrv, key, b.ClientCAs); !errors.Is(err, ErrLeaf) {
		t.Fatalf("server-CA-signed leaf accepted as a component identity: %v", err)
	}
}

func TestPinnedRootMustBeShapedAsServerRoot(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk := func(mod func(*x509.Certificate)) []byte {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
		mod(tpl)
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
		if err != nil {
			t.Fatal(err)
		}
		return pemOf(der)
	}
	good := mk(func(*x509.Certificate) {})
	c, _ := x509.ParseCertificate(derOf(good))
	pin := pinOf(c)
	if _, err := ParseBundle(good, pin); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*x509.Certificate){
		"unbounded path length": func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = -1, false },
		"path length 1":         func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 1, false },
		"no CertSign":           func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCRLSign },
	} {
		if _, err := ParseBundle(mk(mod), pin); !errors.Is(err, ErrBundle) {
			t.Errorf("%s: err = %v, want ErrBundle", name, err)
		}
	}
}

func repinSetup(t *testing.T) (*issuer, string, string) {
	t.Helper()
	iss, m, dir := setup(t)
	if _, err := Enroll(context.Background(), m, dir, iss.exchange); err != nil {
		t.Fatal(err)
	}
	// Point the state at the live test server so a refusal is about the pin, not the network.
	put(t, dir, EndpointsFile, []byte(m.Address+"\n"))
	return iss, m.Address, dir
}

// ADR-0008 AC3: repin keeps the identity, rewrites the state atomically-enough that it always loads,
// and is audited.
func TestRepinKeepsIdentityAndAudits(t *testing.T) {
	iss, _, dir := repinSetup(t)
	before, _ := Load(dir)
	keyBefore, _ := os.ReadFile(filepath.Join(dir, KeyFile))
	leafBefore, _ := os.ReadFile(filepath.Join(dir, LeafFile))

	// The server CA was replaced; the new server presents it, and the endpoint the state knows is
	// pointed at it.
	newSrv := newCA(t, "new installation server CA")
	addr := serveChain(t, newSrv, newSrv.der)
	host, port, _ := net.SplitHostPort(addr)
	eps := []Endpoint{{Host: host, Port: mustPort(t, port)}}
	if err := save(dir, before.Pin, append(iss.srv.pem(), iss.ca.pem()...), derOf(leafBefore), mustKeyDER(t, keyBefore), eps); err != nil {
		t.Fatal(err)
	}

	var events []RepinEvent
	if err := Repin(context.Background(), dir, newSrv.pin().String(), func(e RepinEvent) { events = append(events, e) }); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Err != nil || events[0].OldPin != before.Pin || events[0].NewPin != newSrv.pin() {
		t.Fatalf("audit = %+v", events)
	}
	after, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Pin != newSrv.pin() || len(after.Roots) != 1 || !after.Pin.Matches(after.Roots[0]) {
		t.Fatalf("pin/roots not moved: %+v", after.Pin)
	}
	if len(after.ClientCAs) != 1 || !after.ClientCAs[0].Equal(iss.ca.cert) {
		t.Fatalf("client CAs = %d, want the tenant CA only (old server CA must be gone)", len(after.ClientCAs))
	}
	keyAfter, _ := os.ReadFile(filepath.Join(dir, KeyFile))
	leafAfter, _ := os.ReadFile(filepath.Join(dir, LeafFile))
	if string(keyAfter) != string(keyBefore) || string(leafAfter) != string(leafBefore) {
		t.Fatal("identity (key/leaf) changed by repin")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestRepinRefusals(t *testing.T) {
	iss, addr, dir := repinSetup(t)
	st, _ := Load(dir)
	wantPin := newCA(t, "wanted new CA")
	_ = addr
	cases := map[string]string{
		"same pin":                      st.Pin.String(),
		"pin the server does not serve": wantPin.pin().String(), // endpoint serves iss.srv
	}
	for name, pin := range cases {
		var ev []RepinEvent
		err := Repin(context.Background(), dir, pin, func(e RepinEvent) { ev = append(ev, e) })
		if !errors.Is(err, ErrRepin) {
			t.Errorf("%s: err = %v", name, err)
		}
		if len(ev) != 1 || ev[0].Err == nil {
			t.Errorf("%s: failure not audited: %+v", name, ev)
		}
		got, lerr := Load(dir)
		if lerr != nil || got.Pin != st.Pin {
			t.Errorf("%s: state changed (%v)", name, lerr)
		}
	}
	if err := Repin(context.Background(), dir, "sha256:zz", func(RepinEvent) { t.Error("audited a malformed pin") }); !errors.Is(err, ErrPin) {
		t.Errorf("malformed pin: %v", err)
	}
	_ = iss
	if err := Repin(context.Background(), t.TempDir(), st.Pin.String(), func(RepinEvent) {}); err == nil {
		t.Error("repin of an unenrolled directory succeeded")
	}
}

// snapshotDir returns every file in dir (name -> bytes), so a test can prove nothing was touched.
func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// T-0736 finding 3 / TM-D24 rule D3: the transition bundle is proven to parse before any write. A new
// server CA whose transition bundle (old roots + new root + client CAs) exceeds MaxBundleBytes must
// be refused with nothing written: no state file changes, no temp file, and Load still succeeds.
func TestRepinOversizedTransitionBundleRefusedBeforeAnyWrite(t *testing.T) {
	if !runtimeUnix() {
		t.Skip("unix only")
	}
	iss, _, dir := repinSetup(t)

	// A server-shaped CA (IsCA, MaxPathLenZero, CertSign) padded by a non-critical extension of
	// ~52 KB, so its PEM alone is over MaxBundleBytes.
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "oversized new server CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
		ExtraExtensions: []pkix.Extension{{Id: []int{1, 3, 6, 1, 4, 1, 99999, 1}, Value: make([]byte, 52000)}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	bigCA := authority{c, k, der}

	before, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	transPEM := bigCA.pem()
	for _, r := range before.Roots {
		transPEM = append(transPEM, authority{der: r.Raw}.pem()...)
	}
	if len(transPEM) <= MaxBundleBytes {
		t.Fatalf("precondition: transition bundle is %d bytes, want > %d", len(transPEM), MaxBundleBytes)
	}

	// The endpoint serves [leaf signed by bigCA, bigCA]; the state points at it.
	addr := serveChain(t, bigCA, bigCA.der)
	host, port, _ := net.SplitHostPort(addr)
	keyB, _ := os.ReadFile(filepath.Join(dir, KeyFile))
	leafB, _ := os.ReadFile(filepath.Join(dir, LeafFile))
	eps := []Endpoint{{Host: host, Port: mustPort(t, port)}}
	if err := save(dir, before.Pin, append(iss.srv.pem(), iss.ca.pem()...), derOf(leafB), mustKeyDER(t, keyB), eps); err != nil {
		t.Fatal(err)
	}
	snap := snapshotDir(t, dir)

	var events []RepinEvent
	err = Repin(context.Background(), dir, bigCA.pin().String(), func(e RepinEvent) { events = append(events, e) })
	if !errors.Is(err, ErrRepin) {
		t.Fatalf("err = %v, want ErrRepin", err)
	}
	if !strings.Contains(err.Error(), "transition bundle") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	if len(events) != 1 || events[0].Err == nil || events[0].OldPin != before.Pin || events[0].NewPin != bigCA.pin() {
		t.Fatalf("audit = %+v, want exactly one failure event", events)
	}
	after := snapshotDir(t, dir)
	if len(after) != len(snap) {
		t.Fatalf("files changed: %d -> %d", len(snap), len(after))
	}
	for name, b := range snap {
		if got, ok := after[name]; !ok || got != b {
			t.Errorf("%s changed by a refused repin", name)
		}
	}
	st, err := Load(dir)
	if err != nil {
		t.Fatalf("Load after refused repin: %v", err)
	}
	if st.Pin != before.Pin {
		t.Fatal("pin moved by a refused repin")
	}
}

func pemOf(der []byte) []byte { return authority{der: der}.pem() }

func derOf(pemBytes []byte) []byte {
	b, _ := pem.Decode(pemBytes)
	return b.Bytes
}

func mustPort(t *testing.T, p string) uint16 {
	t.Helper()
	n, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(n)
}

func mustKeyDER(t *testing.T, keyPEM []byte) []byte {
	t.Helper()
	b, _ := pem.Decode(keyPEM)
	if b == nil {
		t.Fatal("no key block")
	}
	return b.Bytes
}
