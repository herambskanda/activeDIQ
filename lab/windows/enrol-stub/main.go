// Command enrol-stub is a LAB-ONLY fleet server stand-in for T-0833: it answers Fleet.Enroll with a
// freshly issued component certificate and records the time of every mTLS Tunnel attempt, so a worker
// can prove that an installed, running, unenrolled agent service picks enrolment up by itself.
//
// It is not the product server: no database, no real tokens, no tenant data. It generates a throwaway
// pinned server CA (path length 0), a tenant client CA and a server leaf for -host, prints the pin and a
// one-time token (stdout, one `KEY=value` per line), and serves on -listen until killed. Nothing it
// generates is written to disk. Runbook: knowledge/development/runbooks/windows-lab.md section 17.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	fleetv1 "github.com/skenzeriq/activediq/internal/proto/activediq/fleet/v1"
)

type stub struct {
	fleetv1.UnimplementedFleetServer
	mu       sync.Mutex
	token    string
	used     bool
	clientCA *x509.Certificate
	clientK  *ecdsa.PrivateKey
	bundle   []byte
	host     string
	port     uint32
	tid      tenant.ID
}

func (s *stub) Enroll(_ context.Context, r *fleetv1.EnrollRequest) (*fleetv1.EnrollResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || r.GetEnrollmentToken() != s.token {
		log.Printf("ENROLL refused (bad or used token)")
		return nil, status.Error(codes.PermissionDenied, "token")
	}
	csr, err := x509.ParseCertificateRequest(r.GetCsrDer())
	if err != nil || csr.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "csr")
	}
	cid := newUUID()
	tpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "lab component"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: fleet.URIs(s.tid, fleet.KindADDC, cid),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, s.clientCA, csr.PublicKey, s.clientK)
	if err != nil {
		return nil, status.Error(codes.Internal, "issue")
	}
	s.used = true
	log.Printf("ENROLL ok component=%s", cid)
	return &fleetv1.EnrollResponse{LeafCertificateDer: der, CaBundlePem: s.bundle,
		Endpoints:    []*fleetv1.Endpoint{{Host: s.host, Port: s.port}},
		LeafNotAfter: timestamppb.New(tpl.NotAfter)}, nil
}

// Tunnel records the verified client identity and refuses: reaching this point is the evidence.
func (s *stub) Tunnel(ss grpc.BidiStreamingServer[fleetv1.TunnelFrame, fleetv1.TunnelFrame]) error {
	who := "unknown"
	if p, ok := peer.FromContext(ss.Context()); ok {
		if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
			if id, err := fleet.IdentityOf(ti.State.PeerCertificates[0]); err == nil {
				who = id.Kind + ":" + id.ComponentID
			}
		}
	}
	log.Printf("TUNNEL mTLS client verified component=%s", who)
	return status.Error(codes.Unavailable, "lab stub: no tunnel")
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n.Add(n, big.NewInt(1))
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

// newStub builds the throwaway PKI and the stub. host is the name or IP the agent dials; it goes into the
// server certificate and the endpoint list.
func newStub(host string, port uint32) (*stub, *tls.Config, string) {
	k := func() *ecdsa.PrivateKey { return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)) }
	now := time.Now()
	rootK, clientK, srvK := k(), k(), k()
	rootT := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "lab pinned server CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER := must(x509.CreateCertificate(rand.Reader, rootT, rootT, &rootK.PublicKey, rootK))
	root := must(x509.ParseCertificate(rootDER))
	clientT := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "lab tenant client CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	clientDER := must(x509.CreateCertificate(rand.Reader, clientT, clientT, &clientK.PublicKey, clientK))
	clientCA := must(x509.ParseCertificate(clientDER))
	srvT := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "lab fleet server"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		srvT.IPAddresses = []net.IP{ip}
	} else {
		srvT.DNSNames = []string{host}
	}
	srvDER := must(x509.CreateCertificate(rand.Reader, srvT, root, &srvK.PublicKey, rootK))
	pemOf := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	tokB := make([]byte, 16)
	_, _ = rand.Read(tokB)
	s := &stub{token: hex.EncodeToString(tokB), clientCA: clientCA, clientK: clientK, host: host, port: port,
		tid: tenant.New(), bundle: append(pemOf(rootDER), pemOf(clientDER)...)}
	pool := x509.NewCertPool()
	pool.AddCert(clientCA)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER, rootDER}, PrivateKey: srvK}},
		ClientAuth:   tls.VerifyClientCertIfGiven, ClientCAs: pool} // Enroll takes no client certificate
	pin := sha256.Sum256(root.RawSubjectPublicKeyInfo)
	return s, tlsCfg, "sha256:" + hex.EncodeToString(pin[:])
}

func main() {
	listen := flag.String("listen", "0.0.0.0:7443", "listen address")
	host := flag.String("host", "", "IP or name the agent dials (in the server certificate and the endpoint list)")
	flag.Parse()
	if *host == "" {
		log.Fatal("-host is required")
	}
	_, ps, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatal(err)
	}
	var port uint32
	if _, err := fmt.Sscanf(ps, "%d", &port); err != nil {
		log.Fatal(err)
	}
	s, tlsCfg, pin := newStub(*host, port)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	fleetv1.RegisterFleetServer(srv, s)
	lis := must(net.Listen("tcp", *listen))
	fmt.Printf("PIN=%s\nTOKEN=%s\nADDR=%s:%d\nREADY=1\n", pin, s.token, *host, port)
	_ = os.Stdout.Sync()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
	log.Fatal(srv.Serve(lis))
}
