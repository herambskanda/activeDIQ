package syslog

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/egress"
)

func TestDefaultIsVerifiedTLS(t *testing.T) {
	d, err := Destination{ID: "d1", Host: "siem.example"}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if d.Transport != TLS || d.Port != 6514 || d.PlaintextOptIn {
		t.Fatalf("got %+v", d)
	}
	v := d.View()
	if !v.TLSVerified || v.Warning != "" || v.PlaintextOptIn {
		t.Fatalf("view %+v", v)
	}
	if OptInEvent("e", authority.Chain{}, d, time.Now()) != nil {
		t.Fatal("TLS destination must not produce an opt-in event")
	}
}

func TestPlaintextNeedsExplicitOptIn(t *testing.T) {
	if _, err := (Destination{ID: "d", Host: "h", Transport: TCP}).Normalize(); !errors.Is(err, ErrPlaintextNotOptedIn) {
		t.Fatalf("err %v", err)
	}
	if _, err := (Destination{ID: "d", Host: "h", PlaintextOptIn: true}).Normalize(); !errors.Is(err, ErrBadDestination) {
		t.Fatalf("opt-in with TLS: %v", err)
	}
	if _, err := (Destination{ID: "d", Host: "h", Transport: "udp"}).Normalize(); !errors.Is(err, ErrBadDestination) {
		t.Fatalf("udp: %v", err)
	}
	d, err := Destination{ID: "d", Host: "h", Transport: TCP, PlaintextOptIn: true}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	v := d.View()
	if v.TLSVerified || !v.PlaintextOptIn || v.Warning == "" || v.Transport != "tcp" || v.Port != 514 {
		t.Fatalf("view %+v", v)
	}
	actor := authority.Chain{Requester: authority.Principal{ID: "u1", Kind: authority.Human}}
	ev := OptInEvent("e1", actor, d, time.Now())
	if ev == nil || ev.Kind != KindPlaintextOptIn || ev.Validate() != nil || ev.Outcome != audit.Success {
		t.Fatalf("event %+v", ev)
	}
	for i := 1; i < len(ev.Details); i++ {
		if ev.Details[i-1].Key >= ev.Details[i].Key {
			t.Fatal("details not in key order")
		}
	}
}

func TestFormatCannotForgeRecords(t *testing.T) {
	s := Format(Message{Facility: 4, Severity: 6, Time: time.Unix(0, 0), Hostname: "a b\n", App: "x", Text: "one\r\n<13>1 forged"})
	if strings.ContainsAny(s, "\r\n") || !strings.HasPrefix(s, "<38>1 1970-01-01T00:00:00.000Z ab x - - - one") {
		t.Fatalf("%q", s)
	}
}

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "siem"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pool
}

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

func TestSendOverVerifiedTLS(t *testing.T) {
	cert, pool := testCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		l, _ := bufio.NewReader(c).ReadString('Z')
		rest := make([]byte, 64)
		n, _ := c.Read(rest)
		got <- l + string(rest[:n])
		if c2, err := ln.Accept(); err == nil {
			_ = c2.(*tls.Conn).Handshake()
			c2.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	d := Destination{ID: "d", Host: "127.0.0.1", Port: port}

	// trusted CA + allow-listed loopback: delivered, octet-counted.
	cl, _ := egress.New(egress.Config{Allow: loopback, RootCAs: pool})
	if err := Send(context.Background(), cl, d, Message{Time: time.Unix(0, 0), Text: "hello"}); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if !strings.Contains(s, strconv.Itoa(len(Format(Message{Time: time.Unix(0, 0), Text: "hello"})))+" <") {
			t.Fatalf("frame %q", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nothing received")
	}

	// system roots do not trust the test CA: verification fails, nothing is sent.
	cl2, _ := egress.New(egress.Config{Allow: loopback})
	if err := Send(context.Background(), cl2, d, Message{Text: "x"}); err == nil {
		t.Fatal("untrusted certificate was accepted")
	}
}

func TestInternalRangeRefusedUnlessAllowListed(t *testing.T) {
	cl, _ := egress.New(egress.Config{})
	for _, d := range []Destination{
		{ID: "a", Host: "127.0.0.1"},
		{ID: "b", Host: "10.1.2.3", Transport: TCP, PlaintextOptIn: true},
		{ID: "c", Host: "169.254.169.254"},
	} {
		err := Send(context.Background(), cl, d, Message{Text: "x"})
		if !errors.Is(err, egress.ErrDestinationDenied) {
			t.Fatalf("%s: %v", d.Host, err)
		}
	}
}

func TestBadHostsRefused(t *testing.T) {
	for _, h := range []string{"a\x00b", "a:b", "[::1]", "ü.example", "a b", "-a.example", "fe80::1%eth0", "a..b", ""} {
		if _, err := (Destination{ID: "d", Host: h}).Normalize(); !errors.Is(err, ErrBadDestination) {
			t.Errorf("host %q: err = %v, want ErrBadDestination", h, err)
		}
	}
	for _, h := range []string{"siem.example.com", "10.0.0.5", "::1", "siem"} {
		if _, err := (Destination{ID: "d", Host: h}).Normalize(); err != nil {
			t.Errorf("host %q: %v", h, err)
		}
	}
}
