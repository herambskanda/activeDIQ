// Package mailtest is the mail-catcher of the test harness (T-0950): a small SMTP server on the loopback
// interface that records what it is sent and can be told to fail on purpose. It is for tests only;
// nothing in a product binary imports it.
//
// It speaks just enough SMTP for the sender: EHLO, STARTTLS (optional), MAIL, RCPT, DATA, RSET, NOOP and
// QUIT. Faults are per recipient address or for the whole server, so a test can induce "the relay
// rejects one of three recipients" or "the relay is down".
//
// Reaching the catcher through the egress client needs the loopback range in Config.Allow, which is
// exactly what an operator allow-list entry for an internal relay looks like; CA() is the pool to
// give egress as Config.RootCAs when the catcher offers TLS.
package mailtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// Received is one accepted message.
type Received struct {
	From string
	To   []string
	Data []byte
	TLS  bool // the message arrived over TLS
}

// Mode is how the catcher offers TLS.
type Mode int

const (
	// Plain offers no TLS.
	Plain Mode = iota
	// STARTTLS advertises STARTTLS and upgrades on request.
	STARTTLS
	// Implicit speaks TLS from the first byte.
	Implicit
	// StrippedSTARTTLS pretends to be a STARTTLS server whose advertisement was removed by a
	// middlebox: it offers nothing.
	StrippedSTARTTLS
)

// Server is a running catcher. Create it with Start.
type Server struct {
	ln   net.Listener
	mode Mode
	cfg  *tls.Config
	pool *x509.CertPool

	mu        sync.Mutex
	msgs      []Received
	rcptCode  map[string]int // recipient address (lower case) -> reply code to RCPT
	dataCode  map[string]int // recipient address -> reply code after DATA
	down      bool           // refuse every connection
	conns     int
	rcptSeen  []string
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// Start runs a catcher on 127.0.0.1 and stops it when the test ends.
func Start(t testing.TB, mode Mode) *Server {
	t.Helper()
	cert, pool := selfSigned(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{ln: ln, mode: mode, pool: pool, rcptCode: map[string]int{}, dataCode: map[string]int{},
		cfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// Host is the host name a Relay should use. It is the IP literal the certificate names.
func (s *Server) Host() string { return "127.0.0.1" }

// Port is the listening port.
func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

// CA is the pool that verifies the catcher's certificate.
func (s *Server) CA() *x509.CertPool { return s.pool }

// Loopback is the egress allow-list entry that makes the catcher reachable.
func Loopback() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} }

// Messages returns the accepted messages, oldest first.
func (s *Server) Messages() []Received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Received(nil), s.msgs...)
}

// Connections is how many connections were accepted.
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

// RcptAttempts lists every RCPT TO address the catcher was given, accepted or not.
func (s *Server) RcptAttempts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.rcptSeen...)
}

// RejectRcpt makes RCPT TO for addr answer with code (for example 550 or 451).
func (s *Server) RejectRcpt(addr string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rcptCode[strings.ToLower(addr)] = code
}

// RejectData makes the end of DATA for a message to addr answer with code instead of 250.
func (s *Server) RejectData(addr string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dataCode[strings.ToLower(addr)] = code
}

// Down closes every new connection at once, like a relay that is not answering.
func (s *Server) Down(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = v
}

// Close stops the catcher.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		_ = s.ln.Close()
		s.wg.Wait()
	})
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		down := s.down
		s.conns++
		s.mu.Unlock()
		if down {
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.session(c)
		}()
	}
}

func (s *Server) session(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	isTLS := false
	if s.mode == Implicit {
		tc := tls.Server(c, s.cfg)
		if tc.Handshake() != nil {
			return
		}
		c, isTLS = tc, true
	}
	tp := textproto.NewConn(c)
	say := func(f string, a ...any) { _ = tp.PrintfLine(f, a...) }
	say("220 mailtest ESMTP")
	var from string
	var to []string
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			if s.mode == STARTTLS && !isTLS {
				say("250-mailtest")
				say("250 STARTTLS")
			} else {
				say("250 mailtest")
			}
		case "STARTTLS":
			if s.mode != STARTTLS || isTLS {
				say("502 not offered")
				continue
			}
			say("220 ready")
			tc := tls.Server(c, s.cfg)
			if tc.Handshake() != nil {
				return
			}
			c, isTLS = tc, true
			tp = textproto.NewConn(c)
			say = func(f string, a ...any) { _ = tp.PrintfLine(f, a...) }
			from, to = "", nil
		case "MAIL":
			from = addrOf(arg)
			to = nil
			say("250 ok")
		case "RCPT":
			a := addrOf(arg)
			s.mu.Lock()
			s.rcptSeen = append(s.rcptSeen, a)
			code := s.rcptCode[strings.ToLower(a)]
			s.mu.Unlock()
			if code != 0 {
				say("%d rejected", code)
				continue
			}
			to = append(to, a)
			say("250 ok")
		case "DATA":
			if len(to) == 0 {
				say("503 no recipients")
				continue
			}
			say("354 go ahead")
			body, err := io.ReadAll(tp.DotReader())
			if err != nil {
				return
			}
			s.mu.Lock()
			code := 0
			for _, r := range to {
				if c := s.dataCode[strings.ToLower(r)]; c != 0 {
					code = c
				}
			}
			if code == 0 {
				s.msgs = append(s.msgs, Received{From: from, To: append([]string(nil), to...), Data: body, TLS: isTLS})
			}
			s.mu.Unlock()
			if code != 0 {
				say("%d not accepted", code)
			} else {
				say("250 queued")
			}
			from, to = "", nil
		case "RSET":
			from, to = "", nil
			say("250 ok")
		case "NOOP":
			say("250 ok")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("500 unknown command")
		}
	}
}

// addrOf extracts the address from "FROM:<a@b>" or "TO:<a@b> PARAM".
func addrOf(arg string) string {
	i, j := strings.IndexByte(arg, '<'), strings.IndexByte(arg, '>')
	if i < 0 || j < i {
		return ""
	}
	return arg[i+1 : j]
}

func selfSigned(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mailtest"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
