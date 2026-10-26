package ad

// Test-only LDAP fault proxy (T-0309). Samba cannot create referral objects, so LF-32 / CC-SRCH-10
// cannot be provoked by data. The proxy sits between the connector and a directory, relays every
// LDAP message untouched, and injects a SearchResultReference (RFC 4511 §4.5.3) into the scoped
// searches it is told to. It is failure injection, not a directory: it lives only in _test files and
// is never imported by product code.
//
// Two upstreams: fakeUpstream (a minimal in-process LDAP responder, runs everywhere) and the Samba
// lab (ldapfault_lab_test.go, tag lab).

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
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	opBindReq    = 0
	opBindResp   = 1
	opUnbindReq  = 2
	opSearchReq  = 3
	opSearchEnt  = 4
	opSearchDone = 5
	opSearchRef  = 19
)

// injectPlan says when the proxy plants a continuation reference. Only searches whose base starts
// with "<GUID=" (the delegation-root form ScopedSearch uses) are touched, so Open's rootDSE and
// schema reads are relayed clean.
type injectPlan struct {
	afterEntries int      // reference goes in after this many entries (0 = before the first)
	urls         []string // the reference's LDAP URLs
	times        int      // how many scoped searches get it; 0 = every one
	skip         int      // scoped searches relayed clean before the first injection
}

type faultProxy struct {
	ln       net.Listener
	upstream func() (net.Conn, error)
	plan     injectPlan

	mu       sync.Mutex
	injected int
	searches int
}

func (p *faultProxy) Addr() string { return p.ln.Addr().String() }
func (p *faultProxy) Injected() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.injected
}

// startFaultProxy listens with TLS on loopback and returns the pool a Session must trust.
func startFaultProxy(t *testing.T, upstream func() (net.Conn, error), plan injectPlan) (*faultProxy, *x509.CertPool) {
	t.Helper()
	cert, pool := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	p := &faultProxy{ln: ln, upstream: upstream, plan: plan}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p, pool
}

func (p *faultProxy) serve(client net.Conn) {
	defer client.Close()
	up, err := p.upstream()
	if err != nil {
		return
	}
	defer up.Close()
	var mu sync.Mutex
	state := map[int64]int{} // messageID -> entries seen, for scoped searches only
	go func() {              // client -> upstream, verbatim
		defer up.Close()
		for {
			pkt, err := ber.ReadPacket(client)
			if err != nil {
				return
			}
			if id, op, base, ok := parseRequest(pkt); ok && op == opSearchReq && strings.HasPrefix(base, "<GUID=") {
				p.mu.Lock()
				p.searches++
				arm := p.searches > p.plan.skip && (p.plan.times == 0 || p.injected < p.plan.times)
				p.mu.Unlock()
				if arm {
					mu.Lock()
					state[id] = 0
					mu.Unlock()
				}
			}
			if _, err := up.Write(pkt.Bytes()); err != nil {
				return
			}
		}
	}()
	for { // upstream -> client, with injection
		pkt, err := ber.ReadPacket(up)
		if err != nil {
			return
		}
		id, op, _, ok := parseRequest(pkt)
		if ok {
			mu.Lock()
			n, armed := state[id]
			if armed && (op == opSearchDone || (op == opSearchEnt && n >= p.plan.afterEntries)) {
				delete(state, id)
				mu.Unlock()
				p.mu.Lock()
				p.injected++
				p.mu.Unlock()
				if _, err := client.Write(referenceMessage(id, p.plan.urls).Bytes()); err != nil {
					return
				}
			} else {
				if armed && op == opSearchEnt {
					state[id] = n + 1
				}
				mu.Unlock()
			}
		}
		if _, err := client.Write(pkt.Bytes()); err != nil {
			return
		}
	}
}

// parseRequest returns messageID, the protocolOp tag and (for a search request) the base DN.
func parseRequest(pkt *ber.Packet) (id int64, op int, base string, ok bool) {
	if len(pkt.Children) < 2 {
		return 0, 0, "", false
	}
	id, _ = pkt.Children[0].Value.(int64)
	body := pkt.Children[1]
	if body.ClassType != ber.ClassApplication {
		return 0, 0, "", false
	}
	op = int(body.Tag)
	if op == opSearchReq && len(body.Children) > 0 {
		base, _ = body.Children[0].Value.(string)
	}
	return id, op, base, true
}

func referenceMessage(id int64, urls []string) *ber.Packet {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	ref := ber.Encode(ber.ClassApplication, ber.TypeConstructed, opSearchRef, nil, "SearchResultReference")
	for _, u := range urls {
		ref.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, u, "URI"))
	}
	env.AppendChild(ref)
	return env
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fault-proxy"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// ---- fakeUpstream: the smallest LDAP responder Open and ScopedSearch need ------------------------

// fakeUpstream answers bind, the rootDSE and schema reads Open makes, and any "<GUID=...>" search
// with `entries` user entries. Everything else gets an empty, successful result.
type fakeUpstream struct {
	ln      net.Listener
	entries int
}

func startFakeUpstream(t *testing.T, entries int) *fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUpstream{ln: ln, entries: entries}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeUpstream) dial() (net.Conn, error) { return net.Dial("tcp", f.ln.Addr().String()) }

const fakeSchemaNC = "CN=Schema,CN=Configuration,DC=lab,DC=test"

func (f *fakeUpstream) serve(c net.Conn) {
	defer c.Close()
	for {
		pkt, err := ber.ReadPacket(c)
		if err != nil {
			return
		}
		id, op, base, ok := parseRequest(pkt)
		if !ok {
			return
		}
		var out []*ber.Packet
		switch op {
		case opUnbindReq:
			return
		case opBindReq:
			out = append(out, resultMsg(id, opBindResp))
		case opSearchReq:
			switch {
			case base == "":
				out = append(out, entryMsg(id, "", map[string][][]byte{
					"schemaNamingContext": {[]byte(fakeSchemaNC)}, "defaultNamingContext": {[]byte("DC=lab,DC=test")},
				}))
			case base == fakeSchemaNC: // the secret-flagged attribute Open insists on finding
				out = append(out, entryMsg(id, "CN=unicodePwd,"+fakeSchemaNC, map[string][][]byte{
					"lDAPDisplayName": {[]byte("unicodePwd")}, "attributeID": {[]byte("1.2.840.113556.1.4.90")},
				}))
			case strings.HasPrefix(base, "<GUID="):
				for i := 0; i < f.entries; i++ {
					g := make([]byte, 16)
					g[0], g[15] = 0xA0, byte(i+1)
					out = append(out, entryMsg(id, "CN=u"+string(rune('a'+i))+",OU=root,DC=lab,DC=test", map[string][][]byte{"objectGUID": {g}}))
				}
			}
			out = append(out, resultMsg(id, opSearchDone))
		default:
			return
		}
		for _, m := range out {
			if _, err := c.Write(m.Bytes()); err != nil {
				return
			}
		}
	}
}

func resultMsg(id int64, op int) *ber.Packet {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(op), nil, "Result")
	r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnostic"))
	env.AppendChild(r)
	return env
}

func entryMsg(id int64, dn string, attrs map[string][][]byte) *ber.Packet {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	e := ber.Encode(ber.ClassApplication, ber.TypeConstructed, opSearchEnt, nil, "Entry")
	e.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "objectName"))
	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for name, vals := range attrs {
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range vals {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v), "val"))
		}
		a.AppendChild(set)
		list.AppendChild(a)
	}
	e.AppendChild(list)
	env.AppendChild(e)
	return env
}

// honeypot is the "referred-to" server. A connector that chased the reference would connect to it;
// the tests assert it never accepts a connection.
type honeypot struct {
	ln   net.Listener
	mu   sync.Mutex
	hits int
}

func startHoneypot(t *testing.T) *honeypot {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &honeypot{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.hits++
			h.mu.Unlock()
			io.Copy(io.Discard, c) //nolint:errcheck
			c.Close()
		}
	}()
	return h
}

func (h *honeypot) Hits() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits
}
