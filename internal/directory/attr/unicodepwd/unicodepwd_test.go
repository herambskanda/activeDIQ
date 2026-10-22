package unicodepwd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
	"github.com/skenzeriq/activediq/internal/platform/corpus/corpustest"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/secret/secretjson"
)

const dcName = "dc1.corp.example.com"

// body is the shape the DecodeSecretBody records decode into: a Secret and a nested copy of itself.
type body struct {
	Password secret.Secret `json:"password"`
	Nested   *body         `json:"nested"`
}

func (b *body) destroy() {
	for p := b; p != nil; p = p.Nested {
		p.Password.Destroy()
	}
}

// reveal is test-only: it turns a Secret into text to compare with the corpus.
func reveal(s secret.Secret) (out string) {
	s.Expose(func(b []byte) { out = string(b) })
	return out
}

func (b *body) value() any {
	m := map[string]any{"password": reveal(b.Password), "nested": nil}
	if b.Nested != nil {
		m["nested"] = b.Nested.value()
	}
	return m
}

// code names a failure by the stable codes the corpus uses. Typed errors win; the decoder's own
// refusals (duplicate or unknown member, wrong type, syntax) are classified by what they are.
func code(err error) string {
	if c := Code(err); c != "" {
		return c
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "duplicate object member"):
		return "DuplicateMember"
	case strings.Contains(msg, "unknown object member"):
		return "UnknownMember"
	case strings.Contains(msg, "invalid UTF-8"):
		return "InvalidUTF8"
	case strings.Contains(msg, "invalid surrogate pair"):
		return "InvalidUTF16"
	}
	var syn *jsontext.SyntacticError
	if errors.As(err, &syn) {
		return "MalformedJSON"
	}
	var sem *jsonv2.SemanticError
	if errors.As(err, &sem) {
		return "WrongType"
	}
	return "Other"
}

func testSecret(r corpus.Record) (secret.Secret, error) {
	in, err := r.Arg("password")
	if err != nil {
		return secret.Secret{}, err
	}
	return secret.FromBytes(in.Raw), nil
}

func TestCorpus(t *testing.T) {
	corpustest.Run(t, "go/attr-unicodepwd", "attr.unicodepwd", func(r corpus.Record) (corpus.Result, error) {
		switch r.Call {
		case "DecodeSecretBody":
			in, err := r.Arg("body")
			if err != nil {
				return corpus.Result{}, err
			}
			var v body
			defer v.destroy()
			if err := secretjson.Decode(in.Raw, &v); err != nil {
				return corpustest.Err(code(err)), nil
			}
			return corpustest.Value(v.value())
		case "Encode":
			s, err := testSecret(r)
			if err != nil {
				return corpus.Result{}, err
			}
			defer s.Destroy()
			b, err := Encode(s)
			if err != nil {
				return corpustest.Err(code(err)), nil
			}
			return corpustest.BytesHex(b), nil
		case "ReplaceOnPlainConnection":
			s, err := testSecret(r)
			if err != nil {
				return corpus.Result{}, err
			}
			m, err := Replace(s, SecureConn{}) // no proof: the connection is plain 389
			if err != nil {
				return corpustest.Err(code(err)), nil
			}
			m.Destroy()
			return corpustest.Render("a modify was built"), nil
		case "ReplaceAfterReconnect":
			s, err := testSecret(r)
			if err != nil {
				return corpus.Result{}, err
			}
			link := newLink(t, dcName, dcName)
			conn, err := Acquire(link, dcName)
			if err != nil {
				return corpus.Result{}, err
			}
			link.gen.Add(1) // the connection dropped and came back
			m, err := Replace(s, conn)
			if err != nil {
				return corpustest.Err(code(err)), nil
			}
			m.Destroy()
			return corpustest.Render("a modify was built"), nil
		case "Redact":
			return redact(t, r)
		case "MarshalJSON", "MarshalBinary":
			s, err := testSecret(r)
			if err != nil {
				return corpus.Result{}, err
			}
			var merr error
			if r.Call == "MarshalJSON" {
				_, merr = jsonv2.Marshal(struct{ P secret.Secret }{s})
				if _, err := json.Marshal(struct{ P secret.Secret }{s}); err == nil { // v1 too
					return corpus.Result{}, errors.New("v1 encoding/json serialised a Secret")
				}
			} else {
				_, merr = s.MarshalBinary()
			}
			if merr == nil {
				return corpustest.Render("serialised"), nil
			}
			return corpustest.Err(code(merr)), nil
		case "ClassifyResult":
			c, err := r.Arg("code")
			if err != nil {
				return corpus.Result{}, err
			}
			d, err := r.Arg("diagnostic")
			if err != nil {
				return corpus.Result{}, err
			}
			n, err := strconv.Atoi(c.Text())
			if err != nil {
				return corpus.Result{}, err
			}
			if err := ClassifyResult(n, d.Text()); err != nil {
				return corpustest.Err(code(err)), nil
			}
			return corpustest.Render("not a policy violation"), nil
		case "AcquireTLS":
			c, err := r.Arg("case")
			if err != nil {
				return corpus.Result{}, err
			}
			return acquireTLS(t, c.Text())
		}
		return corpus.Result{}, corpustest.Skip("unknown call " + r.Call)
	})
}

func redact(t testing.TB, r corpus.Record) (corpus.Result, error) {
	s, err := testSecret(r)
	if err != nil {
		return corpus.Result{}, err
	}
	how, err := r.Arg("how")
	if err != nil {
		return corpus.Result{}, err
	}
	var out string
	switch how.Text() {
	case "format":
		out = fmt.Sprintf("%v", s)
	case "format+v":
		out = fmt.Sprintf("%+v", struct{ P secret.Secret }{s})
	case "format#v":
		out = fmt.Sprintf("%#v", s)
	case "log":
		var buf bytes.Buffer
		slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey || a.Key == slog.LevelKey || a.Key == slog.MessageKey {
				return slog.Attr{}
			}
			return a
		}})).Info("m", "p", s)
		out = strings.TrimSpace(strings.TrimPrefix(buf.String(), "p="))
	case "error":
		out = fmt.Errorf("set failed: %w", errors.New(fmt.Sprint(s))).Error()
		out = strings.TrimPrefix(out, "set failed: ")
	case "nested-private", "pointer", "slog-json", "modify-replace", "modify-change", "modify-value", "modify-private", "modification-private", "modification-mods", "modify-exported":
		return redactNested(t, how.Text(), s)
	default:
		return corpus.Result{}, errors.New("unknown how " + how.Text())
	}
	if strings.Contains(out, reveal(s)) {
		return corpus.Result{}, errors.New("the secret leaked")
	}
	if how.Text() == "format+v" {
		out = strings.TrimSuffix(strings.TrimPrefix(out, "{P:"), "}")
	}
	return corpustest.Render(out), nil
}

type holder struct {
	User string
	pw   secret.Secret
}

type modHolder struct {
	User string
	m    Modify
}

type modEntryHolder struct {
	User string
	mod  Modification
}

type exportedModHolder struct {
	User string
	Req  Modify
}

// redactNested renders the secret through the paths that bypass Format: an unexported field, a
// pointer, the slog JSON handler, JSON marshalling and an encoded Modify. None of them may show the
// bytes of the password or of its UTF-16LE encoding, as text, hex, base64 or a decimal byte list.
func redactNested(t testing.TB, how string, s secret.Secret) (corpus.Result, error) {
	var subject any
	switch how {
	case "nested-private":
		subject = holder{"bob", s}
	case "pointer":
		subject = &holder{"bob", s}
	case "slog-json":
		subject = holder{"bob", s}
	default:
		conn, err := Acquire(newLink(t, dcName, dcName), dcName)
		if err != nil {
			return corpus.Result{}, err
		}
		var m *Modify
		if strings.HasSuffix(how, "replace") {
			m, err = Replace(s, conn)
		} else {
			m, err = Change(s, s, conn)
		}
		if err != nil {
			return corpus.Result{}, err
		}
		defer m.Destroy()
		switch how {
		case "modify-replace", "modify-change":
			subject = m
		case "modify-value":
			subject = *m
		case "modify-private":
			subject = modHolder{"bob", *m}
		case "modification-private":
			subject = modEntryHolder{"bob", m.Mods[0]}
		case "modification-mods":
			subject = m.Mods
		case "modify-exported":
			subject = exportedModHolder{"bob", *m}
		default:
			return corpus.Result{}, errors.New("unknown how " + how)
		}
	}
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d"} {
		outs = append(outs, fmt.Sprintf(verb, subject))
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "r", subject)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "r", subject)
	outs = append(outs, buf.String())
	// Serialisation either fails or carries nothing of the value.
	if j, err := json.Marshal(subject); err == nil {
		outs = append(outs, string(j))
	}
	if j, err := jsonv2.Marshal(subject); err == nil {
		outs = append(outs, string(j))
	}
	pw := reveal(s)
	enc, err := Encode(s)
	if err != nil {
		return corpus.Result{}, err
	}
	needles := []string{pw, hex.EncodeToString([]byte(pw)), fmt.Sprint([]byte(pw)),
		hex.EncodeToString(enc), fmt.Sprint(enc), base64.StdEncoding.EncodeToString(enc), base64.RawStdEncoding.EncodeToString(enc)}
	for _, o := range outs {
		for _, n := range needles {
			if strings.Contains(o, n) {
				return corpus.Result{}, errors.New("the secret leaked: " + how + " in " + o)
			}
		}
	}
	return corpustest.Render("no secret bytes in any rendering"), nil
}

// --- TLS fixtures for PW-17 and PW-18 -------------------------------------------------------

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t testing.TB, cn string) ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return ca{c, key}
}

func (a ca) leaf(t testing.TB, dns string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dns}, DNSNames: []string{dns},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// link is a Link over a real TLS connection.
type link struct {
	conn *tls.Conn
	gen  atomic.Uint64
}

func (l *link) Generation() uint64 { return l.gen.Load() }
func (l *link) ConnectionState() (tls.ConnectionState, bool) {
	return l.conn.ConnectionState(), true
}

// dial starts a TLS server presenting leafFor's certificate and dials it as the connector would:
// verification on, the trust anchors given, the server name the DC's FQDN.
func dial(t testing.TB, serverCA ca, certName string, trustCA ca, fqdn string) (*tls.Conn, error) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{serverCA.leaf(t, certName)}, MinVersion: tls.VersionTLS12})
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
			go func() { _ = c.(*tls.Conn).Handshake(); time.Sleep(time.Second); c.Close() }()
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(trustCA.cert)
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{RootCAs: pool, ServerName: fqdn, MinVersion: tls.VersionTLS12}}
	c, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { c.Close() })
	return c.(*tls.Conn), nil
}

func newLink(t testing.TB, certName, fqdn string) *link {
	t.Helper()
	root := newCA(t, "lab root")
	c, err := dial(t, root, certName, root, fqdn)
	if err != nil {
		t.Fatal(err)
	}
	return &link{conn: c}
}

func acquireTLS(t testing.TB, name string) (corpus.Result, error) {
	root := newCA(t, "lab root")
	var err error
	switch name {
	case "certificate-names-another-host":
		_, err = dial(t, root, "dc2.corp.example.com", root, dcName)
	case "chain-to-no-trust-anchor":
		_, err = dial(t, newCA(t, "rogue"), dcName, root, dcName)
	default:
		return corpus.Result{}, errors.New("unknown case " + name)
	}
	if err == nil {
		return corpustest.Render("handshake succeeded"), nil
	}
	return corpustest.Err(code(ClassifyHandshake(err))), nil
}

func TestAcquireVerifiesAgainstTheFQDN(t *testing.T) {
	l := newLink(t, dcName, dcName)
	conn, err := Acquire(l, dcName)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Verify(); err != nil {
		t.Fatalf("Verify = %v", err)
	}
	// The inventory names another host than the one the certificate is for: refused although the
	// handshake itself verified.
	if _, err := Acquire(l, "dc9.corp.example.com"); Code(err) != TLSVerificationFailed {
		t.Fatalf("Acquire for another FQDN = %v", err)
	}
	if _, err := Acquire(nil, dcName); Code(err) != EncryptionRequired {
		t.Fatalf("Acquire(nil) = %v", err)
	}
	l.gen.Add(1)
	if err := conn.Verify(); Code(err) != SecureConnStale {
		t.Fatalf("Verify after reconnect = %v", err)
	}
	// Re-deriving on the new generation works again.
	if _, err := Acquire(l, dcName); err != nil {
		t.Fatal(err)
	}
}

// A non-TLS link, and a link whose state is unverified, never yield a SecureConn.
type fakeLink struct {
	st tls.ConnectionState
	ok bool
}

func (f fakeLink) Generation() uint64                           { return 1 }
func (f fakeLink) ConnectionState() (tls.ConnectionState, bool) { return f.st, f.ok }

func TestAcquireRefusesWeakStates(t *testing.T) {
	if _, err := Acquire(fakeLink{}, dcName); Code(err) != EncryptionRequired {
		t.Fatalf("plain: %v", err)
	}
	if _, err := Acquire(fakeLink{ok: true, st: tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS12}}, dcName); Code(err) != TLSVerificationFailed {
		t.Fatalf("unverified chain: %v", err)
	}
	if _, err := Acquire(fakeLink{ok: true, st: tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS11}}, dcName); Code(err) != TLSVerificationFailed {
		t.Fatalf("TLS 1.1: %v", err)
	}
}

func TestClassifyHandshakePassesOtherErrors(t *testing.T) {
	e := errors.New("connection refused")
	if ClassifyHandshake(e) != e || ClassifyHandshake(nil) != nil {
		t.Fatal("non-certificate errors must pass through")
	}
}

// --- codec behaviour beyond the corpus ------------------------------------------------------

func TestBoundary256Units(t *testing.T) {
	for name, pw := range map[string]string{"256 BMP": strings.Repeat("a", 256), "128 astral": strings.Repeat("😀", 128)} {
		s := secret.FromBytes([]byte(pw))
		b, err := Encode(s)
		if err != nil || len(b) != 2*(256+2) {
			t.Errorf("%s: len %d err %v", name, len(b), err)
		}
	}
}

func TestChangeIsOneModifyDeleteThenAdd(t *testing.T) {
	l := newLink(t, dcName, dcName)
	conn, _ := Acquire(l, dcName)
	m, err := Change(secret.FromBytes([]byte("old")), secret.FromBytes([]byte("new")), conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Mods) != 2 || m.Mods[0].Op != OpDelete || m.Mods[1].Op != OpAdd || m.Mods[0].Attr != Attribute {
		t.Fatalf("mods = %+v", m.Mods)
	}
	m.Mods[1].Expose(func(v [][]byte) {
		if len(v) != 1 || !bytes.Equal(v[0], utf16le(`"new"`)) {
			t.Fatalf("add value = %x", v)
		}
	})
	var vals []byte
	m.Mods[0].Expose(func(v [][]byte) { vals = v[0] })
	m.Destroy()
	if !bytes.Equal(vals, make([]byte, len(vals))) {
		t.Fatal("Destroy did not zero the value")
	}
	// A bad new password sends nothing and leaves no half-built delete.
	if m, err := Change(secret.FromBytes([]byte("old")), secret.Secret{}, conn); m != nil || Code(err) != secret.EmptySecret {
		t.Fatalf("Change(old, empty) = %v, %v", m, err)
	}
	l.gen.Add(1)
	if _, err := Change(secret.FromBytes([]byte("old")), secret.FromBytes([]byte("new")), conn); Code(err) != SecureConnStale {
		t.Fatalf("Change on a stale conn = %v", err)
	}
}

func TestPolicyViolationCarriesOnlyTheDCDiagnostic(t *testing.T) {
	err := ClassifyResult(19, "0000052D: SvcErr\r\n\x00 DSID-1, data 0")
	if Code(err) != PolicyViolation || !strings.Contains(err.Error(), "0000052D: SvcErr") || strings.ContainsAny(err.Error(), "\r\n\x00") {
		t.Fatalf("err = %q", err)
	}
	if ClassifyResult(19, "some other diagnostic") != nil || ClassifyResult(50, "0000052D") != nil || ClassifyResult(0, "0000052D") != nil {
		t.Fatal("only 19/53 with 0000052D is a policy violation")
	}
	if got := ClassifyResult(53, "0000052d: "+strings.Repeat("x", 1000)); len(got.Error()) > 300 {
		t.Fatalf("diagnostic not capped: %d bytes", len(got.Error()))
	}
}

// Secret behaviour: comparison, Destroy, zero value.
func TestSecretBasics(t *testing.T) {
	a, b := secret.FromBytes([]byte("abc")), secret.FromBytes([]byte("abc"))
	if !a.Equal(b) || a.Equal(secret.FromBytes([]byte("abd"))) || a.Equal(secret.FromBytes([]byte("ab"))) {
		t.Fatal("Equal")
	}
	var seen []byte
	a.Expose(func(x []byte) { seen = x })
	a.Destroy()
	if !a.IsEmpty() || !bytes.Equal(seen, make([]byte, 3)) {
		t.Fatalf("Destroy left %x", seen)
	}
}

// The JSON path unescapes into a fresh buffer, handles every escape and reaches Secret from a
// Secret-bearing struct through secretjson.Decode.
func TestSecretJSONEscapes(t *testing.T) {
	var v body
	defer v.destroy()
	if err := secretjson.Decode([]byte(`{"password":"a\"\\\/\b\f\n\r\tä😀z"}`), &v); err != nil {
		t.Fatal(err)
	}
	if got, want := reveal(v.Password), "a\"\\/\b\f\n\r\tä😀z"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	var n body
	if err := secretjson.Decode([]byte(`{"password":null}`), &n); err != nil || !n.Password.IsEmpty() {
		t.Fatalf("null: %v", err)
	}
}

// Error text from a refused body never contains the offending escape or any of the password.
func TestSecretJSONErrorsDoNotQuoteTheValue(t *testing.T) {
	for _, in := range []string{`{"password":"hunter2\ud800x"}`, `{"password":"hunter2\u0000"}`, "{\"password\":\"hunter2\xff\"}", `{"password":"hunter2`} {
		var v body
		err := secretjson.Decode([]byte(in), &v)
		if err == nil {
			t.Fatalf("%q decoded", in)
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("error quotes the secret: %v", err)
		}
	}
}

// PW-12: no production code switches the LDAP library's packet debug on.
func TestNoLDAPDebug(t *testing.T) {
	root, err := corpus.FindRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Dir(filepath.Dir(root))
	_ = filepath.WalkDir(repo, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "web" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil
		}
		usesLDAP := false
		for _, im := range f.Imports {
			usesLDAP = usesLDAP || strings.Contains(im.Path.Value, "go-ldap/ldap")
		}
		if !usesLDAP {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok && s.Sel.Name == "Debug" {
				t.Errorf("%s: a .Debug switch on a connection in production code (PW-12)", p)
			}
			return true
		})
		return nil
	})
}

func utf16le(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func FuzzUnicodePwd(f *testing.F) {
	corpustest.Seed(f, "attr.unicodepwd")
	f.Fuzz(func(t *testing.T, in []byte) {
		// Encode: what encodes decodes (by the standard library, independently) to '"' + pw + '"'.
		if b, err := Encode(secret.FromBytes(in)); err == nil {
			if len(b)%2 != 0 || len(b) < 4 || !utf8.Valid(in) || bytes.IndexByte(in, 0) >= 0 {
				t.Fatalf("Encode accepted %q -> %x", in, b)
			}
			units := make([]uint16, len(b)/2)
			for i := range units {
				units[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
			}
			if got, want := string(utf16.Decode(units)), `"`+string(in)+`"`; got != want {
				t.Fatalf("roundtrip: %q != %q", got, want)
			}
			// noUnescapedSpecial: the only quote units are the two the codec added around the
			// password's own data; no unpaired surrogate unit is left.
			if units[0] != '"' || units[len(units)-1] != '"' {
				t.Fatalf("value not quoted: %x", b)
			}
			corpustest.NoUnescapedSpecial(t, string(in), "\x00")
		}
		// Decode: a body that decodes holds well-formed, NUL-free text, and what we re-encode as a
		// JSON string decodes to the same bytes.
		var v body
		defer v.destroy()
		if err := secretjson.Decode(in, &v); err != nil {
			if code(err) == "Other" {
				t.Fatalf("unclassified decode error: %v", err)
			}
			return
		}
		for p := &v; p != nil; p = p.Nested {
			p.Password.Expose(func(pw []byte) {
				if !utf8.Valid(pw) || bytes.IndexByte(pw, 0) >= 0 {
					t.Fatalf("decoded password is not well-formed text: %q", pw)
				}
				out, err := json.Marshal(string(pw))
				if err != nil {
					t.Fatal(err)
				}
				corpustest.NoUnescapedSpecial(t, string(out), "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f")
				var again body
				defer again.destroy()
				if err := secretjson.Decode([]byte(`{"password":`+string(out)+`}`), &again); err != nil || !again.Password.Equal(secret.FromBytes(pw)) {
					t.Fatalf("JSON roundtrip of %q: %v", pw, err)
				}
			})
		}
	})
}

func TestEqualEmptyAuthenticatesNothing(t *testing.T) {
	var a, b secret.Secret
	if a.Equal(b) || a.Equal(secret.FromBytes([]byte("x"))) {
		t.Fatal("an empty Secret must equal nothing")
	}
}

// The Modify re-checks its connection at send time (PW-17).
func TestModifyVerifiesAtSendTime(t *testing.T) {
	link := newLink(t, dcName, dcName)
	conn, err := Acquire(link, dcName)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Replace(secret.FromBytes([]byte("Pa55word!")), conn)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Destroy()
	if err := m.Verify(); err != nil {
		t.Fatalf("fresh Modify: %v", err)
	}
	link.gen.Add(1)
	if got := code(m.Verify()); got != SecureConnStale {
		t.Fatalf("after reconnect: %q", got)
	}
}
