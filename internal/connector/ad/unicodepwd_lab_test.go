//go:build lab

// unicodePwd vectors PW-04, PW-14 and PW-09 (cap) against a real DC (T-0074).
// Spec: knowledge/development/architecture/safe-primitives.md §"Password vectors".
//
// The product has no unicodePwd encoder yet, so these tests use a test-owned reference encoder
// (quoted UTF-16LE per MS-ADTS 3.1.1.3.1.5.2) and raw go-ldap over LDAPS. They pin what the DC does
// with the bytes the spec says the product will send; the product encoder must later produce
// exactly these bytes (asserted below against the spec table).
//
// Samba:   make lab-up && make lab-test-connector              (TestLabUnicodePwd*)
// Windows: make lab-test-connector-windows                      (TestWindowsLabUnicodePwd*)
package ad

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// encodeUnicodePwd is the test-side reference: `"` + pw + `"` as UTF-16LE. Nothing is stripped or escaped.
func encodeUnicodePwd(pw string) []byte {
	u := utf16.Encode([]rune(`"` + pw + `"`))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// pwTarget is one DC the vectors run against.
type pwTarget struct {
	label      string // "samba" or "windows"
	addr       string // host:636
	serverName string // certificate name; "" = host
	roots      *x509.CertPool
	adminBind  string
	adminPW    string
	base       string // DC=...
	upnSuffix  string
	// acceptsOverCap is a documented DC divergence: Samba stores a 257-unit password where Windows
	// refuses it, so the product cap (not the DC) must be what rejects PW-09.
	acceptsOverCap bool
}

func (g pwTarget) dial(t *testing.T) *ldap.Conn {
	t.Helper()
	host := g.serverName
	c, err := ldap.DialURL("ldaps://"+g.addr, ldap.DialWithTLSConfig(&tls.Config{RootCAs: g.roots, ServerName: host, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatalf("%s: dial LDAPS: %v", g.label, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// newUser (re)creates a disabled user, returning its DN and UPN. The user is deleted on cleanup.
func (g pwTarget) newUser(t *testing.T, admin *ldap.Conn, sam string) (dn, upn string) {
	t.Helper()
	dn = "CN=" + sam + ",CN=Users," + g.base
	upn = sam + "@" + g.upnSuffix
	_ = admin.Del(ldap.NewDelRequest(dn, nil))
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{sam})
	add.Attribute("userPrincipalName", []string{upn})
	if err := admin.Add(add); err != nil {
		t.Fatalf("%s: create %s: %v", g.label, sam, err)
	}
	t.Cleanup(func() { _ = admin.Del(ldap.NewDelRequest(dn, nil)) })
	return dn, upn
}

// setPwd issues the unicodePwd Replace with exactly raw and returns the LDAP result code (0 = success).
func setPwd(admin *ldap.Conn, dn string, raw []byte) (code uint16, err error) {
	m := ldap.NewModifyRequest(dn, nil)
	m.Replace("unicodePwd", []string{string(raw)})
	err = admin.Modify(m)
	if err == nil {
		return 0, nil
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		return uint16(le.ResultCode), err
	}
	return 0xFFFF, err
}

// enable clears ACCOUNTDISABLE (512 = NORMAL_ACCOUNT) so the user can bind.
func enable(t *testing.T, admin *ldap.Conn, dn string) {
	t.Helper()
	m := ldap.NewModifyRequest(dn, nil)
	m.Replace("userAccountControl", []string{"512"})
	if err := admin.Modify(m); err != nil {
		t.Fatalf("enable %s: %v", dn, err)
	}
}

// canBind reports whether upn+pw binds over a fresh LDAPS connection.
func (g pwTarget) canBind(t *testing.T, upn, pw string) bool {
	t.Helper()
	c := g.dial(t)
	return c.Bind(upn, pw) == nil
}

// repeatTo returns a policy-compliant password of exactly n UTF-16 code units (ASCII).
func repeatTo(n int) string {
	const unit = "Aa1!"
	return strings.Repeat(unit, n/len(unit)) + unit[:n%len(unit)]
}

// runUnicodePwdVectors is the shared body for both labs.
func runUnicodePwdVectors(t *testing.T, g pwTarget) {
	admin := g.dial(t)
	if err := admin.Bind(g.adminBind, g.adminPW); err != nil {
		t.Fatalf("%s: admin bind: %v", g.label, err)
	}

	// The spec byte tables: the reference encoder (and so the future product encoder) must match.
	t.Run("encoding bytes match spec table", func(t *testing.T) {
		for _, c := range []struct{ id, pw, hex string }{
			{"PW-04", `a"b`, "2200610022006200 2200"},
			{"PW-14", `"abc"`, "22002200610062006300220022 00"},
		} {
			want := strings.ReplaceAll(c.hex, " ", "")
			if got := fmt.Sprintf("%x", encodeUnicodePwd(c.pw)); got != want {
				t.Errorf("%s: encoded %s, spec %s", c.id, got, want)
			}
		}
	})

	// A DC enforces its password policy before any vector can be judged, so each quote vector runs
	// twice: the literal spec password (policy may refuse it: recorded, and it must be a policy
	// refusal, not a parse error) and a policy-compliant password with the same quote shape, which
	// is what proves "inner quotes are data".
	vectors := []struct {
		id, literal, compliant string
		stripped               []string // what a wrong implementation would have set
	}{
		{"PW-04", `a"b`, `Zq"7-Lm2xWvB9!k`, []string{`Zq7-Lm2xWvB9!k`, `Zq`}},
		{"PW-14", `"abc"`, `"Zq7-Lm2xWvB9!k"`, []string{`Zq7-Lm2xWvB9!k`}},
	}
	for i, v := range vectors {
		v := v
		t.Run(v.id+" literal vector", func(t *testing.T) {
			dn, upn := g.newUser(t, admin, fmt.Sprintf("pwv%02dl", i))
			code, err := setPwd(admin, dn, encodeUnicodePwd(v.literal))
			t.Logf("RESULT %s %s literal %q: ldap code %d err=%v", g.label, v.id, v.literal, code, err)
			switch code {
			case 0: // policy allows it: it must be exactly that password
				enable(t, admin, dn)
				if !g.canBind(t, upn, v.literal) {
					t.Errorf("DC accepted the modify but bind with %q fails: quotes were mis-parsed", v.literal)
				}
			case ldap.LDAPResultConstraintViolation, ldap.LDAPResultUnwillingToPerform:
				t.Logf("DC refused the literal vector on password policy (code %d); quote semantics proven by the compliant variant", code)
			default:
				t.Errorf("literal vector %q: unexpected result %d: %v (a parse failure would not look like a policy refusal)", v.literal, code, err)
			}
		})
		t.Run(v.id+" compliant variant sets the exact password", func(t *testing.T) {
			dn, upn := g.newUser(t, admin, fmt.Sprintf("pwv%02dc", i))
			code, err := setPwd(admin, dn, encodeUnicodePwd(v.compliant))
			t.Logf("RESULT %s %s compliant %q: ldap code %d err=%v", g.label, v.id, v.compliant, code, err)
			if code != 0 {
				t.Fatalf("DC refused a policy-compliant password with embedded quotes: %d %v", code, err)
			}
			enable(t, admin, dn)
			if !g.canBind(t, upn, v.compliant) {
				t.Errorf("bind with the intended password %q fails: DC stored something else", v.compliant)
			}
			for _, w := range v.stripped {
				if g.canBind(t, upn, w) {
					t.Errorf("bind with %q succeeds: quotes were stripped or truncated by the DC", w)
				}
			}
		})
	}

	// PW-09: the product cap is 256 UTF-16 code units, provisional against the Windows maximum.
	for _, n := range []int{256, 257} {
		n := n
		t.Run(fmt.Sprintf("PW-09 %d code units", n), func(t *testing.T) {
			dn, upn := g.newUser(t, admin, fmt.Sprintf("pwv09n%d", n))
			pw := repeatTo(n)
			code, err := setPwd(admin, dn, encodeUnicodePwd(pw))
			t.Logf("RESULT %s PW-09 %d units: ldap code %d err=%v", g.label, n, code, err)
			if n == 256 {
				if code != 0 {
					t.Fatalf("256 units refused by the DC (%d %v): cap of 256 is too high for this DC", code, err)
				}
				enable(t, admin, dn)
				if !g.canBind(t, upn, pw) {
					t.Errorf("256-unit password set but bind fails")
				}
				return
			}
			switch {
			case g.acceptsOverCap && code != 0:
				t.Errorf("divergence closed? %s now refuses 257 units (%d %v): drop acceptsOverCap", g.label, code, err)
			case !g.acceptsOverCap && code == 0:
				t.Errorf("DC accepted 257 units: the cap of 256 is stricter than this DC; spec/provisional cap needs an M2 ticket")
			}
		})
	}
}
