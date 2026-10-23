package ad

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

func TestSDFlagsSACLNotConstructible(t *testing.T) {
	for _, bad := range []SDPart{0, 8, 16, 15, SDOwner | SDGroup, 0x80} {
		if _, err := NewSDFlags(bad); CodeOf(err) != CodeInvalidArgument {
			t.Errorf("NewSDFlags(%d) = %v, want INVALID_ARGUMENT", bad, err)
		}
	}
	if _, err := NewSDFlags(); err == nil {
		t.Error("empty selection accepted")
	}
	// Every constructible value is a subset of owner|group|DACL and never has the SACL bit.
	for mask := 0; mask < 1<<4; mask++ {
		var parts []SDPart
		for _, p := range []SDPart{SDOwner, SDGroup, SDDACL, 8} {
			if mask&int(p) != 0 {
				parts = append(parts, p)
			}
		}
		f, err := NewSDFlags(parts...)
		if err != nil {
			continue
		}
		if f.Value()&8 != 0 || f.Value()&^7 != 0 {
			t.Errorf("flags %d carries a bit outside owner/group/DACL", f.Value())
		}
	}
	if DefaultSDFlags().Value() != 7 {
		t.Errorf("default = %d, want 7", DefaultSDFlags().Value())
	}
}

func TestSDControlEncoding(t *testing.T) {
	c := DefaultSDFlags().control()
	if c == nil || c.GetControlType() != "1.2.840.113556.1.4.801" {
		t.Fatalf("control = %v", c)
	}
	// SEQUENCE { OID, OCTET STRING { SEQUENCE { INTEGER 7 } } }, not critical.
	got := c.Encode().Bytes()
	if !bytes.HasSuffix(got, []byte{0x04, 0x05, 0x30, 0x03, 0x02, 0x01, 0x07}) {
		t.Errorf("encoded control = % x", got)
	}
	if (SDFlags{}).control() != nil {
		t.Error("zero flags must send no control")
	}
}

func TestCredentialRedacted(t *testing.T) {
	c := Credential{BindName: "svc@x", Password: secret.FromBytes([]byte("hunter2"))}
	cfg := Config{Credential: c}
	s := &Session{cfg: cfg}
	var sb, tb bytes.Buffer
	slog.New(slog.NewJSONHandler(&sb, nil)).Info("x", "cred", c, "cfg", cfg)
	slog.New(slog.NewTextHandler(&tb, nil)).Info("x", "cred", c, "cfg", cfg)
	out := []string{sb.String(), tb.String()}
	for _, v := range []any{c, cfg, s, &cfg} {
		out = append(out, fmt.Sprint(v), fmt.Sprintf("%v %+v %#v", v, v, v))
		if j, err := json.Marshal(v); err == nil {
			out = append(out, string(j))
		}
	}
	for _, o := range out {
		if strings.Contains(o, "hunter2") {
			t.Errorf("credential leaked: %q", o)
		}
	}
}

func TestOpenDoesNotRetainPassword(t *testing.T) {
	// Open copies the credential out of the stored config before bind.
	s := &Session{cfg: Config{}}
	if !s.cfg.Credential.Password.IsEmpty() {
		t.Fatal("zero session holds a password")
	}
}

func TestSDControlIsCritical(t *testing.T) {
	p := DefaultSDFlags().control().Encode()
	if len(p.Children) != 3 {
		t.Fatalf("children = %d, want OID, criticality, value", len(p.Children))
	}
	if crit, ok := p.Children[1].Value.(bool); !ok || !crit {
		t.Errorf("criticality = %v, want TRUE", p.Children[1].Value)
	}
}

func TestSDHasSACL(t *testing.T) {
	withSACL := []byte{1, 0, 0x14, 0x90} // SE_SACL_PRESENT|SE_DACL_PRESENT|SE_SELF_RELATIVE low byte 0x14
	noSACL := []byte{1, 0, 0x04, 0x84}
	if !sdHasSACL(withSACL) || sdHasSACL(noSACL) || sdHasSACL(nil) {
		t.Error("sdHasSACL wrong")
	}
}

func TestAbsorbDropsUnrequestedAttributes(t *testing.T) {
	ent := newEntry("CN=x")
	pending := map[string]int{}
	asked := map[string]struct{}{"member": {}}
	raw := ldap.NewEntry("CN=x", map[string][]string{"foo;range=0-1": {"a"}, "member;range=0-1": {"m"}})
	absorbEntry(ent, pending, asked, raw)
	if _, ok := pending["foo"]; ok || len(ent.attrs["foo"]) != 0 {
		t.Error("unrequested attribute was kept or followed")
	}
	if pending["member"] != 2 {
		t.Errorf("pending = %v", pending)
	}
}

func TestWatchCancelAtCompletionRace(t *testing.T) {
	for i := 0; i < 200; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		a, b := net.Pipe()
		conn := ldap.NewConn(a, false)
		conn.Start()
		go io.Copy(io.Discard, b)
		s := &Session{conn: conn}
		stop := s.watch(ctx, conn)
		cancel()
		stop()
		go s.Close() // concurrent Close after the watcher has exited must not panic or race
		_ = s.Close()
		b.Close()
	}
}

func TestSplitRange(t *testing.T) {
	cases := []struct {
		in         string
		base       string
		lo, hi     int
		star, isOK bool
	}{
		{"member;range=0-1499", "member", 0, 1499, false, true},
		{"member;range=1500-*", "member", 1500, 0, true, true},
		{"Member;Range=0-*", "Member", 0, 0, true, true},
		{"member", "member", 0, 0, false, false},
		{"member;range=x-9", "member;range=x-9", 0, 0, false, false},
		{"member;range=9-3", "member;range=9-3", 0, 0, false, false},
	}
	for _, c := range cases {
		b, lo, hi, star, ok := splitRange(c.in)
		if b != c.base || lo != c.lo || hi != c.hi || star != c.star || ok != c.isOK {
			t.Errorf("splitRange(%q) = %q %d %d %v %v", c.in, b, lo, hi, star, ok)
		}
	}
}

func newOffline() *Session { return &Session{schema: DefaultSchema(), pageSize: 10} }

func TestAttributePolicy(t *testing.T) {
	s := newOffline()
	for _, n := range []string{"*", "+", "member;range=0-5", "x)(y", "", "1.1"} {
		if _, err := s.checkAttrs([]string{n}, true); CodeOf(err) != CodeInvalidArgument {
			t.Errorf("attribute %q: %v", n, err)
		}
	}
	// Constructed attributes: Read yes, search no.
	for _, n := range []string{"tokenGroups", "allowedAttributesEffective", "allowedChildClassesEffective", "sDRightsEffective", "nTSecurityDescriptor", "TOKENGROUPS"} {
		if _, err := s.checkAttrs([]string{n}, true); err != nil {
			t.Errorf("Read must allow %s: %v", n, err)
		}
		if _, err := s.checkAttrs([]string{n}, false); CodeOf(err) != CodeAttributeNotAllowed {
			t.Errorf("search must refuse %s: %v", n, err)
		}
	}
	// Secrets are refused by name (any case) in both modes.
	for _, n := range []string{"unicodePwd", "UNICODEPWD", "ms-Mcs-AdmPwd", "msLAPS-Password"} {
		sc := ldapfilter.NewSchema(ldapfilter.AttrInfo{Name: n, Syntax: ldapfilter.SynOctet})
		s2 := &Session{schema: sc}
		for _, allow := range []bool{true, false} {
			if _, err := s2.checkAttrs([]string{n}, allow); CodeOf(err) != CodeSecretAttribute {
				t.Errorf("secret %s allow=%v: %v", n, allow, err)
			}
		}
	}
	// Not in the allowlist: refused, not passed through.
	if _, err := s.checkAttrs([]string{"someNewAttr"}, true); CodeOf(err) != CodeInvalidArgument {
		t.Errorf("unknown attribute: %v", err)
	}
}

func TestSearchRejectsBeforeAnyIO(t *testing.T) {
	s := newOffline() // conn is nil: any request that got past validation would report DC_UNREACHABLE
	dc, _ := dn.Parse("DC=lab,DC=test", dn.Strict)
	base := dn.DNRef(dc)
	cn, _ := ldapfilter.ParseAttrName("cn", s.schema)
	s.schema = ldapfilter.NewSchema(ldapfilter.AttrInfo{Name: "cn", Syntax: ldapfilter.SynString}, ldapfilter.AttrInfo{Name: "unicodePwd", Syntax: ldapfilter.SynOctet})
	up, _ := ldapfilter.ParseAttrName("unicodePwd", s.schema)
	noop := func(*Entry) error { return nil }
	ctx := context.Background()
	cases := map[string]SearchRequest{
		"secret filter":   {Base: base, Scope: ScopeSubtree, Filter: ldapfilter.Present(up), Attributes: []string{"cn"}},
		"empty assertion": {Base: base, Scope: ScopeSubtree, Filter: ldapfilter.Eq(cn, ldapfilter.String("")), Attributes: []string{"cn"}},
		"nil filter":      {Base: base, Scope: ScopeSubtree, Attributes: []string{"cn"}},
		"bad scope":       {Base: base, Filter: ldapfilter.Present(cn), Attributes: []string{"cn"}},
		"no attributes":   {Base: base, Scope: ScopeBase, Filter: ldapfilter.Present(cn)},
		"zero base":       {Scope: ScopeBase, Filter: ldapfilter.Present(cn), Attributes: []string{"cn"}},
	}
	for name, req := range cases {
		err := s.Search(ctx, req, noop)
		if c := CodeOf(err); c != CodeFilterRejected && c != CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := s.Search(ctx, SearchRequest{Base: base, Scope: ScopeBase, Filter: ldapfilter.Present(cn), Attributes: []string{"cn"}}, noop); CodeOf(err) != CodeUnreachable {
		t.Errorf("valid request on a closed session: %v", err)
	}
}

// TestHostileValuesAreEscaped renders hostile assertion values and bases through the typed builders
// the way Search does, and checks that nothing special survives unescaped (AC4).
func TestHostileValuesAreEscaped(t *testing.T) {
	sc := DefaultSchema()
	cn, _ := ldapfilter.ParseAttrName("cn", sc)
	for _, v := range []string{"*)(objectClass=*", `a\2a`, "x\x00y", "(|(cn=*))", "admin*", "ü,+\"\\<>;"} {
		out, err := ldapfilter.Render(ldapfilter.Eq(cn, ldapfilter.String(v)), sc)
		if err != nil {
			continue // refused is also safe
		}
		body := out.String()[len("(cn=") : len(out.String())-1]
		for _, bad := range []string{"*", "(", ")", "\x00"} {
			if bytes.Contains([]byte(body), []byte(bad)) {
				t.Errorf("value %q rendered %q with raw %q", v, out, bad)
			}
		}
	}
	// A hostile DN is escaped by the dn package, and a base with an injected value is one RDN.
	d, err := dn.Child(mustDN(t, "OU=Managed,DC=lab,DC=test"), dn.CN, `x,OU=Evil+cn=y\`)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := dn.DNRef(d).ForRequest()
	if ref != `CN=x\,OU=Evil\+cn=y\\,OU=Managed,DC=lab,DC=test` && ref != `CN=x\,OU\3DEvil\+cn\3Dy\\,OU=Managed,DC=lab,DC=test` {
		t.Errorf("base = %q", ref)
	}
}

func mustDN(t *testing.T, s string) dn.DN {
	t.Helper()
	d, err := dn.Parse(s, dn.Strict)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestOpenRefusals(t *testing.T) {
	cred := Credential{BindName: "a@b", Password: secret.FromBytes([]byte("p"))}
	if _, err := Open(context.Background(), Config{Credential: cred}); CodeOf(err) != CodeInvalidArgument {
		t.Errorf("no servers: %v", err)
	}
	if _, err := Open(context.Background(), Config{Servers: []string{"dc1"}}); CodeOf(err) != CodeInvalidArgument {
		t.Errorf("no credential: %v", err)
	}
	for _, gc := range []string{"dc1:3268", "dc1:3269"} {
		if _, err := Open(context.Background(), Config{Servers: []string{gc}, Credential: cred}); CodeOf(err) != CodeGlobalCatalog {
			t.Errorf("%s: %v", gc, err)
		}
	}
}
