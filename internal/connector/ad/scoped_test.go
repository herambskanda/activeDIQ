package ad

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// LF-40: only the closed set of general-search controls passes; show-deleted and show-recycled are
// refused, and the error does not echo the OID.
func TestCheckControls(t *testing.T) {
	if err := CheckControls("1.2.840.113556.1.4.319", "1.2.840.113556.1.4.1339", "1.2.840.113556.1.4.529", "1.2.840.113556.1.4.801"); err != nil {
		t.Errorf("closed set: %v", err)
	}
	for _, oid := range []string{"1.2.840.113556.1.4.417", "1.2.840.113556.1.4.2064", "1.2.840.113556.1.4.1504", "", "x"} {
		err := CheckControls("1.2.840.113556.1.4.319", oid)
		if CodeOf(err) != CodeControlNotAllowed {
			t.Errorf("%q: %v", oid, err)
		} else if oid != "" && contains(err.Error(), oid) {
			t.Errorf("error echoes the OID: %v", err)
		}
	}
}

func contains(s, sub string) bool { return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0 }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestScopedSearchRejectsBeforeAnyIO(t *testing.T) {
	s := newOffline()
	g := guid.GUID{1}
	root := dn.GUIDRef(g)
	dcn, _ := dn.Parse("DC=lab,DC=test", dn.Strict)
	cn, _ := ldapfilter.ParseAttrName("cn", s.schema)
	f := ldapfilter.Present(cn)
	noop := func(*Entry) error { return nil }
	cases := map[string]ScopedRequest{
		"no roots":       {Depth: ScopeSubtree, Filter: f, Attributes: []string{"cn"}},
		"no filter":      {Roots: []dn.ObjectRef{root}, Depth: ScopeSubtree, Attributes: []string{"cn"}},
		"base depth":     {Roots: []dn.ObjectRef{root}, Depth: ScopeBase, Filter: f, Attributes: []string{"cn"}},
		"DN root":        {Roots: []dn.ObjectRef{dn.DNRef(dcn)}, Depth: ScopeSubtree, Filter: f, Attributes: []string{"cn"}},
		"star":           {Roots: []dn.ObjectRef{root}, Depth: ScopeSubtree, Filter: f, Attributes: []string{"*"}},
		"constructed":    {Roots: []dn.ObjectRef{root}, Depth: ScopeSubtree, Filter: f, Attributes: []string{"tokenGroups"}},
		"second root DN": {Roots: []dn.ObjectRef{root, dn.DNRef(dcn)}, Depth: ScopeSubtree, Filter: f, Attributes: []string{"cn"}},
	}
	for name, req := range cases {
		want := CodeInvalidArgument
		if name == "constructed" {
			want = CodeAttributeNotAllowed
		}
		if _, err := s.ScopedSearch(context.Background(), req, noop); CodeOf(err) != want {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := s.ScopedSearch(context.Background(), ScopedRequest{Roots: []dn.ObjectRef{root}, Depth: ScopeSubtree, Filter: f, Attributes: []string{"cn"}}, noop); CodeOf(err) != CodeUnreachable {
		t.Errorf("valid request on a closed session: %v", err)
	}
}

// LF-37/38 offline: once a schema-flagged attribute is in the session schema, an attribute list, a
// filter and a sort key all refuse it, and the static list is refused even when the forest lacks it.
func TestSecretSchemaRefusals(t *testing.T) {
	s := newOffline()
	s.schema = s.schema.With(
		ldapfilter.AttrInfo{Name: "customRodcOnly", OID: "1.2.840.113556.1.8000.2554.1", Syntax: ldapfilter.SynOctet, Secret: true},
		ldapfilter.AttrInfo{Name: "ms-Mcs-AdmPwd", Syntax: ldapfilter.SynOctet, Secret: true},
	)
	for _, n := range []string{"customRodcOnly", "CUSTOMRODCONLY", "1.2.840.113556.1.8000.2554.1", "ms-Mcs-AdmPwd"} {
		if !s.schema.IsSecret(n) {
			t.Errorf("%s not secret", n)
		}
	}
	for _, n := range []string{"customRodcOnly", "1.2.840.113556.1.8000.2554.1", "ms-Mcs-AdmPwd"} {
		if _, err := s.checkAttrs([]string{"cn", n}, true); CodeOf(err) != CodeSecretAttribute {
			t.Errorf("attrs %s: %v", n, err)
		}
		if _, err := ldapfilter.ParseSortKey(n, s.schema); ldapfilter.Code(err) != ldapfilter.ForbiddenSortKey {
			t.Errorf("sort %s: %v", n, err)
		}
		a, _ := ldapfilter.ParseAttrName(n, s.schema)
		if _, err := ldapfilter.Render(ldapfilter.Present(a), s.schema); ldapfilter.Code(err) != ldapfilter.SecretAttribute {
			t.Errorf("filter %s: %v", n, err)
		}
	}
	if _, err := ldapfilter.ParseSortKey("cn", s.schema); err != nil {
		t.Errorf("ordinary sort key: %v", err)
	}
	// With does not mutate the receiver and cannot clear a flag.
	if DefaultSchema().IsSecret("customRodcOnly") {
		t.Error("With mutated the default schema")
	}
	if !s.schema.With(ldapfilter.AttrInfo{Name: "customRodcOnly", Syntax: ldapfilter.SynString}).IsSecret("customRodcOnly") {
		t.Error("an unflagged duplicate cleared Secret")
	}
}

func TestReadSecretRefusals(t *testing.T) {
	s := newOffline()
	s.schema = s.schema.With(ldapfilter.AttrInfo{Name: "msFVE-RecoveryPassword", Syntax: ldapfilter.SynString})
	var events []SecretReadEvent
	s.cfg.SecretAudit = func(e SecretReadEvent) error { events = append(events, e); return nil }
	g := guid.GUID{9}
	attr, err := s.SecretAttr("msFVE-RecoveryPassword")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SecretAttr("cn"); CodeOf(err) != CodeInvalidArgument {
		t.Errorf("non-secret attr: %v", err)
	}
	if _, err := s.SecretAttr("nonesuch"); CodeOf(err) != CodeInvalidArgument {
		t.Errorf("unknown attr: %v", err)
	}
	grant, err := MintSecretReadGrant("alice", g, attr, "recovery ticket 42")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MintSecretReadGrant("", g, attr, "r"); err == nil {
		t.Error("grant without actor")
	}
	if _, err := MintSecretReadGrant("a", g, attr, ""); err == nil {
		t.Error("grant without reason")
	}
	ctx := context.Background()
	other := guid.GUID{8}
	if _, err := s.ReadSecret(ctx, dn.GUIDRef(other), attr, grant); CodeOf(err) != CodeInvalidArgument {
		t.Errorf("grant for another object: %v", err)
	}
	dcn, _ := dn.Parse("DC=lab,DC=test", dn.Strict)
	if _, err := s.ReadSecret(ctx, dn.DNRef(dcn), attr, grant); CodeOf(err) != CodeInvalidArgument {
		t.Errorf("DN target: %v", err)
	}
	if _, err := s.ReadSecret(ctx, dn.GUIDRef(g), attr, SecretReadGrant{}); CodeOf(err) != CodeInvalidArgument {
		t.Errorf("zero grant: %v", err)
	}
	if _, err := s.ReadSecret(ctx, dn.GUIDRef(g), attr, grant); CodeOf(err) != CodeUnreachable {
		t.Errorf("valid request on a closed session: %v", err)
	}
	if len(events) != 4 || events[3].Outcome != string(CodeUnreachable) || events[3].Actor != "alice" || events[3].Reason != "recovery ticket 42" {
		t.Errorf("every call is audited with its outcome: %+v", events)
	}
	s.cfg.SecretAudit = nil
	if _, err := s.ReadSecret(ctx, dn.GUIDRef(g), attr, grant); CodeOf(err) != CodeInvalidArgument {
		t.Errorf("no audit sink: %v", err)
	}
}

// T-0313 (3): a failed read whose audit also fails returns both errors; the read's code still leads.
func TestReadSecretFailedReadAndFailedAudit(t *testing.T) {
	s := newOffline()
	s.schema = s.schema.With(ldapfilter.AttrInfo{Name: "msFVE-RecoveryPassword", Syntax: ldapfilter.SynString})
	sinkErr := errors.New("sink down")
	s.cfg.SecretAudit = func(SecretReadEvent) error { return sinkErr }
	g := guid.GUID{9}
	attr, err := s.SecretAttr("msFVE-RecoveryPassword")
	if err != nil {
		t.Fatal(err)
	}
	grant, _ := MintSecretReadGrant("alice", g, attr, "ticket 42")
	sec, err := s.ReadSecret(context.Background(), dn.GUIDRef(g), attr, grant) // closed session: UNREACHABLE
	if CodeOf(err) != CodeUnreachable {
		t.Fatalf("the read failure must stay first: %v", err)
	}
	if !errors.Is(err, sinkErr) {
		t.Errorf("the audit failure is dropped: %v", err)
	}
	var found bool
	for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
		if ae, ok := e.(*Error); ok && ae.Code == CodeProtocol {
			found = true
		}
	}
	if !found {
		t.Errorf("no audit-failed error in the join: %v", err)
	}
	sec.Expose(func(b []byte) {
		if len(b) != 0 {
			t.Error("value escaped on a failed read")
		}
	})
}

// T-0313 (4): zero schema-flagged attributes fails closed; any flagged one passes.
func TestCollectSecretSchemaFailsClosedOnEmpty(t *testing.T) {
	empty := func([]byte) (*ldap.SearchResult, error) { return &ldap.SearchResult{}, nil }
	if _, err := collectSecretSchema(empty); CodeOf(err) != CodeProtocol {
		t.Fatalf("empty schema result must fail closed: %v", err)
	}
	one := func([]byte) (*ldap.SearchResult, error) {
		return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("CN=x", map[string][]string{"lDAPDisplayName": {"customSecret"}})}}, nil
	}
	extra, err := collectSecretSchema(one)
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, a := range extra {
		if a.Name == "customSecret" && a.Secret {
			saw = true
		}
	}
	if !saw {
		t.Error("flagged attribute not marked secret")
	}
	boom := errors.New("boom")
	if _, err := collectSecretSchema(func([]byte) (*ldap.SearchResult, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Errorf("page error: %v", err)
	}
}
