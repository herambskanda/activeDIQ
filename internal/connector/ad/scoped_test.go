package ad

import (
	"context"
	"testing"

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
