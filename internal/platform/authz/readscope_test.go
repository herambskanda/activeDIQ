package authz_test

import (
	"reflect"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

func oid(n byte) authz.ObjectID { return authz.ObjectID{15: n} }

func term(k authz.TermKind, c, r byte) authz.ScopeTerm {
	return authz.ScopeTerm{Kind: k, Connection: oid(c), Root: oid(r)}
}

func TestReadScope_zero_value_grants_nothing(t *testing.T) {
	var s authz.ReadScope
	if !s.Empty() {
		t.Fatal("zero ReadScope must be Empty")
	}
	if len(s.Terms()) != 0 {
		t.Fatalf("Terms = %v, want none", s.Terms())
	}
	if _, ok := s.Token(); ok {
		t.Fatal("zero ReadScope has no token layer")
	}
	if len(s.Reasons()) != 0 || s.Summary() != "" {
		t.Fatalf("reasons %v summary %q", s.Reasons(), s.Summary())
	}
	_ = s.Fingerprint() // defined for the zero value
}

func TestReadScope_has_no_exported_fields(t *testing.T) {
	rt := reflect.TypeOf(authz.ReadScope{})
	for i := 0; i < rt.NumField(); i++ {
		if f := rt.Field(i); f.IsExported() {
			t.Errorf("authz.ReadScope exports field %s: any package could build a non-empty scope", f.Name)
		}
	}
}

func TestReadScope_term_kind_zero_is_unknown(t *testing.T) {
	var k authz.TermKind
	for _, known := range []authz.TermKind{authz.TermNamingContext, authz.TermSubtree, authz.TermOneLevel} {
		if k == known {
			t.Fatalf("zero TermKind equals %v", known)
		}
		if known.String() == "unknown" {
			t.Errorf("kind %d has no name", known)
		}
	}
	if k.String() != "unknown" || authz.TermKind(200).String() != "unknown" {
		t.Error("undefined kinds must be unknown")
	}
}

func TestReadScope_Empty(t *testing.T) {
	inc := []authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}
	cases := []struct {
		name  string
		scope authz.ReadScope
		want  bool
	}{
		{"no grants", authz.NewReadScope(nil, nil, nil, ""), true},
		{"a grant", authz.NewReadScope([]authz.ScopeGrant{{Include: inc}}, nil, nil, ""), false},
		{"token with include", authz.NewReadScope([]authz.ScopeGrant{{Include: inc}}, &authz.TokenLayer{Include: inc}, nil, ""), false},
		{"token with no include", authz.NewReadScope([]authz.ScopeGrant{{Include: inc}}, &authz.TokenLayer{}, nil, ""), true},
		{"token but no grants", authz.NewReadScope(nil, &authz.TokenLayer{Include: inc}, nil, ""), true},
	}
	for _, c := range cases {
		if got := c.scope.Empty(); got != c.want {
			t.Errorf("%s: Empty = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestReadScope_methods_return_copies(t *testing.T) {
	in := []authz.ScopeGrant{{Include: []authz.ScopeTerm{term(authz.TermSubtree, 1, 2)}, Exclude: []authz.ScopeTerm{term(authz.TermOneLevel, 1, 3)}}}
	tok := &authz.TokenLayer{Include: []authz.ScopeTerm{term(authz.TermNamingContext, 1, 4)}}
	reasons := []authz.ScopeReason{"scope_kind_unsupported:group_members"}
	s := authz.NewReadScope(in, tok, reasons, "summary")
	fp := s.Fingerprint()

	in[0].Include[0].Root = oid(99)
	tok.Include[0].Root = oid(99)
	reasons[0] = "mutated"
	got := s.Terms()
	got[0].Include[0].Root = oid(98)
	gt, ok := s.Token()
	if !ok {
		t.Fatal("token layer lost")
	}
	gt.Include[0].Root = oid(98)
	s.Reasons()[0] = "mutated"

	if s.Fingerprint() != fp {
		t.Fatal("mutating inputs or returned slices changed the scope")
	}
	if s.Terms()[0].Include[0].Root != oid(2) || s.Reasons()[0] != "scope_kind_unsupported:group_members" || s.Summary() != "summary" {
		t.Fatal("scope content changed")
	}
}

func TestReadScope_Fingerprint(t *testing.T) {
	a, b := term(authz.TermSubtree, 1, 2), term(authz.TermNamingContext, 1, 3)
	x := term(authz.TermOneLevel, 1, 4)
	base := authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{a, b}, Exclude: []authz.ScopeTerm{x}}, {Include: []authz.ScopeTerm{x}}}, nil, nil, "one")

	same := authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{x}}, {Include: []authz.ScopeTerm{b, a}, Exclude: []authz.ScopeTerm{x}}},
		nil, []authz.ScopeReason{"r"}, "different text")
	if base.Fingerprint() != same.Fingerprint() {
		t.Error("order, reasons and summary must not change the fingerprint")
	}

	differs := map[string]authz.ReadScope{
		"include vs exclude": authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{a, b, x}}, {Include: []authz.ScopeTerm{x}}}, nil, nil, ""),
		"other kind":         authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{term(authz.TermOneLevel, 1, 2), b}, Exclude: []authz.ScopeTerm{x}}, {Include: []authz.ScopeTerm{x}}}, nil, nil, ""),
		"other connection":   authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{term(authz.TermSubtree, 9, 2), b}, Exclude: []authz.ScopeTerm{x}}, {Include: []authz.ScopeTerm{x}}}, nil, nil, ""),
		"merged grants":      authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{a, b, x}, Exclude: []authz.ScopeTerm{x}}}, nil, nil, ""),
		"empty token layer":  authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{a, b}, Exclude: []authz.ScopeTerm{x}}, {Include: []authz.ScopeTerm{x}}}, &authz.TokenLayer{}, nil, ""),
		"no grants":          authz.NewReadScope(nil, nil, nil, ""),
	}
	seen := map[[32]byte]string{base.Fingerprint(): "base"}
	for name, s := range differs {
		fp := s.Fingerprint()
		if prev, dup := seen[fp]; dup {
			t.Errorf("%q has the same fingerprint as %q", name, prev)
		}
		seen[fp] = name
	}

	// The token layer is a layer of its own: the same terms as a grant are not the same scope.
	tokA := authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{a}}}, &authz.TokenLayer{Include: []authz.ScopeTerm{b}}, nil, "")
	tokB := authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{b}}}, &authz.TokenLayer{Include: []authz.ScopeTerm{a}}, nil, "")
	if tokA.Fingerprint() == tokB.Fingerprint() {
		t.Error("swapping grant and token terms must change the fingerprint")
	}
}
