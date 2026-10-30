package authztest_test

import (
	"reflect"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
)

func TestReadScope_builds_a_scope_from_outside_authz(t *testing.T) {
	g := authz.ScopeGrant{
		Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: authz.ObjectID{1}, Root: authz.ObjectID{2}}},
		Exclude: []authz.ScopeTerm{{Kind: authz.TermOneLevel, Connection: authz.ObjectID{1}, Root: authz.ObjectID{3}}},
	}
	s := authztest.ReadScope(g)
	if s.Empty() {
		t.Fatal("scope with a grant is Empty")
	}
	if got := s.Terms(); !reflect.DeepEqual(got, []authz.ScopeGrant{g}) {
		t.Fatalf("Terms = %+v, want what was passed in", got)
	}
	if _, ok := s.Token(); ok {
		t.Fatal("ReadScope adds no token layer")
	}
	if !authztest.ReadScope().Empty() {
		t.Fatal("ReadScope() with no grants must be Empty")
	}
}

func TestReadScopeWithToken(t *testing.T) {
	tok := authz.TokenLayer{Include: []authz.ScopeTerm{{Kind: authz.TermNamingContext, Connection: authz.ObjectID{1}, Root: authz.ObjectID{2}}}}
	s := authztest.ReadScopeWithToken(tok, authz.ScopeGrant{Include: tok.Include})
	got, ok := s.Token()
	if !ok || !reflect.DeepEqual(got, tok) {
		t.Fatalf("Token = %+v, %v", got, ok)
	}
	if !authztest.ReadScopeWithToken(authz.TokenLayer{}, authz.ScopeGrant{Include: tok.Include}).Empty() {
		t.Fatal("a token layer with no include must make the scope Empty")
	}
}

func TestReadScopeWithReasons(t *testing.T) {
	s := authztest.ReadScopeWithReasons([]authz.ScopeReason{"scope_kind_unsupported:group_members"})
	if got := s.Reasons(); len(got) != 1 || got[0] != "scope_kind_unsupported:group_members" {
		t.Fatalf("Reasons = %v", got)
	}
}
