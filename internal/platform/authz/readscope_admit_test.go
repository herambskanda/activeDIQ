package authz_test

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// Objects: connection 1; OU a=10 under head 9; OU b=11 under head 9; a's child OU c=12; user u=20 in c.
func viewIn(parents ...byte) authz.ObjectView {
	v := authz.ObjectView{Connection: oid(1), ID: oid(20), Complete: true}
	for _, p := range parents {
		v.Ancestors = append(v.Ancestors, oid(p))
	}
	return v
}

func grantScope(inc, exc []authz.ScopeTerm, tok *authz.TokenLayer) authz.ReadScope {
	return authz.NewReadScope([]authz.ScopeGrant{{Include: inc, Exclude: exc}}, tok, nil, "")
}

func TestAdmits_table(t *testing.T) {
	sub := func(r byte) authz.ScopeTerm { return term(authz.TermSubtree, 1, r) }
	one := func(r byte) authz.ScopeTerm { return term(authz.TermOneLevel, 1, r) }
	nc := func(r byte) authz.ScopeTerm { return term(authz.TermNamingContext, 1, r) }
	cases := []struct {
		name string
		s    authz.ReadScope
		v    authz.ObjectView
		want bool
	}{
		{"zero scope", authz.ReadScope{}, viewIn(12, 10, 9), false},
		{"subtree include, object deep inside", grantScope([]authz.ScopeTerm{sub(10)}, nil, nil), viewIn(12, 10, 9), true},
		{"scoped to OU a, object lives in OU b", grantScope([]authz.ScopeTerm{sub(10)}, nil, nil), viewIn(11, 9), false},
		{"subtree root is the object itself", grantScope([]authz.ScopeTerm{sub(20)}, nil, nil), viewIn(12, 10, 9), true},
		{"naming context include", grantScope([]authz.ScopeTerm{nc(9)}, nil, nil), viewIn(12, 10, 9), true},
		{"one level: direct child", grantScope([]authz.ScopeTerm{one(12)}, nil, nil), viewIn(12, 10, 9), true},
		{"one level: grandchild is not covered", grantScope([]authz.ScopeTerm{one(10)}, nil, nil), viewIn(12, 10, 9), false},
		{"one level rooted at the connection reaches nothing", grantScope([]authz.ScopeTerm{one(1)}, nil, nil), viewIn(), false},
		{"exclude inside the include", grantScope([]authz.ScopeTerm{sub(10)}, []authz.ScopeTerm{sub(12)}, nil), viewIn(12, 10, 9), false},
		{"exclude elsewhere does not matter", grantScope([]authz.ScopeTerm{sub(10)}, []authz.ScopeTerm{sub(11)}, nil), viewIn(12, 10, 9), true},
		{"exclude of an unknown kind kills the grant", grantScope([]authz.ScopeTerm{sub(10)}, []authz.ScopeTerm{{Kind: 0, Connection: oid(1), Root: oid(11)}}, nil), viewIn(12, 10, 9), false},
		{"exclude with a zero root kills the grant", grantScope([]authz.ScopeTerm{sub(10)}, []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: oid(1)}}, nil), viewIn(12, 10, 9), false},
		{"include of an unknown kind matches nothing", grantScope([]authz.ScopeTerm{{Kind: 99, Connection: oid(1), Root: oid(10)}}, nil, nil), viewIn(12, 10, 9), false},
		{"include for another connection", grantScope([]authz.ScopeTerm{term(authz.TermSubtree, 2, 10)}, nil, nil), viewIn(12, 10, 9), false},
		{"incomplete chain", grantScope([]authz.ScopeTerm{sub(10)}, nil, nil), authz.ObjectView{Connection: oid(1), ID: oid(20), Ancestors: []authz.ObjectID{oid(12), oid(10)}}, false},
		{"zero element in the chain", grantScope([]authz.ScopeTerm{sub(10)}, nil, nil), authz.ObjectView{Connection: oid(1), ID: oid(20), Ancestors: []authz.ObjectID{oid(12), {}, oid(10)}, Complete: true}, false},
		{"zero object", grantScope([]authz.ScopeTerm{sub(10)}, nil, nil), authz.ObjectView{Connection: oid(1), Ancestors: []authz.ObjectID{oid(10)}, Complete: true}, false},
		{"token narrows to a region that holds the object", grantScope([]authz.ScopeTerm{sub(9)}, nil, &authz.TokenLayer{Include: []authz.ScopeTerm{sub(12)}}), viewIn(12, 10, 9), true},
		{"token narrows to a region that does not", grantScope([]authz.ScopeTerm{sub(9)}, nil, &authz.TokenLayer{Include: []authz.ScopeTerm{sub(11)}}), viewIn(12, 10, 9), false},
		{"token cannot widen past the grant", grantScope([]authz.ScopeTerm{sub(11)}, nil, &authz.TokenLayer{Include: []authz.ScopeTerm{sub(9)}}), viewIn(12, 10, 9), false},
		{"empty token layer grants nothing", grantScope([]authz.ScopeTerm{sub(9)}, nil, &authz.TokenLayer{}), viewIn(12, 10, 9), false},
		{"token exclude", grantScope([]authz.ScopeTerm{sub(9)}, nil, &authz.TokenLayer{Include: []authz.ScopeTerm{sub(9)}, Exclude: []authz.ScopeTerm{sub(10)}}), viewIn(12, 10, 9), false},
		{"unusable token include grants nothing", grantScope([]authz.ScopeTerm{sub(9)}, nil, &authz.TokenLayer{Include: []authz.ScopeTerm{sub(9), {Kind: authz.TermSubtree, Connection: oid(1)}}}), viewIn(12, 10, 9), false},
	}
	for _, c := range cases {
		if got := c.s.Admits(c.v); got != c.want {
			t.Errorf("%s: Admits = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAdmits_union_of_grants_each_with_its_own_exclude(t *testing.T) {
	sub := func(r byte) authz.ScopeTerm { return term(authz.TermSubtree, 1, r) }
	s := authz.NewReadScope([]authz.ScopeGrant{
		{Include: []authz.ScopeTerm{sub(10)}, Exclude: []authz.ScopeTerm{sub(12)}},
		{Include: []authz.ScopeTerm{sub(12)}},
	}, nil, nil, "")
	if !s.Admits(viewIn(12, 10, 9)) {
		t.Fatal("the second grant includes what the first excludes: an exclude applies per grant")
	}
}

func TestSearchRoots(t *testing.T) {
	sub := func(c, r byte) authz.ScopeTerm { return term(authz.TermSubtree, c, r) }
	t.Run("zero scope", func(t *testing.T) {
		if got := (authz.ReadScope{}).SearchRoots(oid(1)); got != nil {
			t.Fatalf("got %v, want none", got)
		}
	})
	t.Run("deduplicated, this connection only, naming context becomes a subtree", func(t *testing.T) {
		s := authz.NewReadScope([]authz.ScopeGrant{
			{Include: []authz.ScopeTerm{sub(1, 10), sub(2, 11), term(authz.TermOneLevel, 1, 12)}},
			{Include: []authz.ScopeTerm{sub(1, 10), term(authz.TermNamingContext, 1, 9)}},
		}, nil, nil, "")
		got := s.SearchRoots(oid(1))
		want := []authz.SearchRoot{{Kind: authz.TermSubtree, Root: oid(10)}, {Kind: authz.TermOneLevel, Root: oid(12)}, {Kind: authz.TermSubtree, Root: oid(9)}}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	})
	t.Run("a grant with an unusable exclude contributes no root", func(t *testing.T) {
		s := authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{sub(1, 10)}, Exclude: []authz.ScopeTerm{{Kind: 0, Connection: oid(1), Root: oid(5)}}}}, nil, nil, "")
		if got := s.SearchRoots(oid(1)); got != nil {
			t.Fatalf("got %v, want none", got)
		}
	})
	t.Run("an empty token layer leaves no roots", func(t *testing.T) {
		s := authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{sub(1, 10)}}}, &authz.TokenLayer{}, nil, "")
		if got := s.SearchRoots(oid(1)); got != nil {
			t.Fatalf("got %v, want none", got)
		}
	})
	t.Run("unusable include is not a root", func(t *testing.T) {
		s := authz.NewReadScope([]authz.ScopeGrant{{Include: []authz.ScopeTerm{{Kind: authz.TermSubtree, Connection: oid(1)}}}}, nil, nil, "")
		if got := s.SearchRoots(oid(1)); len(got) != 0 {
			t.Fatalf("got %v, want none", got)
		}
	})
}
