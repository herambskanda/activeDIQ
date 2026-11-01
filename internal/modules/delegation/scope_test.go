package delegation_test

import (
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/modules/delegation"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/module/moduletest"
)

func TestScopeEvaluatorsRegisteredForDirectoryKinds(t *testing.T) {
	c, err := moduletest.Register(delegation.New(platform.Deps{}, directory.Services{}))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	conn, root := authz.ObjectID{1}, authz.ObjectID{2}
	want := map[string]authz.TermKind{
		"naming_context": authz.TermNamingContext,
		"ou_subtree":     authz.TermSubtree,
		"ou_one_level":   authz.TermOneLevel,
	}
	if got := c.ScopeKinds(); len(got) != len(want) {
		t.Fatalf("ScopeKinds = %v, want exactly %d", got, len(want))
	}
	for kind, term := range want {
		e, ok := c.ScopeEvaluator(kind)
		if !ok {
			t.Fatalf("no evaluator for %s", kind)
		}
		got, err := e.Term(conn, root)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if got != (authz.ScopeTerm{Kind: term, Connection: conn, Root: root}) {
			t.Errorf("%s: term = %+v, want kind %v", kind, got, term)
		}
		if _, err := e.Term(authz.ObjectID{}, root); !errors.Is(err, authz.ErrInvalidObjectID) {
			t.Errorf("%s: zero connection: err = %v", kind, err)
		}
		if _, err := e.Term(conn, authz.ObjectID{}); !errors.Is(err, authz.ErrInvalidObjectID) {
			t.Errorf("%s: zero root: err = %v", kind, err)
		}
	}
	for _, kind := range []string{"entra_tenant", "tier0_scope", "tenant", "group_members", "administrative_unit", ""} {
		if _, ok := c.ScopeEvaluator(kind); ok {
			t.Errorf("kind %q must have no evaluator", kind)
		}
	}
}
