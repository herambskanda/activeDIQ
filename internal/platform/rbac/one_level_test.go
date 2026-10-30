package rbac

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// T-0881: an ou_one_level root reaches the direct children of its OU and is never read as a subtree.
func TestOneLevelRootReachesDirectChildrenOnly(t *testing.T) {
	oneLevel := func(g string) Root { return Root{Kind: OUOneLevel, Connection: conn, GUID: g} }
	subtree := func(g string, ex bool) Root { return Root{Kind: OUSubtree, Connection: conn, GUID: g, Exclude: ex} }
	// obj sits directly under ouA, which sits under ouB, under the NC head.
	direct := authority.Facts{Exists: true, Ancestors: []string{ouA, ouB, ncHead}, AncestorsComplete: true}
	// obj sits under a child OU (obj's parent is ouB; ouA is two levels up).
	deeper := authority.Facts{Exists: true, Ancestors: []string{ouB, ouA, ncHead}, AncestorsComplete: true}
	cases := []struct {
		name  string
		roots []Root
		facts authority.Facts
		allow bool
	}{
		{"direct child of the root OU", []Root{oneLevel(ouA)}, direct, true},
		{"object in a child OU of the root is not a direct child", []Root{oneLevel(ouA)}, deeper, false},
		{"root two levels up is not a direct parent", []Root{oneLevel(ncHead)}, direct, false},
		{"direct child of another OU", []Root{oneLevel(ouB)}, direct, false},
		{"exclude under the direct child's chain denies", []Root{oneLevel(ouA), subtree(ouB, true)}, direct, false},
		{"exclude on the parent itself denies", []Root{oneLevel(ouA), subtree(ouA, true)}, direct, false},
		{"exclude elsewhere does not narrow", []Root{oneLevel(ouA), subtree(conn2, true)}, direct, true},
		{"one-level beside a subtree root still allows the subtree", []Root{oneLevel(ouB), subtree(ouA, false)}, direct, true},
		{"an exclude of kind ou_one_level fails closed", []Root{oneLevel(ouA), {Kind: OUOneLevel, Connection: conn, GUID: ouB, Exclude: true}}, direct, false},
		{"an unknown kind is never read as a subtree", []Root{{Kind: "ou_children", Connection: conn, GUID: ouA}}, direct, false},
		{"an unknown exclude kind narrows", []Root{subtree(ouA, false), {Kind: "ou_children", Connection: conn, GUID: ouB, Exclude: true}}, direct, false},
		{"another connection's one-level root", []Root{{Kind: OUOneLevel, Connection: conn2, GUID: ouA}}, direct, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := objectCase(t, c.roots, c.facts)
			if c.allow && err != nil {
				t.Fatalf("want allowed, got %v", err)
			}
			if !c.allow && !errors.Is(err, ErrDenied) {
				t.Fatalf("want denied, got %v", err)
			}
		})
	}
}

// The root itself and a target with no parent are not "direct children".
func TestOneLevelRootDoesNotCoverTheRootOrAParentlessObject(t *testing.T) {
	roots := []Root{{Kind: OUOneLevel, Connection: conn, GUID: ouA}}
	a := az(t, Assignment{ID: "a1", Permissions: []authz.Permission{"objects.user.delete"}, Roots: roots})
	own := authority.TargetRef{Connection: conn, GUID: ouA, Class: "organizationalUnit", NC: "nc"}
	if err := a.Authorize(ctxT(), human(acct), "objects.user.delete", own,
		authority.Facts{Exists: true, Ancestors: []string{ncHead}, AncestorsComplete: true}); !errors.Is(err, ErrDenied) {
		t.Fatalf("the OU itself: %v", err)
	}
	// A root whose GUID equals the connection must not match a parentless object (Ancestors[0] is the connection).
	b := az(t, Assignment{ID: "a2", Permissions: []authz.Permission{"objects.user.delete"}, Roots: []Root{{Kind: OUOneLevel, Connection: conn, GUID: conn}}})
	if err := b.Authorize(ctxT(), human(acct), "objects.user.delete", authority.TargetRef{Connection: conn, GUID: obj, Class: "user", NC: "nc"},
		authority.Facts{Exists: true, AncestorsComplete: true}); !errors.Is(err, ErrDenied) {
		t.Fatalf("connection-GUID one-level root over a parentless object: %v", err)
	}
}

func TestValidRootsOneLevel(t *testing.T) {
	tn := tenant.ID{}
	ok := []Root{{Kind: OUOneLevel, Connection: conn, GUID: ouA}}
	if !validRoots(tn, ok) {
		t.Error("an ou_one_level include root is a valid root")
	}
	if validRoots(tn, []Root{{Kind: OUOneLevel, Connection: conn, GUID: ouA}, {Kind: OUOneLevel, Connection: conn, GUID: ouB, Exclude: true}}) {
		t.Error("ou_one_level is not a valid exclude")
	}
	if validRoots(tn, []Root{{Kind: OUOneLevel, Connection: conn, GUID: conn}}) {
		t.Error("an ou_one_level root may not carry the connection's GUID")
	}
	if validRoots(tn, []Root{{Kind: "ou_children", Connection: conn, GUID: ouA}}) {
		t.Error("unknown kind accepted")
	}
}

// The backed-side resolution marks a one-level root even when the resolver does not.
func TestResolveMarksOneLevelWhateverTheResolverReturns(t *testing.T) {
	a, err := New(fakeSrc{}, withRoots(fakeRoots{}))
	if err != nil {
		t.Fatal(err)
	}
	sr, err := a.resolve(context.Background(), tenant.ID{}, Root{Kind: OUOneLevel, Connection: conn, GUID: ouA})
	if err != nil || !sr.OneLevel {
		t.Fatalf("one-level root resolved as %+v, %v", sr, err)
	}
	sr, err = a.resolve(context.Background(), tenant.ID{}, Root{Kind: OUSubtree, Connection: conn, GUID: ouA})
	if err != nil || sr.OneLevel {
		t.Fatalf("subtree root resolved as %+v, %v", sr, err)
	}
	if _, err := a.resolve(context.Background(), tenant.ID{}, Root{Kind: OUOneLevel, Connection: conn, GUID: ouA, Exclude: true}); err == nil {
		t.Fatal("a one-level exclude must not resolve")
	}
}
