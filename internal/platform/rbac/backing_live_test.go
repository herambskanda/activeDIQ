package rbac

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type fixedAccts map[ObjectRef][]string

func (f fixedAccts) AccountsBackedBy(_ context.Context, _ tenant.ID, o ObjectRef) ([]string, error) {
	return f[o], nil
}

type failPeers struct{ err error }

func (f failPeers) PeersOf(context.Context, tenant.ID, ObjectRef) ([]ObjectRef, error) {
	return nil, f.err
}

func TestBackingIsIncompleteWhenASourceWasNotReadInFull(t *testing.T) {
	tn, _ := tenant.Parse("11111111-1111-4111-8111-111111111111")
	b, err := NewBacking(fixedAccts{}, failPeers{ErrSourceIncomplete})
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.BackedBy(context.Background(), tn, authority.TargetRef{Connection: conn, GUID: ouC})
	if err != nil || got.Complete {
		t.Fatalf("incomplete peers: %+v %v", got, err)
	}
	b, _ = NewBacking(fixedAccts{}, failPeers{errors.New("db down")})
	if _, err := b.BackedBy(context.Background(), tn, authority.TargetRef{Connection: conn, GUID: ouC}); err == nil {
		t.Fatal("a read error must be an error, never an empty answer")
	}
	if _, err := NewBacking(nil, failPeers{}); err == nil {
		t.Fatal("nil account index accepted")
	}
}

type factsFn func(authority.FactsQuery) (authority.Facts, error)

func (f factsFn) Facts(_ context.Context, pins authority.Pins, q authority.FactsQuery) (authority.Facts, error) {
	if pins != nil {
		return authority.Facts{}, errors.New("a root read must not carry pins")
	}
	return f(q)
}

func TestRootResolverReadsAncestryLive(t *testing.T) {
	tn, _ := tenant.Parse("11111111-1111-4111-8111-111111111111")
	var asked authority.FactsQuery
	r, err := NewRootResolver(factsFn(func(q authority.FactsQuery) (authority.Facts, error) {
		asked = q
		return authority.Facts{Exists: true, Ancestors: []string{ouC, ncHead}, AncestorsComplete: true}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	sr, err := r.Resolve(context.Background(), tn, Root{Kind: OUSubtree, Connection: conn, GUID: ouCSub})
	if err != nil || !sr.Complete || len(sr.Ancestors) != 2 {
		t.Fatalf("resolve = %+v %v", sr, err)
	}
	if !asked.Ancestry || asked.Target.GUID != ouCSub || asked.Target.Connection != conn {
		t.Fatalf("query = %+v", asked)
	}
	// A connection-level root is read from nowhere.
	sr, err = r.Resolve(context.Background(), tn, Root{Kind: Tier0Scope, Connection: conn, GUID: conn})
	if err != nil || !sr.Complete || len(sr.Ancestors) != 0 {
		t.Fatalf("tier0 root = %+v %v", sr, err)
	}

	// Fail closed: read error, vanished root, incomplete chain, bad kind, no connection.
	for name, f := range map[string]func(authority.FactsQuery) (authority.Facts, error){
		"error":    func(authority.FactsQuery) (authority.Facts, error) { return authority.Facts{}, errors.New("no DC") },
		"vanished": func(authority.FactsQuery) (authority.Facts, error) { return authority.Facts{}, nil },
		"bad parent": func(authority.FactsQuery) (authority.Facts, error) {
			return authority.Facts{Exists: true, Ancestors: []string{"x"}, AncestorsComplete: true}, nil
		},
	} {
		r, _ := NewRootResolver(factsFn(f))
		if _, err := r.Resolve(context.Background(), tn, Root{Kind: OUSubtree, Connection: conn, GUID: ouCSub}); err == nil {
			t.Errorf("%s: resolved", name)
		}
	}
	r, _ = NewRootResolver(factsFn(func(authority.FactsQuery) (authority.Facts, error) { return authority.Facts{Exists: true}, nil }))
	if sr, err := r.Resolve(context.Background(), tn, Root{Kind: OUSubtree, Connection: conn, GUID: ouCSub}); err != nil || sr.Complete {
		t.Errorf("incomplete chain must not be Complete: %+v %v", sr, err)
	}
	if _, err := r.Resolve(context.Background(), tn, Root{Kind: "weird", Connection: conn, GUID: ouCSub}); err == nil {
		t.Error("unknown kind resolved")
	}
	if _, err := r.Resolve(context.Background(), tn, Root{Kind: OUSubtree, GUID: ouCSub}); err == nil {
		t.Error("root without connection resolved")
	}
}
