package client

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
)

type readsFake struct {
	objs  map[string]ObjectRead
	err   error
	calls int
}

func (r *readsFake) Object(_ context.Context, _ authority.Pins, _ authority.TargetRef, guid string, _ bool) (ObjectRead, error) {
	r.calls++
	return r.objs[guid], r.err
}

var pins = authority.Pins{"nc": "dc1"}

// Acceptance 5: a connection ID as the GUID of a tier0_scope target is not read and is not Tier-0.
func TestTier0ScopeTargetIsNeitherReadNorTier0(t *testing.T) {
	r := &readsFake{err: errors.New("directory has never heard of this")}
	for name, f := range map[string]*ConnectorFacts{"with reads": NewConnectorFacts(r), "without reads": NewConnectorFacts(nil), "nil": nil} {
		got, err := f.Facts(context.Background(), pins, authority.FactsQuery{
			Target: authority.TargetRef{Connection: "c1", GUID: "c1", Class: TargetClassTier0Scope}, Tier0: true, Ancestry: true})
		if err != nil || got.Tier0 || !got.Exists {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	if r.calls != 0 {
		t.Fatalf("connector was read %d times for a scope", r.calls)
	}
}

func TestStoreTargetIsNotReadFromTheDirectory(t *testing.T) {
	r := &readsFake{}
	got, err := NewConnectorFacts(r).Facts(context.Background(), pins, authority.FactsQuery{Target: authority.TargetRef{GUID: "row-1", Class: "thing"}})
	if err != nil || !got.Exists || got.Tier0 || r.calls != 0 {
		t.Fatalf("%+v, %v, %d", got, err, r.calls)
	}
}

func TestDirectoryTargetWithNoReadsFailsClosed(t *testing.T) {
	_, err := NewConnectorFacts(nil).Facts(context.Background(), pins, authority.FactsQuery{Target: authority.TargetRef{Connection: "c1", GUID: "o", Class: "user"}})
	if !errors.Is(err, ErrNoReads) {
		t.Fatalf("err = %v", err)
	}
}

func TestParentChainIsWalkedLive(t *testing.T) {
	r := &readsFake{objs: map[string]ObjectRead{
		"o":  {Exists: true, Parent: "ou"},
		"ou": {Exists: true, Parent: "nc"},
		"nc": {Exists: true},
	}}
	q := authority.FactsQuery{Target: authority.TargetRef{Connection: "c1", GUID: "o", Class: "user"}, Tier0: true, Ancestry: true}
	got, err := NewConnectorFacts(r).Facts(context.Background(), pins, q)
	if err != nil || !got.Exists || got.Tier0 || !got.AncestorsComplete || len(got.Ancestors) != 2 || got.Ancestors[0] != "ou" || got.Ancestors[1] != "nc" {
		t.Fatalf("%+v, %v", got, err)
	}
	q.Ancestry = false
	r.calls = 0
	got, _ = NewConnectorFacts(r).Facts(context.Background(), pins, q)
	if r.calls != 1 || got.AncestorsComplete || got.Ancestors != nil {
		t.Fatalf("no ancestry asked: %+v after %d reads", got, r.calls)
	}
}

func TestTier0AndMissingAndBrokenChains(t *testing.T) {
	q := authority.FactsQuery{Target: authority.TargetRef{Connection: "c1", GUID: "o", Class: "user"}, Ancestry: true}
	f := func(objs map[string]ObjectRead) authority.Facts {
		got, err := NewConnectorFacts(&readsFake{objs: objs}).Facts(context.Background(), pins, q)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := f(map[string]ObjectRead{"o": {Exists: true, Tier0: true}}); !got.Tier0 {
		t.Errorf("tier0 not reported: %+v", got)
	}
	if got := f(map[string]ObjectRead{}); got.Exists || got.AncestorsComplete {
		t.Errorf("missing object: %+v", got)
	}
	if got := f(map[string]ObjectRead{"o": {Exists: true, Parent: "gone"}}); got.AncestorsComplete {
		t.Errorf("vanished parent must be incomplete: %+v", got)
	}
	if got := f(map[string]ObjectRead{"o": {Exists: true, Parent: "a"}, "a": {Exists: true, Parent: "o"}}); got.AncestorsComplete {
		t.Errorf("loop must be incomplete: %+v", got)
	}
	if _, err := NewConnectorFacts(&readsFake{err: errors.New("dc down")}).Facts(context.Background(), pins, q); err == nil {
		t.Error("a read error must surface, not become empty facts")
	}
}

// A create target has no GUID: its facts are its planned parent's, never a read of the empty GUID.
func TestCreateTargetIsJudgedOnItsPlannedParent(t *testing.T) {
	r := &readsFake{objs: map[string]ObjectRead{"ou": {Exists: true, Tier0: true, Parent: "nc"}, "nc": {Exists: true}}}
	got, err := NewConnectorFacts(r).Facts(context.Background(), pins, authority.FactsQuery{
		Target: authority.TargetRef{Connection: "c1", Class: "user", Parent: "ou", RDN: "X"}, Tier0: true, Ancestry: true})
	if err != nil || !got.Exists || !got.Tier0 || len(got.Ancestors) != 1 || got.Ancestors[0] != "nc" || !got.AncestorsComplete {
		t.Fatalf("%+v, %v", got, err)
	}
}
