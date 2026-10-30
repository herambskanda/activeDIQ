package rbac

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ErrSourceIncomplete is returned by an AccountIndex or PeerIndex that could not read its source in
// full (a bound exceeded, a corrupt row). The answer is then incomplete and the guard refuses.
var ErrSourceIncomplete = errors.New("rbac: backing source not read in full")

// ObjectRef names a directory object: connection ID and objectGUID, canonical lower-case UUID text.
type ObjectRef struct{ Connection, GUID string }

// AccountIndex lists the console accounts that rest on a directory object: its directory account and
// the sso accounts bound to it (DM-30). Implemented over the authn store.
type AccountIndex interface {
	AccountsBackedBy(ctx context.Context, t tenant.ID, o ObjectRef) ([]string, error)
}

// PeerIndex lists the objects correlated to a directory object in either direction, in every DM-20
// state except removed (candidate, matched and broken). Implemented over the inventory store.
type PeerIndex interface {
	PeersOf(ctx context.Context, t tenant.ID, o ObjectRef) ([]ObjectRef, error)
}

type liveBacking struct {
	accounts AccountIndex
	peers    PeerIndex
}

// NewBacking returns the Backing over the account and correlation sources (DM-30.I7). The accounts
// of an object are those on the object itself plus those on each correlated peer; the answer is
// Complete only when every one of those reads succeeded in full.
func NewBacking(accounts AccountIndex, peers PeerIndex) (Backing, error) {
	if accounts == nil || peers == nil {
		return nil, errors.New("rbac: backing needs an account index and a peer index")
	}
	return &liveBacking{accounts: accounts, peers: peers}, nil
}

func (b *liveBacking) BackedBy(ctx context.Context, t tenant.ID, target authority.TargetRef) (BackedAccounts, error) {
	self := ObjectRef{Connection: target.Connection, GUID: target.GUID}
	if t.IsZero() || self.Connection == "" || self.GUID == "" {
		return BackedAccounts{}, nil // not a directory object: nothing is known, so not complete
	}
	peers, err := b.peers.PeersOf(ctx, t, self)
	if errors.Is(err, ErrSourceIncomplete) {
		return BackedAccounts{}, nil
	}
	if err != nil {
		return BackedAccounts{}, fmt.Errorf("rbac: reading correlations: %w", err)
	}
	seen := map[string]bool{}
	var ids []string
	for _, o := range append([]ObjectRef{self}, peers...) {
		got, err := b.accounts.AccountsBackedBy(ctx, t, o)
		if errors.Is(err, ErrSourceIncomplete) {
			return BackedAccounts{}, nil
		}
		if err != nil {
			return BackedAccounts{}, fmt.Errorf("rbac: reading backed accounts: %w", err)
		}
		for _, id := range got {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return BackedAccounts{Accounts: ids, Complete: true}, nil
}

// FactsReader is the live facts read of the directory client (operation.LiveFacts' shape).
type FactsReader interface {
	Facts(ctx context.Context, pins authority.Pins, q authority.FactsQuery) (authority.Facts, error)
}

type liveRoots struct{ facts FactsReader }

// NewRootResolver returns the RootResolver that reads a root's ancestor chain live through the
// directory client, never from storage or the request. A root whose chain was not read in full
// resolves as not Complete, which authz refuses. The read is a plain read of a container, not a
// write, so it carries no DC pins: the connector read adapter picks the DC.
func NewRootResolver(f FactsReader) (RootResolver, error) {
	if f == nil {
		return nil, errors.New("rbac: root resolver needs a facts reader")
	}
	return &liveRoots{facts: f}, nil
}

func (r *liveRoots) Resolve(ctx context.Context, _ tenant.ID, root Root) (authz.ScopeRoot, error) {
	id, err := authz.ParseObjectID(root.GUID)
	if err != nil {
		return authz.ScopeRoot{}, err
	}
	switch root.Kind {
	case EntraTenant, Tier0Scope:
		// A tenant or a connection is the head of its own tree: no ancestors to read.
		return authz.ScopeRoot{ID: id, Complete: true}, nil
	case NamingContext, OUSubtree:
	default:
		return authz.ScopeRoot{}, fmt.Errorf("rbac: unknown root kind %q", root.Kind)
	}
	if root.Connection == "" {
		return authz.ScopeRoot{}, errors.New("rbac: root has no connection")
	}
	f, err := r.facts.Facts(ctx, nil, authority.FactsQuery{
		Target:   authority.TargetRef{Connection: root.Connection, GUID: root.GUID},
		Ancestry: true,
	})
	if err != nil {
		return authz.ScopeRoot{}, fmt.Errorf("rbac: reading root ancestry: %w", err)
	}
	if !f.Exists {
		return authz.ScopeRoot{}, errors.New("rbac: scope root no longer exists")
	}
	out := authz.ScopeRoot{ID: id, Complete: f.AncestorsComplete}
	for _, a := range f.Ancestors {
		aid, err := authz.ParseObjectID(a)
		if err != nil {
			return authz.ScopeRoot{}, fmt.Errorf("rbac: ancestor is not a GUID: %w", err)
		}
		out.Ancestors = append(out.Ancestors, aid)
	}
	return out, nil
}
