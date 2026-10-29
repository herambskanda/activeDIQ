package server

import (
	"context"
	"errors"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// accountAdapter serves rbac.AccountIndex from the authn account store.
type accountAdapter struct{ idx *authn.AccountIndex }

func (a accountAdapter) AccountsBackedBy(ctx context.Context, t tenant.ID, o rbac.ObjectRef) ([]string, error) {
	ids, err := a.idx.BackedBy(ctx, t, authn.DirectoryRef{ConnectionID: strings.ToLower(o.Connection), ObjectGUID: strings.ToLower(o.GUID)})
	if errors.Is(err, authn.ErrTooManyAccounts) {
		return nil, rbac.ErrSourceIncomplete
	}
	return ids, err
}

// peerAdapter serves rbac.PeerIndex from the DM-20 correlation reader: every state but removed, both
// directions (CorrelationsFor returns links from either side).
type peerAdapter struct{ src inventory.CorrelationSource }

func (p peerAdapter) PeersOf(ctx context.Context, t tenant.ID, o rbac.ObjectRef) ([]rbac.ObjectRef, error) {
	c, err := p.src.CorrelationsFor(ctx, t, inventory.Ref{Connection: inventory.ConnectionID(strings.ToLower(o.Connection)), Object: inventory.GUID(strings.ToLower(o.GUID))})
	if errors.Is(err, inventory.ErrTooMany) || errors.Is(err, inventory.ErrCorrupt) || errors.Is(err, inventory.ErrInvalid) {
		return nil, rbac.ErrSourceIncomplete
	}
	if err != nil {
		return nil, err
	}
	out := make([]rbac.ObjectRef, 0, len(c.Links))
	for _, l := range c.Links {
		out = append(out, rbac.ObjectRef{Connection: string(l.Peer.Connection), GUID: string(l.Peer.Object)})
	}
	return out, nil
}
