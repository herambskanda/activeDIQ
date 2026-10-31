package server

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authn/negotiate"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// sidSource is the inventory read the Negotiate directory port needs (inventory.Reader).
type sidSource interface {
	ObjectsBySID(ctx context.Context, t tenant.ID, s sid.SID) ([]inventory.Ref, error)
}

// negotiateDirectory fills negotiate.Directory (T-0945): the platform sign-in core names a principal by
// canonical SID text and gets authn.DirectoryRef values back, and this adapter, in the composition root,
// is the only place that knows the SID codec and the inventory.
//
// A SID that does not parse, or that the inventory refuses as invalid (the zero SID), is an empty
// answer, which negotiate refuses as unmapped (NEG-2). The matches are capped at
// inventory.MaxSIDMatches; negotiate treats more than one as ambiguous. Any other read error is
// returned as an infrastructure failure.
type negotiateDirectory struct{ src sidSource }

var _ negotiate.Directory = negotiateDirectory{}

func (d negotiateDirectory) ObjectsBySID(ctx context.Context, t tenant.ID, text string) ([]authn.DirectoryRef, error) {
	s, err := sid.Parse(text)
	if err != nil {
		return nil, nil
	}
	refs, err := d.src.ObjectsBySID(ctx, t, s)
	if errors.Is(err, inventory.ErrInvalid) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(refs) > inventory.MaxSIDMatches {
		refs = refs[:inventory.MaxSIDMatches]
	}
	out := make([]authn.DirectoryRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, authn.DirectoryRef{ConnectionID: string(r.Connection), ObjectGUID: string(r.Object)})
	}
	return out, nil
}
