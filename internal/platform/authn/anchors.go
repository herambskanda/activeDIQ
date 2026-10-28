package authn

import (
	"context"
	"errors"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ErrAnchorNoMatch: the anchor claim names no directory object (or more than one). The sign-in goes on
// unbound; it never guesses a binding.
var ErrAnchorNoMatch = errors.New("authn: anchor resolves to no single directory object")

// DirectoryAnchors is the kernel's read port into the directory inventory (ADR-0003 F6, blueprint 7.5).
// directory/inventory implements it; compose/server hands it in as a value. authn imports no directory
// package.
type DirectoryAnchors interface {
	// Resolve returns the directory object an SSO anchor names: oid with a tid that matches an Entra
	// connection, or onprem_sid. ErrAnchorNoMatch when there is none or more than one.
	Resolve(ctx context.Context, t tenant.ID, a Anchor) (DirectoryRef, error)
	// Matched reports whether the Entra object and the AD object have a matched correlation (DM-20.I4).
	Matched(ctx context.Context, t tenant.ID, entra, ad DirectoryRef) (bool, error)
}
