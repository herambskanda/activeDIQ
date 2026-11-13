package write

import (
	"context"

	"github.com/skenzeriq/activediq/internal/connector/provider"
	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// adSide is the AD write side of a session-backed provider (provider.SessionBacked): the object
// directory over the provider's one session and the deleted-object classifier. It lives in this
// package because the LDAP write bodies may be imported only here (TM-F-T0GUARD); the provider holds
// the session, the directory and the pins, and this assembles them. It embeds the provider, so
// Classify and the rest of the core are the provider's own.
type adSide struct {
	provider.Provider
	src provider.SessionBacked
	// Dir, Pins and Self are the provider's, read once at New.
	Dir  tier0.ADDirectory
	Pins provider.PinStore
	Self dn.ObjectRef
	// snapshot computes the tier0 set for the member cross-check of kind 6; nil means the AD
	// classifier over Dir. Tests substitute it.
	snapshot func(ctx context.Context, designated []guid.GUID) (*tier0.ADSet, error)
}

var (
	_ ObjectProvider    = (*adSide)(nil)
	_ DeletedClassifier = (*adSide)(nil)
	_ AccountProvider   = (*adSide)(nil)
	_ writeDirectory    = (*adSide)(nil)
)

// newADSide returns the write side of p, or nil when p is not session-backed.
func newADSide(p provider.Provider) *adSide {
	sb, ok := p.(provider.SessionBacked)
	if !ok {
		return nil
	}
	return &adSide{Provider: p, src: sb, Dir: sb.Directory(), Pins: sb.PinStore(), Self: sb.SelfRef()}
}

// WriteDirectory implements writeDirectory.
func (p *adSide) WriteDirectory() ObjectDirectory { return p.src.WriteDirectory() }

// AccountSession implements AccountProvider.
func (p *adSide) AccountSession() AccountSession { return p.src.AccountSession() }

// Objects implements ObjectProvider when the directory and the bound DC are one session.
func (p *adSide) Objects() StructureDirectory {
	s := p.src.OneSession()
	if s == nil {
		return nil
	}
	return SessionObjects{S: s}
}
