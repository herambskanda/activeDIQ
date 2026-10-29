package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authn/tenantref"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/httpx/authnhttp"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// consoleStack is the console authentication stack the API ports and the attestation share: one session
// store, the cookie-session Authenticator over it, and the step-up check over the same store.
//
// StepUp carries the TOTP factor: authn.Service over the tenant data-encryption-key source (the store-backed
// keys.KeySource, unwrapped by the boot-unlocked KEK provider) and the store as its failure recorder. A
// tenant with no active key, or a failed unwrap, makes Reverify refuse (fail closed, "keys: <Code>" only).
type consoleStack struct {
	Sessions *authn.Store
	StepUp   *authn.StepUp
	Authn    *authnhttp.Authenticator
	// Local is AN-8 and Second is AN-10 TOTP: the sign-in plane Tags mounts. Local resolves the install's
	// tenant through SetTenant, which Run calls once the tenant exists.
	Local  *authn.LocalCredentials
	Second *authn.SecondFactor
	log    *slog.Logger
	tenant atomic.Pointer[tenant.ID]
}

// SetTenant tells the sign-in plane which tenant the install has; until then AN-8 answers a server fault.
func (c *consoleStack) SetTenant(t tenant.ID) { c.tenant.Store(&t) }

func (c *consoleStack) installTenant() (tenant.ID, bool) {
	if p := c.tenant.Load(); p != nil {
		return *p, true
	}
	return tenant.ID{}, false
}

// Tags is the sign-in plane (/auth/*): AN-8 for a local account and AN-10 with TOTP. WebAuthn, sign-out and
// the CSRF value answer 501 until their tickets land.
func (c *consoleStack) Tags() apihost.TagHandlers {
	return authn.Handlers{
		Password:     authnhttp.PasswordCookies{Factor: c.Local},
		SecondFactor: authnhttp.TOTPCookies{Factor: c.Second},
		Log:          c.log,
	}.Bind()
}

func buildConsole(db *store.DB, sink audit.Sink, ks authn.KeySource, log *slog.Logger) (*consoleStack, error) {
	sessions, err := authn.New(authn.Config{DB: db, Audit: sink})
	if err != nil {
		return nil, fmt.Errorf("server: session store: %w", err)
	}
	au, err := authnhttp.NewAuthenticator(sessions, log)
	if err != nil {
		return nil, fmt.Errorf("server: session authenticator: %w", err)
	}
	if ks == nil {
		return nil, errors.New("server: console: no tenant key source for the TOTP factor")
	}
	totp := &authn.Service{Keys: ks, Failures: db}
	pending, err := authn.NewPendingStore(db, sink, nil)
	if err != nil {
		return nil, fmt.Errorf("server: pending sign-ins: %w", err)
	}
	c := &consoleStack{Sessions: sessions, StepUp: &authn.StepUp{Sessions: sessions, TOTP: totp}, Authn: au, log: log}
	c.Local = &authn.LocalCredentials{DB: db, Sessions: sessions, Pending: pending, Keys: ks, Audit: sink, Tenant: c.installTenant}
	c.Second = &authn.SecondFactor{DB: db, Pending: pending, Sessions: sessions, TOTP: totp, Audit: sink}
	return c, nil
}

// ports are the API ports with the real authentication, RBAC and step-up behind the given limiter.
func (c *consoleStack) ports(lim apihost.Limiter, az operation.Authorizer, cat apihost.Permissions) apihost.Ports {
	return apihost.Ports{Authn: c.Authn, Authz: consoleAuthz{az, cat}, Limits: lim, StepUp: c.StepUp}
}

// consoleAuthz is apihost's chain step 12: may this principal hold the operation's permission at all.
// It asks the shared RBAC authorizer at tenant scope (the tenant store root), deny by default: only a
// console session is a principal here (an API token's constraint is not read yet, so it is refused), and
// a platform-scoped operation has no authorizer yet. An operation whose object scope is narrower than the
// tenant is authorised again by its own handler against the real target (the attestation does).
type consoleAuthz struct {
	az  operation.Authorizer
	cat apihost.Permissions // the permission catalogue: a permission outside it is denied before RBAC is asked
}

func (a consoleAuthz) Allow(ctx context.Context, p apihost.Principal, permission, scope string) (bool, error) {
	if a.az == nil || !a.cat.Has(permission) || scope != "tenant" || p.Kind != apihost.KindSession || p.ID == "" {
		return false, nil
	}
	t, err := tenantref.TenantFromText(p.Tenant)
	if err != nil {
		return false, nil
	}
	chain := authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(p.ID), Kind: authority.Human}}
	target := authority.TargetRef{Class: rbac.TargetClassTenant, GUID: t.String()} // the tenant store root
	err = a.az.Authorize(authority.WithAuthorityFactor(authority.WithTenant(ctx, t.String()), p.AuthorityFactor), chain, authz.Permission(permission), target, authority.Facts{})
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, rbac.ErrDenied):
		return false, nil
	default:
		return false, err // an infrastructure fault: the chain refuses
	}
}
