package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

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
)

// consoleStack is the console authentication stack the API ports and the attestation share: one session
// store, the cookie-session Authenticator over it, and the step-up check over the same store.
//
// StepUp carries no TOTP factor yet: the tenant data-encryption-key source authn.Service needs is not
// composed (no keys.DEK provider exists in the server role). Fresh and FreshSession only read mfa_at, so
// they work; Reverify refuses ("not fully configured"), which is the safe direction.
type consoleStack struct {
	Sessions *authn.Store
	StepUp   *authn.StepUp
	Authn    *authnhttp.Authenticator
}

func buildConsole(db *store.DB, sink audit.Sink, log *slog.Logger) (*consoleStack, error) {
	sessions, err := authn.New(authn.Config{DB: db, Audit: sink})
	if err != nil {
		return nil, fmt.Errorf("server: session store: %w", err)
	}
	au, err := authnhttp.NewAuthenticator(sessions, log)
	if err != nil {
		return nil, fmt.Errorf("server: session authenticator: %w", err)
	}
	return &consoleStack{Sessions: sessions, StepUp: &authn.StepUp{Sessions: sessions}, Authn: au}, nil
}

// ports are the API ports with the real authentication, RBAC and step-up behind the given limiter.
func (c *consoleStack) ports(lim apihost.Limiter, az operation.Authorizer) apihost.Ports {
	return apihost.Ports{Authn: c.Authn, Authz: consoleAuthz{az}, Limits: lim, StepUp: c.StepUp}
}

// consoleAuthz is apihost's chain step 12: may this principal hold the operation's permission at all.
// It asks the shared RBAC authorizer at tenant scope (the tenant store root), deny by default: only a
// console session is a principal here (an API token's constraint is not read yet, so it is refused), and
// a platform-scoped operation has no authorizer yet. An operation whose object scope is narrower than the
// tenant is authorised again by its own handler against the real target (the attestation does).
type consoleAuthz struct{ az operation.Authorizer }

func (a consoleAuthz) Allow(ctx context.Context, p apihost.Principal, permission, scope string) (bool, error) {
	if a.az == nil || scope != "tenant" || p.Kind != apihost.KindSession || p.ID == "" {
		return false, nil
	}
	t, err := tenantref.TenantFromText(p.Tenant)
	if err != nil {
		return false, nil
	}
	chain := authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(p.ID), Kind: authority.Human}}
	target := authority.TargetRef{Class: rbac.TargetClassTenant, GUID: t.String()} // the tenant store root
	err = a.az.Authorize(authority.WithTenant(ctx, t.String()), chain, authz.Permission(permission), target, authority.Facts{})
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, rbac.ErrDenied):
		return false, nil
	default:
		return false, err // an infrastructure fault: the chain refuses
	}
}
