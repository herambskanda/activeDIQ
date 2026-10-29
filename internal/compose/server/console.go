package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

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
// StepUp carries the TOTP factor: authn.Service over the tenant data-encryption-key source (the store-backed
// keys.KeySource, unwrapped by the boot-unlocked KEK provider) and the store as its failure recorder. A
// tenant with no active key, or a failed unwrap, makes Reverify refuse (fail closed, "keys: <Code>" only).
type consoleStack struct {
	Sessions *authn.Store
	StepUp   *authn.StepUp
	Authn    *authnhttp.Authenticator
	// Denials, when set, records every refused permission check in the audit trail.
	Denials *deniedAudit
}

// deniedAudit is what ports needs to record refusals: the store and the audit sink.
type deniedAudit struct {
	DB   *store.DB
	Sink audit.Sink
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
	return &consoleStack{Sessions: sessions, StepUp: &authn.StepUp{Sessions: sessions, TOTP: totp}, Authn: au,
		Denials: &deniedAudit{DB: db, Sink: sink}}, nil
}

// ports are the API ports with the real authentication, RBAC and step-up behind the given limiter.
func (c *consoleStack) ports(lim apihost.Limiter, az operation.Authorizer) apihost.Ports {
	var authz apihost.Authorizer = consoleAuthz{az}
	if d := c.Denials; d != nil {
		authz = auditedAuthz{next: authz, db: d.DB, sink: d.Sink, now: time.Now, log: slog.Default()}
	}
	return apihost.Ports{Authn: c.Authn, Authz: authz, Limits: lim, StepUp: c.StepUp}
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
