package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync/atomic"
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
	// WebAuthn is AN-10 with a security key. It is nil unless the install has a public URL (the relying
	// party), and while nil its two routes answer 501.
	WebAuthn *authn.WebAuthnFactor
	// Denials, when set, records every refused permission check in the audit trail.
	Denials *deniedAudit
	log     *slog.Logger
	tenant  atomic.Pointer[tenant.ID]
}

// SetTenant tells the sign-in plane which tenant the install has; until then AN-8 answers a server fault.
func (c *consoleStack) SetTenant(t tenant.ID) { c.tenant.Store(&t) }

func (c *consoleStack) installTenant() (id tenant.ID, ok bool) {
	if p := c.tenant.Load(); p != nil {
		return *p, true
	}
	return id, false // the zero value, named: compose never composes a tenant.ID (ADR-0002 rule 5)
}

// Tags is the sign-in plane (/auth/*): AN-8 for a local account and AN-10 with TOTP, and with WebAuthn when
// the install has a public URL. Without one the WebAuthn routes stay 501 (the field is left a nil interface,
// not a wrapper around a nil factor). Sign-out and the CSRF value answer 501 until their tickets land.
func (c *consoleStack) Tags() apihost.TagHandlers {
	h := authn.Handlers{
		Password:     authnhttp.PasswordCookies{Factor: c.Local},
		SecondFactor: authnhttp.TOTPCookies{Factor: c.Second},
		Log:          c.log,
	}
	if c.WebAuthn != nil {
		h.WebAuthn = authnhttp.WebAuthnCookies{Factor: c.WebAuthn}
	}
	return h.Bind()
}

// webAuthnRelyingParty derives the relying party from the install's public URL, the https origin browsers
// use: the RP ID is the origin's hostname without port and the one allowed origin is the origin itself
// (scheme, host and port, no path). config validates the shape; a value that is not an https origin is
// refused here too, because this is the binding that decides which pages may sign a user in.
func webAuthnRelyingParty(publicURL string) (authn.WebAuthnConfig, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return authn.WebAuthnConfig{}, errors.New("server: WebAuthn: the public URL is not an https origin")
	}
	return authn.WebAuthnConfig{RPID: u.Hostname(), RPDisplayName: "activeDIQ", Origins: []string{"https://" + u.Host}}, nil
}

// consoleOption adjusts buildConsole.
type consoleOption func(*consoleOptions)

type consoleOptions struct{ publicURL string }

// withPublicURL is the install's ACTIVEDIQ_PUBLIC_URL; with it the console offers WebAuthn sign-in.
func withPublicURL(u string) consoleOption { return func(o *consoleOptions) { o.publicURL = u } }

// deniedAudit is what ports needs to record refusals: the store and the audit sink.
type deniedAudit struct {
	DB   *store.DB
	Sink audit.Sink
}

func buildConsole(db *store.DB, sink audit.Sink, ks authn.KeySource, log *slog.Logger, opts ...consoleOption) (*consoleStack, error) {
	var o consoleOptions
	for _, f := range opts {
		f(&o)
	}
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
	c := &consoleStack{Sessions: sessions, StepUp: &authn.StepUp{Sessions: sessions, TOTP: totp}, Authn: au, log: log,
		Denials: &deniedAudit{DB: db, Sink: sink}}
	c.Local = &authn.LocalCredentials{DB: db, Sessions: sessions, Pending: pending, Keys: ks, Audit: sink, Tenant: c.installTenant}
	c.Second = &authn.SecondFactor{DB: db, Pending: pending, Sessions: sessions, TOTP: totp, Audit: sink}
	if o.publicURL == "" {
		// One line at start-up, so an operator who expected security-key sign-in is told it is off.
		if log != nil {
			log.Info("WebAuthn sign-in is off: ACTIVEDIQ_PUBLIC_URL is not set")
		}
		return c, nil
	}
	rp, err := webAuthnRelyingParty(o.publicURL)
	if err != nil {
		return nil, err
	}
	if c.WebAuthn, err = authn.NewWebAuthnFactor(rp, db, pending, sessions, sink); err != nil {
		return nil, fmt.Errorf("server: WebAuthn factor: %w", err)
	}
	return c, nil
}

// ports are the API ports with the real authentication, RBAC and step-up behind the given limiter.
func (c *consoleStack) ports(lim apihost.Limiter, az operation.Authorizer, cat apihost.Permissions) apihost.Ports {
	var authz apihost.Authorizer = consoleAuthz{az, cat}
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
