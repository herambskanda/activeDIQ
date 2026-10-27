package apihost

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// PrincipalKind says how a principal authenticated. It decides whether the CSRF check applies.
type PrincipalKind string

const (
	KindSession PrincipalKind = "session" // browser cookie session: unsafe methods need the CSRF header
	KindToken   PrincipalKind = "token"   // bearer API token or OAuth client: exempt from CSRF
)

// Principal is who a request acts as. apihost passes it to the ports and to the handler's context;
// it never inspects an identity beyond this.
type Principal struct {
	ID string
	// Tenant is the tenant the principal belongs to, as derived by the Authenticator (ADR-0002 rule 5).
	// The rate limiter keys on it, so the same ID in two tenants has two budgets. Empty only for a
	// platform principal.
	Tenant string
	Kind   PrincipalKind
	// SessionID is the console session's handle (not its token) for a KindSession principal; empty for a
	// token. The step-up check reads the session's mfa_at through it.
	SessionID string
}

// ErrUnauthenticated is what an Authenticator returns for a missing or invalid credential. Any
// other error is an internal failure and the request is refused (fail closed).
var ErrUnauthenticated = errors.New("apihost: unauthenticated")

// ErrCSRF is what CheckCSRF returns when the CSRF header is missing or does not match.
var ErrCSRF = errors.New("apihost: csrf check failed")

// Authenticator turns a session cookie or bearer token into a principal (chain step 8) and performs
// the CSRF check for cookie sessions (step 9).
type Authenticator interface {
	Authenticate(r *http.Request) (Principal, error)
	CheckCSRF(r *http.Request, p Principal) error
}

// Authorizer decides principal × x-permission (chain step 12). scope is the operation's
// x-activediq-scope, "tenant" or "platform".
type Authorizer interface {
	Allow(ctx context.Context, p Principal, permission, scope string) (bool, error)
}

// Decision is a rate-limit verdict.
type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
}

// Limiter applies the rate class of the operation (rule 10): per source IP before authentication
// (step 3) and per principal after it (step 10).
type Limiter interface {
	// AllowIP meters the request against the per-IP bucket of class. ip is the source host as
	// apihost resolved it, unvalidated. The adapter must never key a bucket by the raw string.
	// It derives the key as threat model §7.8 ("The per-IP key is a network prefix") requires:
	// parse with net/netip, strip the zone, unmap IPv4-mapped IPv6, and key 64:ff9b::/96 by
	// its embedded IPv4. It then masks IPv4 to /32 and IPv6 to /64 by default. The host
	// configuration may set IPv4 to /24../32 and IPv6 to /48../64; anything else fails startup.
	// Keying IPv6 by full address would hand one /64 2^64 buckets. Unparseable sources share one
	// bucket per class. When the bucket table is full, new keys share one overflow bucket per
	// class, which throttles them and never admits them unlimited.
	AllowIP(ctx context.Context, class, ip string) (Decision, error)
	AllowPrincipal(ctx context.Context, class string, p Principal) (Decision, error)
}

// StepUpChecker reports whether the principal passed a fresh multi-factor check (step 11).
type StepUpChecker interface {
	Fresh(ctx context.Context, p Principal) (bool, error)
}

// Ports is everything apihost needs from kernel packages that themselves serve API (ADR-0004
// rule 5). compose/server injects the implementations; apihost imports none of those packages.
type Ports struct {
	Authn  Authenticator
	Authz  Authorizer
	Limits Limiter
	StepUp StepUpChecker
}

type ctxKey int

const (
	principalKey ctxKey = iota
	traceKey
)

// PrincipalFrom returns the authenticated principal of the request, or false for an anonymous one.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}

// TraceID returns the request's trace ID, the one in its problem responses.
func TraceID(ctx context.Context) string {
	s, _ := ctx.Value(traceKey).(string)
	return s
}

func withTrace(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, traceKey, id)
}

func withPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}
