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
	ID   string
	Kind PrincipalKind
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
