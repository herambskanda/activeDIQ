package server

import (
	"context"
	"net/http"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

// apiCatalogue is the EP-6 permission set; it is empty until the permission catalogue lands, so any
// operation with a real permission fails Build rather than being served unguarded.
var apiCatalogue = apihost.Permissions{}

// failClosedPorts are the ports until the auth, RBAC, rate-limit and step-up kernels exist. They
// refuse everything, so a route mounted before the real ports are injected cannot be reached.
func failClosedPorts() apihost.Ports {
	return apihost.Ports{Authn: denyAuthn{}, Authz: denyAuthz{}, Limits: denyLimits{}, StepUp: denyStepUp{}}
}

type denyAuthn struct{}

func (denyAuthn) Authenticate(*http.Request) (apihost.Principal, error) {
	return apihost.Principal{}, apihost.ErrUnauthenticated
}
func (denyAuthn) CheckCSRF(*http.Request, apihost.Principal) error { return apihost.ErrCSRF }

type denyAuthz struct{}

func (denyAuthz) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return false, nil
}

type denyLimits struct{}

func (denyLimits) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{RetryAfter: time.Second}, nil
}
func (denyLimits) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{RetryAfter: time.Second}, nil
}

type denyStepUp struct{}

func (denyStepUp) Fresh(context.Context, apihost.Principal) (bool, error) { return false, nil }
