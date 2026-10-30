package server

import (
	"context"
	"net/http"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

// failClosedPorts are test ports with no console stack behind them: authentication, RBAC and step-up
// refuse everything, so a route mounted on them cannot be reached. Limits is the given limiter.
func failClosedPorts(lim apihost.Limiter) apihost.Ports {
	return apihost.Ports{Authn: denyAuthn{}, Authz: denyAuthz{}, Limits: lim, StepUp: denyStepUp{}}
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

type denyStepUp struct{}

func (denyStepUp) Fresh(context.Context, apihost.Principal) (bool, error) { return false, nil }
