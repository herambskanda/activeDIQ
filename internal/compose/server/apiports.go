package server

import (
	"context"
	"net/http"

	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/notify/syslog"
)

// APIPolicy is the policy the server passes to apihost.Build: policy.yaml as embedded in the binary
// (policy.gen.json, parsed by apihost.ParsePolicy). fitness-api A4 compares it with the policy.yaml it
// reads from the tree. It panics if the embedded policy does not parse; TestEmbeddedPolicyBuilds and
// gen-api -check keep that from shipping.
func APIPolicy() apihost.Policy {
	p, err := apihost.LoadPolicy()
	if err != nil {
		panic("server: embedded api policy: " + err.Error())
	}
	return p
}

// apiCatalogue is the EP-6 permission set as far as mounted operations use it: Build fails an operation
// whose permission is missing here rather than serving it unguarded.
var apiCatalogue = apihost.Permissions{string(connections.TakeoverAttestPermission), syslog.ManagePermission, syslog.ReadPermission}

// failClosedPorts are the ports with no console stack behind them: authentication, RBAC and step-up
// refuse everything, so a route mounted on them cannot be reached. Tests use them; Run mounts
// consoleStack.ports instead. Limits is the real limiter (per-IP in memory, per-principal in the shared
// store).
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
