package server

import (
	"context"
	"net/http"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
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

// apiCatalogue is the EP-6 permission set; it is empty until the permission catalogue lands, so any
// operation with a real permission fails Build rather than being served unguarded.
var apiCatalogue = apihost.Permissions{}

// failClosedPorts are the ports until the auth, RBAC and step-up kernels exist: those three refuse
// everything, so a route mounted before the real ports are injected cannot be reached. Limits is the
// real limiter (per-IP in memory, per-principal in the shared store); with denyAuthn no request reaches
// chain step 10 yet, and once an Authenticator fills Principal.Tenant the limiter meters it unchanged.
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
