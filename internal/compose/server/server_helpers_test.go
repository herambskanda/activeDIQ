package server

import (
	"fmt"
	"net/http"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

// buildAPI makes the API handler: apihost.Build over the embedded contract and the embedded
// policy.yaml, with the body budget from configuration. A tag no module contributes is unmounted and
// answers a problem.
func buildAPI(cfg config.Config, lim apihost.Limiter, tags ...apihost.TagHandlers) (http.Handler, error) {
	policy, err := apihost.LoadPolicy()
	if err != nil {
		return nil, fmt.Errorf("server: api policy: %w", err)
	}
	return buildAPIPortsWith(cfg, policy, failClosedPorts(lim), tags...)
}

// buildAPIWith is buildAPI over a given policy; tests use it to prove the router follows policy.yaml.
func buildAPIWith(cfg config.Config, policy apihost.Policy, lim apihost.Limiter, tags ...apihost.TagHandlers) (http.Handler, error) {
	return buildAPIPortsWith(cfg, policy, failClosedPorts(lim), tags...)
}
