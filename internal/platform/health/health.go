// Package health serves the anonymous platform probes /health/live and /health/ready (AN-1).
//
// The probes are reachable by anyone who can reach the port, so they say nothing about the
// installation (TM §7.6, rules for AN-1): the 200 body is {"status":"ok"} and every failure is a
// problem without a detail member. Why a check failed goes to the server log only.
package health

import (
	"context"
	"log/slog"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/health/api"
)

// Check probes one dependency. Its error text is for the log; it never reaches a client.
type Check func(ctx context.Context) error

// NamedCheck labels a Check for the log.
type NamedCheck struct {
	Name  string
	Check Check
}

// Handlers implements api.Handlers.
type Handlers struct {
	checks []NamedCheck
	log    *slog.Logger
}

var _ api.Handlers = (*Handlers)(nil)

// New builds the handlers. Readiness is ready when every check passes. A nil log uses slog.Default.
func New(log *slog.Logger, checks ...NamedCheck) *Handlers {
	if log == nil {
		log = slog.Default()
	}
	return &Handlers{checks: checks, log: log}
}

// GetLiveness answers 200 while the process can serve a request.
func (h *Handlers) GetLiveness(context.Context, api.GetLivenessInput) (api.GetLivenessOutput, error) {
	return api.GetLiveness200{Body: api.HealthStatus{Status: api.HealthStateOk}}, nil
}

// GetReadiness answers 200 when every dependency check passes, otherwise 503 /problems/not-ready
// with no detail. A check that panics is left to apihost's recover: 500 /problems/internal, also
// without detail, the panic text in the log only.
func (h *Handlers) GetReadiness(ctx context.Context, _ api.GetReadinessInput) (api.GetReadinessOutput, error) {
	for _, c := range h.checks {
		if err := c.Check(ctx); err != nil {
			h.log.Warn("readiness check failed", "check", c.Name, "error", err)
			return nil, apitypes.NotReady("")
		}
	}
	return api.GetReadiness200{Body: api.HealthStatus{Status: api.HealthStateOk}}, nil
}
