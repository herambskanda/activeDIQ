package server

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/server/entra"
	"github.com/skenzeriq/activediq/internal/modules/connections"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/egress"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

const (
	// entraAuthority and graphBase are the only two destinations the attestation talks to. Both go through
	// the egress client, never a client of their own (FF-SP2).
	entraAuthority = "https://login.microsoftonline.com"
	graphBase      = "https://graph.microsoft.com/v1.0"
	// attestCallbackPath is the callback's path under the public origin; it is the registered redirect URI.
	attestCallbackPath = "/api/v1/connections/takeover-attestation/callback"
)

// buildAttestation wires the TM-D17 attestation: the real token-exchange and Graph adapters over the
// egress client, the shared authorizer, and the callback gate. It returns no tags when the install has not
// configured an attestation app registration, so the routes stay unmounted.
func buildAttestation(cfg config.Config, db *store.DB, sink audit.Sink, az operation.Authorizer, su connections.StepUp) ([]apihost.TagHandlers, error) {
	if cfg.AttestClientID == "" {
		return nil, nil
	}
	hc, err := egress.New(egress.Config{})
	if err != nil {
		return nil, fmt.Errorf("server: attestation egress: %w", err)
	}
	at, err := connections.NewAttester(connections.AttestConfig{
		DB: db, Audit: sink, Authz: connectionAuthorizer{az}, StepUp: su,
		IdP:      &entra.OIDCIdP{HTTP: hc, Authority: entraAuthority, ClientID: cfg.AttestClientID},
		Graph:    &entra.GraphReader{HTTP: hc, Base: graphBase},
		ClientID: cfg.AttestClientID, RedirectURI: publicOrigin(cfg.PublicURL) + attestCallbackPath, Authority: entraAuthority,
		Component: "connections",
	})
	if err != nil {
		return nil, fmt.Errorf("server: attester: %w", err)
	}
	h := &connections.AttestHandlers{Attester: at, Gate: &connections.WindowGate{}}
	return []apihost.TagHandlers{h.Bind()}, nil
}

func publicOrigin(u string) string {
	for len(u) > 0 && u[len(u)-1] == '/' {
		u = u[:len(u)-1]
	}
	return u
}

// connectionAuthorizer adapts the operation Authorizer's two-step question to the single call the
// Attester makes. The attestation's target is the entra_tenant scope of a connection: the connection is
// the top of its own chain, so it has no ancestors and no live directory read could add any. The facts
// say exactly that (it exists, its chain is complete, it is not a Tier-0 object) and only for a target
// shaped that way; any other target gets empty facts, which RBAC refuses (target_facts_incomplete).
// Without them every entra_tenant check is refused and the attestation can never start.
type connectionAuthorizer struct{ operation.Authorizer }

func (a connectionAuthorizer) Authorize(ctx context.Context, c authority.Chain, p authz.Permission, t authority.TargetRef) error {
	var f authority.Facts
	if t.Class == "entra_tenant" && t.Connection != "" && t.Connection == t.GUID {
		f = authority.Facts{Exists: true, AncestorsComplete: true}
	}
	return a.Authorizer.Authorize(ctx, c, p, t, f)
}

// sessionStepUp adapts authn.StepUp.FreshSession (tenant + session handle) to the attestation's StepUp
// port. A nil StepUp refuses, so a half-built stack cannot grant a step-up.
type sessionStepUp struct{ u *authn.StepUp }

func (s sessionStepUp) Fresh(ctx context.Context, t tenant.ID, sessionID string) (bool, error) {
	if s.u == nil {
		return false, nil
	}
	return s.u.FreshSession(ctx, t, sessionID)
}
