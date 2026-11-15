package connections

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/modules/connections/entra"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/egress"
	"github.com/skenzeriq/activediq/internal/platform/operation"
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

// attestationHandlers wires the TM-D17 attestation: the real token-exchange and Graph adapters over the
// egress client, the shared authorizer, and the callback gate. It returns false when the install has not
// configured an attestation app registration, so the module registers no route for it.
func attestationHandlers(deps platform.Deps) (*AttestHandlers, bool, error) {
	if deps.Attestation.ClientID == "" {
		return nil, false, nil
	}
	hc, err := egress.New(egress.Config{})
	if err != nil {
		return nil, false, fmt.Errorf("connections: attestation egress: %w", err)
	}
	if deps.Attestation.Origin == "" {
		return nil, false, fmt.Errorf("connections: attestation needs the public origin for its redirect URI")
	}
	at, err := NewAttester(AttestConfig{
		DB: deps.DB, Audit: deps.Audit, Authz: connectionAuthorizer{deps.Authz}, StepUp: sessionStepUp{deps.StepUp},
		IdP:      &entra.OIDCIdP{HTTP: hc, Authority: entraAuthority, ClientID: deps.Attestation.ClientID},
		Graph:    &entra.GraphReader{HTTP: hc, Base: graphBase},
		ClientID: deps.Attestation.ClientID, RedirectURI: deps.Attestation.Origin + attestCallbackPath, Authority: entraAuthority,
		Component: "connections",
	})
	if err != nil {
		return nil, false, fmt.Errorf("connections: attester: %w", err)
	}
	return &AttestHandlers{Attester: at, Gate: &WindowGate{}}, true, nil
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
