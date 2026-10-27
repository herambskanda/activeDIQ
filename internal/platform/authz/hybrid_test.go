package authz_test

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authz"
)

// TM-D17 (threat model §6.8 rules 1, 4, 5): the hybrid gate.

func matched() *authz.Correlation {
	return &authz.Correlation{State: authz.CorrelationMatched, Takeover: authz.TakeoverAttested}
}

func derived(c *authz.Correlation, perms ...authz.Permission) *authz.Principal {
	return &authz.Principal{ID: "sso", Assignments: []authz.Assignment{{
		Role: authz.Role{Permissions: perms}, Scope: scope(root("ou-sales", domain)),
		Via: &authz.Derivation{Correlation: c},
	}}}
}

func TestHybridGateMatchedApplies(t *testing.T) {
	d := evaluator().Authorize(derived(matched(), reset), nil, reset, obj("u1", "ou-sales", domain))
	if !d.Allowed || len(d.HybridRefusals) != 0 {
		t.Fatalf("matched correlation must apply: %+v", d)
	}
}

func TestHybridGateCandidateDenied(t *testing.T) {
	cases := map[string]string{
		"candidate": "tenant_takeover_open", "forged": "not_synced", "sid_mismatch": "sid_mismatch",
		"cloud_managed": "cloud_managed", "once_cloud_only": "reconfirm_required",
	}
	for name, why := range cases {
		c := matched()
		c.State, c.Reason = "candidate", why
		d := evaluator().Authorize(derived(c, reset), nil, reset, obj("u1", "ou-sales", domain))
		if d.Allowed || d.Reason != authz.ReasonHybridNotMatched {
			t.Fatalf("%s: %+v", name, d)
		}
		if len(d.HybridRefusals) != 1 || d.HybridRefusals[0].CorrelationReason != why {
			t.Fatalf("%s: refusal not carried for audit: %+v", name, d.HybridRefusals)
		}
	}
	for _, st := range []string{"broken", "", "removed"} {
		c := matched()
		c.State = st
		if d := evaluator().Authorize(derived(c, reset), nil, reset, obj("u1", "ou-sales", domain)); d.Allowed {
			t.Fatalf("state %q must not carry authority", st)
		}
	}
	if d := evaluator().Authorize(derived(nil, reset), nil, reset, obj("u1", "ou-sales", domain)); d.Allowed {
		t.Fatal("missing correlation facts must refuse")
	}
}

func TestHybridGateNeverCrossesTenantOwner(t *testing.T) {
	for _, p := range []authz.Permission{"rbac.assign", "delegation.scope.edit", "connections.hybrid_link.confirm", "connections.takeover.attest"} {
		d := evaluator().Authorize(derived(matched(), p), nil, p, obj("u1", "ou-sales", domain))
		if d.Allowed || d.Reason != authz.ReasonHybridNeverCrosses {
			t.Fatalf("%s crossed: %+v", p, d)
		}
	}
	owner := derived(matched(), reset)
	owner.Assignments[0].Role.TenantOwner = true
	if d := evaluator().Authorize(owner, nil, reset, obj("u1", "ou-sales", domain)); d.Allowed {
		t.Fatal("tenant-owner role crossed a correlation")
	}
	// The same permission granted directly still works: it is the crossing that is refused.
	direct := holder("console", []authz.Permission{"rbac.assign"}, scope(root("ou-sales", domain)))
	if !evaluator().Authorize(direct, nil, "rbac.assign", obj("u1", "ou-sales", domain)).Allowed {
		t.Fatal("direct grant must be unaffected")
	}
}

func TestHybridGateTier0Refused(t *testing.T) {
	c := matched()
	c.Tier0Either = true
	d := evaluator().Authorize(derived(c, reset), nil, reset, obj("u1", "ou-sales", domain))
	if d.Allowed || d.Reason != authz.ReasonHybridTier0 {
		t.Fatalf("tier0 correlation side: %+v", d)
	}
	tg := obj("u1", "ou-sales", domain)
	tg.CorrelatedTier0 = true
	d = evaluator().Authorize(derived(matched(), reset), nil, reset, tg)
	if d.Allowed || d.Reason != authz.ReasonHybridTier0 {
		t.Fatalf("target with tier0 peer: %+v", d)
	}
}

func TestHybridGateUnattestedDegradedMode(t *testing.T) {
	for _, st := range []string{"unattested", "open", "stale", ""} {
		c := matched()
		c.Takeover = st
		p := derived(c, reset)
		// Add a direct grant: it keeps working while the derived one is denied.
		p.Assignments = append(p.Assignments, authz.Assignment{
			Role: authz.Role{Permissions: []authz.Permission{del}}, Scope: scope(root("ou-sales", domain))})
		tg := obj("u1", "ou-sales", domain)
		d := evaluator().Authorize(p, nil, reset, tg)
		if d.Allowed || d.Reason != authz.ReasonHybridUnattested {
			t.Fatalf("%q: derived grant applied: %+v", st, d)
		}
		if !evaluator().Authorize(p, nil, del, tg).Allowed {
			t.Fatalf("%q: direct grant must still apply", st)
		}
	}
}

func TestHybridGateRefusalAuditedEvenWhenDirectAllows(t *testing.T) {
	c := matched()
	c.State = "candidate"
	p := derived(c, reset)
	p.Assignments = append(p.Assignments, authz.Assignment{
		Role: authz.Role{Permissions: []authz.Permission{reset}}, Scope: scope(root("ou-sales", domain))})
	d := evaluator().Authorize(p, nil, reset, obj("u1", "ou-sales", domain))
	if !d.Allowed || len(d.HybridRefusals) != 1 {
		t.Fatalf("direct allows, refusal still reported: %+v", d)
	}
}
