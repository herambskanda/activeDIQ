package operation

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// tmplAuthz records what the Runner's bound gate passes to the unbound check.
type tmplAuthz struct {
	chain    authority.Chain
	tenant   string
	template string
	calls    int
	err      error
}

func (a *tmplAuthz) CheckTemplate(ctx context.Context, c authority.Chain, _ authz.Permission, tpl string) error {
	a.calls++
	a.chain, a.template = c, tpl
	a.tenant, _ = authority.TenantFrom(ctx)
	return a.err
}

// AC1: the gate uses the operation's own chain and tenant (RunStore path); the Plan names neither.
func TestTemplateGateIsBoundToTheOperationChainAndTenant(t *testing.T) {
	ta := &tmplAuthz{}
	r, _ := newRunner(t, behaviour{verifyOK: true, template: "tpl-1"}, nil, factsFake{}, sink{})
	r.cfg.TemplateAuthz = ta
	rq := req()
	if _, err := r.RunStore(context.Background(), rq); err != nil {
		t.Fatal(err)
	}
	if ta.calls != 1 || ta.chain.Requester.ID != "alice" || ta.tenant != rq.Tenant.String() || ta.template != "tpl-1" {
		t.Fatalf("calls=%d chain=%+v tenant=%q template=%q", ta.calls, ta.chain, ta.tenant, ta.template)
	}
}

// AC1 (submit path): the same binding when Submit plans with the stored operation's chain.
func TestTemplateGateBindingSubmitPath(t *testing.T) {
	ta := &tmplAuthz{}
	tn := tenant.New()
	chain := authority.Chain{Requester: authority.Principal{ID: "bob", Kind: authority.Human}}
	g := templateGate{authz: ta, chain: chain, tenant: tn}
	if err := g.CheckTemplate(context.Background(), "p", "tpl-2"); err != nil {
		t.Fatal(err)
	}
	if ta.chain.Requester.ID != "bob" || ta.tenant != tn.String() {
		t.Fatalf("chain=%+v tenant=%q", ta.chain, ta.tenant)
	}
	// A tenant on the caller's context is overridden by the operation's.
	if err := g.CheckTemplate(authority.WithTenant(context.Background(), "other"), "p", "tpl-2"); err != nil || ta.tenant != tn.String() {
		t.Fatalf("err=%v tenant=%q", err, ta.tenant)
	}
}

// AC2: a nil TemplateAuthz denies.
func TestNilTemplateAuthzDenies(t *testing.T) {
	err := templateGate{}.CheckTemplate(context.Background(), "p", "tpl")
	var pr *PlanRefusal
	if !errors.As(err, &pr) || pr.Code != "template_not_permitted" {
		t.Fatalf("err = %v", err)
	}
	r, db := newRunner(t, behaviour{verifyOK: true, template: "tpl"}, nil, factsFake{}, sink{}) // no TemplateAuthz
	if _, err := r.RunStore(context.Background(), req()); !errors.Is(err, ErrDenied) || len(db.writes) != 0 {
		t.Fatalf("err=%v writes=%v", err, db.writes)
	}
}

// AC3: a refusal surfaces as PlanRefusal template_not_permitted: audited as a denial on a run.
func TestTemplateRefusalIsAuditedAsDenied(t *testing.T) {
	ta := &tmplAuthz{err: errors.New("template not permitted")}
	r, db := newRunner(t, behaviour{verifyOK: true, template: "other"}, nil, factsFake{}, sink{})
	r.cfg.TemplateAuthz = ta
	_, err := r.RunStore(context.Background(), req())
	if !errors.Is(err, ErrDenied) || len(db.writes) != 0 {
		t.Fatalf("err=%v writes=%v", err, db.writes)
	}
	if len(db.committed) != 1 || db.committed[0].Outcome != audit.Denied || db.committed[0].Reason != "template_not_permitted" {
		t.Fatalf("events = %+v", db.committed)
	}
}
