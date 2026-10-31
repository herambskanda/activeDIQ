package server

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// fakeAz records the target of the one Authorize call and answers with err.
type fakeAz struct {
	err    error
	target authority.TargetRef
	perm   authz.Permission
	ctx    context.Context
}

func (f *fakeAz) FactsQuery(authority.Chain, authz.Permission, authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{}
}

func (f *fakeAz) Authorize(ctx context.Context, _ authority.Chain, p authz.Permission, t authority.TargetRef, _ authority.Facts) error {
	f.ctx, f.perm, f.target = ctx, p, t
	return f.err
}

// reportsAuthz fails closed and asks at tenant scope (security review F3).
func TestReportsAuthz(t *testing.T) {
	tid := tenant.New()
	chain := authority.Chain{Requester: authority.Principal{ID: "u1", Kind: authority.Human}}
	infra := errors.New("rbac store down")
	for _, tc := range []struct {
		name    string
		az      *fakeAz
		nilAz   bool
		wantOK  bool
		wantErr bool
	}{
		{name: "no authorizer", nilAz: true},
		{name: "denied", az: &fakeAz{err: fmt.Errorf("wrapped: %w", rbac.ErrDenied)}},
		{name: "infrastructure fault", az: &fakeAz{err: infra}, wantErr: true},
		{name: "allowed", az: &fakeAz{}, wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := reportsAuthz{}
			if !tc.nilAz {
				a.az = tc.az
			}
			ok, err := a.Allow(context.Background(), tid, chain, "reports.run")
			if ok != tc.wantOK || (err != nil) != tc.wantErr {
				t.Fatalf("Allow = %v, %v; want %v, err %v", ok, err, tc.wantOK, tc.wantErr)
			}
			if tc.nilAz {
				return
			}
			if tc.az.perm != "reports.run" || tc.az.target.Class != rbac.TargetClassTenant || tc.az.target.GUID != tid.String() {
				t.Errorf("asked %q on %+v", tc.az.perm, tc.az.target)
			}
		})
	}
}

// Off a request (the rerun job runs with no principal) the authority factor is absent: a grant that needs it
// is refused, never assumed. The present-factor path takes apihost.PrincipalFrom, which only the API host
// can set, so it is not unit-tested here.
func TestReportsAuthzWithoutPrincipalHasNoAuthorityFactor(t *testing.T) {
	tid := tenant.New()
	chain := authority.Chain{Requester: authority.Principal{ID: "u1", Kind: authority.Human}}
	f := &fakeAz{}
	if _, err := (reportsAuthz{az: f}).Allow(context.Background(), tid, chain, "reports.run"); err != nil {
		t.Fatal(err)
	}
	if authority.AuthorityFactorFrom(f.ctx) {
		t.Error("an authority factor appeared with no principal")
	}
}
