package authn

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

// T-0445 acceptance 1: CountActive counts only the tenant's active accounts among ids.
func TestCountActiveCountsOnlyActiveAccountsOfTheTenant(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		ctx := context.Background()
		act1, act2 := activeAcct(t, e, "ca-active-1"), activeAcct(t, e, "ca-active-2")
		dis := activeAcct(t, e, "ca-disabled")
		if _, err := e.a.SetState(ctx, e.ten, dis.ID, AccountDisabled, human); err != nil {
			t.Fatal(err)
		}
		pending := newSSO(t, e, "ca-pending")
		// An active account of another tenant, whose id is passed in too.
		other := tenanttest.Seed(t, e.d.ExecOwner, "t2")
		oa, err := NewAccounts(e.db, e.ss, rbac.Owners{})
		if err != nil {
			t.Fatal(err)
		}
		foreign, err := oa.Create(ctx, NewAccount{Tenant: other, Kind: KindSSO, DisplayName: "f", CreatedBy: "system",
			SSOIssuer: "https://idp.example/", SSOSubject: "f", MFARequired: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := oa.SetState(ctx, other, foreign.ID, AccountActive, human); err != nil {
			t.Fatal(err)
		}
		count := func(ids ...string) int {
			var n int
			if err := e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) (err error) {
				n, err = e.a.CountActive(ctx, tx, e.ten, ids)
				return
			}); err != nil {
				t.Fatal(err)
			}
			return n
		}
		if n := count(act1.ID, act2.ID, dis.ID, pending.ID, foreign.ID, "99999999-9999-4999-8999-999999999999"); n != 2 {
			t.Fatalf("CountActive = %d, want 2", n)
		}
		if n := count(dis.ID, pending.ID, foreign.ID); n != 0 {
			t.Fatalf("CountActive of non-active = %d, want 0", n)
		}
		if n := count(); n != 0 {
			t.Fatalf("CountActive(nil) = %d", n)
		}
		if _, err := e.a.CountActive(ctx, nil, e.ten, []string{act1.ID}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("nil tx: %v", err)
		}
		if _, err := e.a.CountActive(ctx, nil, tenant.ID{}, nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("zero tenant: %v", err)
		}
	})
}

// T-0445 acceptances 3 and 4: granting or revoking an owner assignment ends that account's sessions with
// reason role_changed in the same transaction; the last active owner is still refused and keeps its session.
func TestOwnerAssignmentsEndSessionsInTheSameTransaction(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		ctx := context.Background()
		if err := e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error { return rbac.SeedBuiltIns(ctx, tx, e.ten) }); err != nil {
			t.Fatal(err)
		}
		oa, err := rbac.NewOwnerAssignments(e.db, e.snk, e.a, e.ss)
		if err != nil {
			t.Fatal(err)
		}
		o1, o2 := activeAcct(t, e, "ow-1"), activeAcct(t, e, "ow-2")

		// Grant: o1's live session ends as role_changed.
		tok1 := liveSession(t, e, o1.ID)
		id1, err := oa.Grant(ctx, e.ten, o1.ID, human)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.ss.Lookup(ctx, tok1); !errors.Is(err, ErrRevoked) {
			t.Fatalf("session after grant = %v, want ErrRevoked", err)
		}
		var why string
		if err := e.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT end_reason FROM public.authn_sessions WHERE tenant_id = $1 AND account_id = $2::uuid`, e.ten.String(), o1.ID).Scan(&why)
		}); err != nil || why != string(ReasonRoleChanged) {
			t.Fatalf("end_reason = %q, %v", why, err)
		}

		// The only owner: refused, and its (new) session survives.
		tok1b := liveSession(t, e, o1.ID)
		if err := oa.Revoke(ctx, e.ten, id1, human); !errors.Is(err, rbac.ErrLastOwner) {
			t.Fatalf("revoke last owner = %v, want ErrLastOwner", err)
		}
		if _, err := e.ss.Lookup(ctx, tok1b); err != nil {
			t.Fatalf("refused revoke ended the session: %v", err)
		}

		// With a second owner, revoking o1 succeeds and ends o1's sessions only.
		if _, err := oa.Grant(ctx, e.ten, o2.ID, human); err != nil {
			t.Fatal(err)
		}
		tok1c, tok2 := liveSession(t, e, o1.ID), liveSession(t, e, o2.ID)
		if err := oa.Revoke(ctx, e.ten, id1, human); err != nil {
			t.Fatal(err)
		}
		if _, err := e.ss.Lookup(ctx, tok1c); !errors.Is(err, ErrRevoked) {
			t.Fatalf("session after revoke = %v, want ErrRevoked", err)
		}
		if _, err := e.ss.Lookup(ctx, tok2); err != nil {
			t.Fatalf("another account's session ended: %v", err)
		}
	})
}
