package inventory_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func (e *env) rev(t *testing.T, tid tenant.ID) uint64 {
	t.Helper()
	v, err := e.r.Tier0Revision(context.Background(), tid)
	if err != nil {
		t.Fatalf("Tier0Revision: %v", err)
	}
	return v
}

func (e *env) designate(t *testing.T, tid tenant.ID, c inventory.ConnectionID, obj string, on bool) {
	t.Helper()
	err := e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
		if on {
			_, err := w.Designate(ctx, tx, c, inventory.GUID(obj), "alice")
			return err
		}
		return w.Undesignate(ctx, tx, c, inventory.GUID(obj), "alice")
	})
	if err != nil {
		t.Fatalf("designate(%v): %v", on, err)
	}
}

// Acceptance 1: adding, removing and re-adding a designation each strictly increase the revision;
// a no-op designate does not.
func TestTier0RevisionDesignations(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		const obj = "aaaaaaaa-0000-4000-8000-0000000000d1"
		r0 := e.rev(t, e.a)
		e.designate(t, e.a, e.adA, obj, true)
		r1 := e.rev(t, e.a)
		if r1 <= r0 {
			t.Fatalf("add: %d -> %d", r0, r1)
		}
		e.designate(t, e.a, e.adA, obj, true) // no-op
		if r := e.rev(t, e.a); r != r1 {
			t.Fatalf("no-op designate moved the revision: %d -> %d", r1, r)
		}
		e.designate(t, e.a, e.adA, obj, false)
		r2 := e.rev(t, e.a)
		if r2 <= r1 {
			t.Fatalf("remove: %d -> %d", r1, r2)
		}
		e.designate(t, e.a, e.adA, obj, true)
		if r3 := e.rev(t, e.a); r3 <= r2 {
			t.Fatalf("re-add: %d -> %d", r2, r3)
		}
	})
}

// Acceptance 2: a change to the tier0 facts of a correlation increases the revision; re-stating the
// same facts later (a refresh) and a non-tier0 correlation leave it unchanged.
func TestTier0RevisionFacts(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		f := formation(e, adG1, enG1)
		if _, err := e.form(t, f); err != nil { // not tier0
			t.Fatal(err)
		}
		r0 := e.rev(t, e.a)
		f.FactsAsOf, f.Now = t1.Add(time.Hour), t1.Add(time.Hour)
		if _, err := e.form(t, f); err != nil { // same facts, newer as-of
			t.Fatal(err)
		}
		if r := e.rev(t, e.a); r != r0 {
			t.Fatalf("unchanged facts moved the revision: %d -> %d", r0, r)
		}
		f.ADBases = []inventory.Basis{inventory.BasisC16}
		if _, err := e.form(t, f); err != nil {
			t.Fatal(err)
		}
		r1 := e.rev(t, e.a)
		if r1 <= r0 {
			t.Fatalf("facts became tier0: %d -> %d", r0, r1)
		}
		f.FactsAsOf = f.FactsAsOf.Add(time.Hour)
		if _, err := e.form(t, f); err != nil {
			t.Fatal(err)
		}
		if r := e.rev(t, e.a); r != r1 {
			t.Fatalf("re-stated facts moved the revision: %d -> %d", r1, r)
		}
		f.ADBases = nil
		if _, err := e.form(t, f); err != nil {
			t.Fatal(err)
		}
		if r := e.rev(t, e.a); r <= r1 {
			t.Fatalf("facts stopped being tier0: %d -> %d", r1, r)
		}
	})
}

// Acceptance 3: one tenant's changes never move another's revision, and the counter cannot be
// moved backwards through the runtime role.
func TestTier0RevisionTenantIsolationAndMonotone(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		rb := e.rev(t, e.b)
		e.designate(t, e.a, e.adA, "aaaaaaaa-0000-4000-8000-0000000000d2", true)
		if r := e.rev(t, e.b); r != rb {
			t.Fatalf("tenant B moved: %d -> %d", rb, r)
		}
		e.designate(t, e.b, e.adB, "aaaaaaaa-0000-4000-8000-0000000000d3", true)
		ra := e.rev(t, e.a)
		if e.rev(t, e.b) <= rb || ra == 0 {
			t.Fatal("each tenant counts its own changes")
		}
		if err := e.exec(e.a, `UPDATE public.inventory_tier0_revisions SET revision = 1`); err == nil && ra > 1 {
			t.Fatal("the runtime role moved the revision backwards")
		}
		if r := e.rev(t, e.a); r != ra {
			t.Fatalf("revision changed: %d -> %d", ra, r)
		}
		if _, err := e.r.Tier0Revision(context.Background(), tenant.ID{}); err == nil {
			t.Fatal("zero tenant must be refused")
		}
	})
}

// T-0500: row security itself refuses a tenant re-assigning its revision row to another tenant. The
// forward-only triggers are disabled so only the policy's WITH CHECK can be what refuses it; with them
// enabled the move is refused too.
func TestTier0RevisionRowSecurityRefusesTenantReassignment(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.designate(t, e.a, e.adA, "aaaaaaaa-0000-4000-8000-0000000000e2", true)
		move := `UPDATE public.inventory_tier0_revisions SET tenant_id = $1 WHERE tenant_id = $2`
		check := func(label string) {
			t.Helper()
			err := e.exec(e.a, move, e.b.String(), e.a.String())
			code := store.SQLState(err)
			if code == "" {
				t.Fatalf("%s: re-assignment was not refused by the database: %v", label, err)
			}
			if label == "triggers disabled" && (code != "42501" || !strings.Contains(err.Error(), "row-level security")) {
				t.Fatalf("%s: want a row-security refusal (42501), got %s %v", label, code, err)
			}
		}
		check("triggers enabled")
		for _, trg := range []string{"inventory_tier0_revisions_guard", "inventory_tier0_revisions_tenant_guard"} {
			if err := e.d.ExecOwner(context.Background(), `ALTER TABLE public.inventory_tier0_revisions DISABLE TRIGGER `+trg); err != nil {
				t.Fatalf("disable %s: %v", trg, err)
			}
		}
		check("triggers disabled")
		if r := e.rev(t, e.a); r == 0 {
			t.Fatal("tenant A lost its revision row")
		}
	})
}

// T-0506: the AFTER trigger inventory_tier0_revisions_tenant_guard (migration 0039) is the last line
// against a writer that row security does not constrain. Here the writer is the table owner with
// NO FORCE ROW LEVEL SECURITY (the owner is then exempt from the policy) and the BEFORE guard is
// disabled, so nothing but the AFTER trigger can refuse the move. If it is dropped, this fails.
func TestTier0RevisionAfterTriggerRefusesTenantMoveByRLSBypassingWriter(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		e.designate(t, e.a, e.adA, "aaaaaaaa-0000-4000-8000-0000000000f2", true)
		const tbl = `public.inventory_tier0_revisions`
		for _, stmt := range []string{
			`ALTER TABLE ` + tbl + ` NO FORCE ROW LEVEL SECURITY`,
			`ALTER TABLE ` + tbl + ` DISABLE TRIGGER inventory_tier0_revisions_guard`,
		} {
			if err := e.d.ExecOwner(ctx, stmt); err != nil {
				t.Fatalf("%s: %v", stmt, err)
			}
		}
		// The owner now sees tenant A's row: the move below targets a non-empty set, so a refusal
		// cannot be a filtered-out zero-row UPDATE.
		rows, err := e.d.OwnerStrings(ctx, `SELECT count(*)::text FROM `+tbl+` WHERE tenant_id = $1`, e.a.String())
		if err != nil || len(rows) != 1 || rows[0] == "0" {
			t.Fatalf("owner must see tenant A's revision row, got %v (err %v)", rows, err)
		}
		err = e.d.ExecOwner(ctx, `UPDATE `+tbl+` SET tenant_id = $1 WHERE tenant_id = $2`, e.b.String(), e.a.String())
		if code := store.SQLState(err); code != "23514" || !strings.Contains(err.Error(), "never change tenant") {
			t.Fatalf("want 23514 from the AFTER tenant guard, got %q: %v", code, err)
		}
		rows, err = e.d.OwnerStrings(ctx, `SELECT count(*)::text FROM `+tbl+` WHERE tenant_id = $1`, e.a.String())
		if err != nil || len(rows) != 1 || rows[0] == "0" {
			t.Fatalf("tenant A lost its revision row: %v (err %v)", rows, err)
		}
	})
}
