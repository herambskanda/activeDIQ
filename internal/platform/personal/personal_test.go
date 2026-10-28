package personal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

const subj = "dir:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222"

type rig struct {
	t  *testing.T
	d  *storetest.Database
	db *store.DB
	id tenant.ID
}

func setup(t *testing.T, s *storetest.Server) *rig {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return &rig{t: t, d: d, db: db, id: tenanttest.Seed(t, d.ExecOwner, "A")}
}

func (r *rig) in(id tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error {
	return r.db.WithTenant(context.Background(), id, fn)
}

// owner runs one statement as the owner role in the rig's tenant (row-level security is forced for it too).
func (r *rig) owner(table, sql string) error {
	// The owner role owns the table, so it may switch off forced row-level security for it (the owner is
	// otherwise subject to it) and then change rows directly, as an attacker with the owner credential would.
	// This avoids setting the tenant by hand: only internal/platform/store sets it (fitness-tenancy T5).
	return r.d.ExecOwner(context.Background(), `ALTER TABLE public.`+table+` NO FORCE ROW LEVEL SECURITY; `+sql)
}

func TestPutResolveEraseKeepsHash(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r, p := setup(t, s), New()
		var ref Ref
		if err := r.in(r.id, func(ctx context.Context, tx store.Tx) (err error) {
			ref, err = p.Put(ctx, tx, r.id, subj, "audit_event", "target.display", "CN=Ann,DC=x")
			return
		}); err != nil {
			t.Fatal(err)
		}
		// 1. The value is held outside the record: the ref carries none of it.
		canonBefore, err := ref.Canonical()
		if err != nil || bytes.Contains(canonBefore, []byte("CN=Ann")) {
			t.Fatalf("canonical form: %v / leaks value", err)
		}
		hashBefore := sha256.Sum256(canonBefore)
		var got string
		var erased bool
		if err := r.in(r.id, func(ctx context.Context, tx store.Tx) (err error) {
			got, erased, err = p.Resolve(ctx, tx, r.id, ref)
			return
		}); err != nil || erased || got != "CN=Ann,DC=x" {
			t.Fatalf("resolve = %q %v %v", got, erased, err)
		}
		// Another tenant cannot see it.
		other := tenanttest.Seed(t, r.d.ExecOwner, "B")
		_ = r.in(other, func(ctx context.Context, tx store.Tx) error {
			if v, er, _ := p.Resolve(ctx, tx, other, ref); !er || v != Redacted {
				t.Errorf("cross-tenant resolve = %q %v", v, er)
			}
			return nil
		})
		// 2. Erase, then resolve returns the marker.
		var n int
		if err := r.in(r.id, func(ctx context.Context, tx store.Tx) (err error) {
			n, err = erase(ctx, tx, r.id, subj)
			return
		}); err != nil || n != 1 {
			t.Fatalf("erase = %d %v", n, err)
		}
		if err := r.in(r.id, func(ctx context.Context, tx store.Tx) (err error) {
			got, erased, err = p.Resolve(ctx, tx, r.id, ref)
			return
		}); err != nil || !erased || got != Redacted {
			t.Fatalf("after erase resolve = %q %v %v", got, erased, err)
		}
		// 3. The hash over the ref is unchanged.
		canonAfter, _ := ref.Canonical()
		if sha256.Sum256(canonAfter) != hashBefore {
			t.Fatal("hash changed after erasure")
		}
		// Erasing again is a no-op.
		_ = r.in(r.id, func(ctx context.Context, tx store.Tx) error {
			if n, err := erase(ctx, tx, r.id, subj); err != nil || n != 0 {
				t.Errorf("second erase = %d %v", n, err)
			}
			return nil
		})
	})
}

func TestHoldTamperAndRuntimeRoleCannotUpdate(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r, p := setup(t, s), New()
		var ref Ref
		if err := r.in(r.id, func(ctx context.Context, tx store.Tx) (err error) {
			ref, err = p.Put(ctx, tx, r.id, subj, "audit_event", "mail", "a@x")
			return
		}); err != nil {
			t.Fatal(err)
		}
		// The runtime role cannot UPDATE the value: tampering needs the owner role.
		err := r.in(r.id, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.personal_value SET value = 'evil'`)
			return err
		})
		if err == nil {
			t.Fatal("runtime role updated personal_value")
		}
		if err := r.owner("personal_value", `UPDATE public.personal_value SET value = 'evil'`); err != nil {
			t.Fatal(err)
		}
		_ = r.in(r.id, func(ctx context.Context, tx store.Tx) error {
			if _, _, err := p.Resolve(ctx, tx, r.id, ref); !errors.Is(err, ErrTampered) {
				t.Errorf("tampered resolve = %v", err)
			}
			return nil
		})
		// Legal hold blocks erasure and deletes nothing.
		if err := r.owner("personal_hold", `ALTER TABLE public.personal_subject NO FORCE ROW LEVEL SECURITY; INSERT INTO public.personal_hold (tenant_id, subject_ref) SELECT tenant_id, subject_ref FROM public.personal_subject`); err != nil {
			t.Fatal(err)
		}
		_ = r.in(r.id, func(ctx context.Context, tx store.Tx) error {
			if _, err := erase(ctx, tx, r.id, subj); !errors.Is(err, ErrHeld) {
				t.Errorf("held erase = %v", err)
			}
			return nil
		})
	})
}

func TestPutRefusesBadInput(t *testing.T) {
	p, id := New(), tenant.New()
	for _, c := range []struct{ subject, kind, field string }{
		{"bad", "k", "f"}, {subj, "", "f"}, {subj, "k", "bad field"}, {"dir:x:y", "k", "f"},
	} {
		if _, err := p.Put(context.Background(), nil, id, c.subject, c.kind, c.field, "v"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v = %v", c, err)
		}
	}
	var zero step.Step
	if _, err := p.Erase(context.Background(), zero, id, subj); !errors.Is(err, step.ErrZeroStep) {
		t.Errorf("zero step erase = %v", err)
	}
	if err := p.SetHold(context.Background(), zero, id, subj); !errors.Is(err, step.ErrZeroStep) {
		t.Errorf("zero step set hold = %v", err)
	}
	if err := p.ReleaseHold(context.Background(), zero, id, subj); !errors.Is(err, step.ErrZeroStep) {
		t.Errorf("zero step release hold = %v", err)
	}
}

func TestCommitmentBindsAllFields(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, 32)
	id := [16]byte{1}
	base, _ := Commit(salt, id, "f", "v")
	for name, c := range map[string]func() ([32]byte, error){
		"value": func() ([32]byte, error) { return Commit(salt, id, "f", "w") },
		"field": func() ([32]byte, error) { return Commit(salt, id, "g", "v") },
		"id":    func() ([32]byte, error) { return Commit(salt, [16]byte{2}, "f", "v") },
		"salt":  func() ([32]byte, error) { return Commit(bytes.Repeat([]byte{2}, 32), id, "f", "v") },
	} {
		if got, _ := c(); got == base {
			t.Errorf("commitment ignores %s", name)
		}
	}
}
