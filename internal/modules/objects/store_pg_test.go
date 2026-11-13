package objects

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type env struct {
	t  *testing.T
	db *store.DB
	a  tenant.ID
	b  tenant.ID
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	a, b := tenanttest.Seed(t, d.ExecOwner, "A"), tenanttest.Seed(t, d.ExecOwner, "B")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return &env{t: t, db: db, a: a, b: b}
}

func (e *env) in(tid tenant.ID, f func(ctx context.Context, tx store.Tx)) {
	e.t.Helper()
	if err := e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error { f(ctx, tx); return nil }); err != nil {
		e.t.Fatal(err)
	}
}

func TestTemplateLifecycle(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		// A naming format must be released before a template can pin it.
		var fid string
		e.in(e.a, func(ctx context.Context, tx store.Tx) {
			var err error
			if fid, _, err = namings.saveDraftTx(ctx, tx, "", sam); err != nil {
				t.Fatal(err)
			}
		})
		tpl := userTemplate()
		tpl.NamingFormats = map[NamePurpose]Pin{PurposeSAMAccountName: {ID: fid, Version: 1}}
		var id string
		e.in(e.a, func(ctx context.Context, tx store.Tx) {
			var v int
			var err error
			if id, v, err = saveTemplateTx(ctx, tx, "", tpl); err != nil || v != 1 {
				t.Fatalf("create: %v %v", v, err)
			}
			// Saving again replaces the draft in place.
			tpl.Name = "Standard user v1b"
			if _, v, err = saveTemplateTx(ctx, tx, id, tpl); err != nil || v != 1 {
				t.Fatalf("revise draft: %v %v", v, err)
			}
			if err := publishTemplateTx(ctx, tx, id, 1); err == nil {
				t.Fatal("published a template pinning a draft naming format")
			}
		})
		e.in(e.a, func(ctx context.Context, tx store.Tx) {
			if err := namings.transitionTx(ctx, tx, fid, 1, StateDraft, StateActive); err != nil {
				t.Fatal(err)
			}
			if err := publishTemplateTx(ctx, tx, id, 1); err != nil {
				t.Fatal(err)
			}
			if err := publishTemplateTx(ctx, tx, id, 1); !errors.Is(err, ErrConflict) {
				t.Fatalf("second publish: %v", err)
			}
			got, err := (Templates{}).Latest(ctx, tx, id)
			if err != nil || got.Version != 1 || got.State != StatePublished || got.Def.Name != "Standard user v1b" ||
				got.Def.AllowedContainers[0] != ouA || got.Def.Fields[3].Default != "Contoso" {
				t.Fatalf("latest: %+v %v", got, err)
			}
		})
		// Revising a published template opens version 2 as a draft; version 1 stays as it was.
		e.in(e.a, func(ctx context.Context, tx store.Tx) {
			tpl.Name = "Standard user v2"
			_, v, err := saveTemplateTx(ctx, tx, id, tpl)
			if err != nil || v != 2 {
				t.Fatalf("revise published: %v %v", v, err)
			}
			if l, err := (Templates{}).Latest(ctx, tx, id); err != nil || l.Version != 1 {
				t.Fatalf("an unpublished draft must not be the pinned one: %+v %v", l, err)
			}
			list, err := (Templates{}).List(ctx, tx, KindUser)
			if err != nil || len(list) != 1 || list[0].Version != 2 || list[0].State != StateDraft {
				t.Fatalf("list: %+v %v", list, err)
			}
			if l, err := (Templates{}).List(ctx, tx, KindGroup); err != nil || len(l) != 0 {
				t.Fatalf("list by kind: %+v %v", l, err)
			}
			// The kind of a definition cannot change.
			g := tpl
			g.Kind = KindGroup
			g.NamingFormats = nil
			if _, _, err := saveTemplateTx(ctx, tx, id, g); !errors.Is(err, ErrPurpose) {
				t.Fatalf("kind change: %v", err)
			}
			if err := templates.transitionTx(ctx, tx, id, 1, StatePublished, StateArchived); err != nil {
				t.Fatal(err)
			}
		})
	})
}

// DM-50.I1 is held by the database, not by the Go code: an UPDATE that bypasses the store is refused.
func TestPublishedVersionIsImmutableInTheDatabase(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		tpl := userTemplate()
		tpl.NamingFormats = nil
		var id string
		e.in(e.a, func(ctx context.Context, tx store.Tx) {
			var err error
			if id, _, err = saveTemplateTx(ctx, tx, "", tpl); err != nil {
				t.Fatal(err)
			}
			if err := publishTemplateTx(ctx, tx, id, 1); err != nil {
				t.Fatal(err)
			}
		})
		for name, sql := range map[string]string{
			"definition": `UPDATE public.objects_templates SET definition = '{}'::jsonb WHERE id = $1`,
			"name":       `UPDATE public.objects_templates SET name = 'x' WHERE id = $1`,
			"unpublish":  `UPDATE public.objects_templates SET state = 'draft', published_at = NULL WHERE id = $1`,
			"kind":       `UPDATE public.objects_templates SET object_kind = 'group' WHERE id = $1`,
		} {
			err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) error {
				_, err := tx.Exec(ctx, sql, id)
				return err
			})
			if err == nil || store.SQLState(err) != "AD403" {
				t.Errorf("%s: want AD403, got %v", name, err)
			}
		}
		err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM public.objects_templates WHERE id = $1`, id)
			return err
		})
		if err == nil {
			t.Error("the runtime role deleted a version")
		}
	})
}

func TestTenantIsolationAndNoTenant(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		var id string
		e.in(e.a, func(ctx context.Context, tx store.Tx) {
			var err error
			if id, _, err = namings.saveDraftTx(ctx, tx, "", sam); err != nil {
				t.Fatal(err)
			}
		})
		e.in(e.b, func(ctx context.Context, tx store.Tx) {
			if _, err := (NamingFormats{}).Get(ctx, tx, id, 1); !errors.Is(err, ErrNotFound) {
				t.Errorf("tenant B read tenant A's format: %v", err)
			}
			if _, _, err := namings.saveDraftTx(ctx, tx, id, sam); !errors.Is(err, ErrNotFound) {
				t.Errorf("tenant B revised tenant A's format: %v", err)
			}
			if l, err := (NamingFormats{}).List(ctx, tx, ""); err != nil || len(l) != 0 {
				t.Errorf("tenant B lists %v %v", l, err)
			}
		})
		// A naming format's body round-trips through the store.
		e.in(e.a, func(ctx context.Context, tx store.Tx) {
			got, err := (NamingFormats{}).Get(ctx, tx, id, 1)
			if err != nil || got.State != StateDraft || len(got.Def.Alternatives) != 2 || got.Def.Alternatives[0].Tokens[0].Take != 1 {
				t.Fatalf("round trip: %+v %v", got, err)
			}
			if _, err := (NamingFormats{}).Latest(ctx, tx, id); !errors.Is(err, ErrNotFound) {
				t.Errorf("a draft is not the latest active version: %v", err)
			}
		})
		// No tenant context: refused before any SQL against the tables.
		if err := e.db.WithPlatform(context.Background(), "objects test: no tenant context", func(ctx context.Context, tx store.Tx) error {
			if _, err := (NamingFormats{}).Get(ctx, tx, id, 1); !errors.Is(err, ErrNoTenant) {
				t.Errorf("no tenant: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
