package authn

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const (
	acctConn  = "00000000-0000-4000-8000-0000000000c1"
	acctGUID  = "11111111-2222-4333-8444-555555555555"
	acctGUID2 = "11111111-2222-4333-8444-555555555556"
	acctOID   = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	acctTID   = "99999999-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	acctSID   = "S-1-5-21-1004336348-1177238915-682003330-1105"
)

// ownerAs runs one fixture statement as the owner role inside the tenant's RLS context (the table is
// FORCEd, so the owner is subject to the policy too).
func ownerAs(d *storetest.Database, ten tenant.ID, sql string, args ...any) error {
	ctx := context.Background()
	c, err := d.Owner(ctx)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	tx, err := c.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, ten.String()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type acctEnv struct {
	d   *storetest.Database
	ten tenant.ID
	a   *Accounts
}

func eachAcct(t *testing.T, fn func(t *testing.T, e *acctEnv)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		ten := tenanttest.Seed(t, d.ExecOwner, "t1")
		if err := ownerAs(d, ten, `INSERT INTO public.connections (tenant_id, id, kind, display_name, credential_id, transport_security)
			VALUES ($1::uuid, $2::uuid, 'ad_forest', 'c', $3::uuid, 'ldaps')`, ten.String(), acctConn, acctConn); err != nil {
			t.Fatal(err)
		}
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		a, err := NewAccounts(db)
		if err != nil {
			t.Fatal(err)
		}
		fn(t, &acctEnv{d: d, ten: ten, a: a})
	})
}

// Acceptance 1: the table, its RLS and the CHECKs tying kind to the reference and SSO fields.
func TestAccountsTableShapeAndChecks(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		ctx := context.Background()
		flags, err := e.d.OwnerStrings(ctx, `SELECT relrowsecurity::text || relforcerowsecurity::text FROM pg_class WHERE oid = 'public.authn_accounts'::regclass`)
		if err != nil || len(flags) != 1 || flags[0] != "truetrue" {
			t.Fatalf("RLS enabled+forced = %v, %v", flags, err)
		}
		// Positive control: the fixture path accepts a valid row, so each refusal below is the table's.
		if err := ownerAs(e.d, e.ten, `INSERT INTO public.authn_accounts (tenant_id, kind, display_name, created_by) VALUES ($1::uuid, 'local', 'ok', 'system')`, e.ten.String()); err != nil {
			t.Fatalf("valid row refused: %v", err)
		}
		bad := map[string]string{
			"local with sso fields":     `(tenant_id, kind, display_name, created_by, sso_issuer, sso_subject) VALUES ($1::uuid, 'local', 'x', 'system', 'i', 's')`,
			"local without mfa":         `(tenant_id, kind, display_name, created_by, mfa_required) VALUES ($1::uuid, 'local', 'x', 'system', false)`,
			"sso without subject":       `(tenant_id, kind, display_name, created_by, sso_issuer) VALUES ($1::uuid, 'sso', 'x', 'system', 'i')`,
			"directory without ref":     `(tenant_id, kind, display_name, created_by) VALUES ($1::uuid, 'directory', 'x', 'system')`,
			"directory with half ref":   `(tenant_id, kind, display_name, created_by, directory_connection_id) VALUES ($1::uuid, 'directory', 'x', 'system', '` + acctConn + `')`,
			"directory with anchor":     `(tenant_id, kind, display_name, created_by, directory_connection_id, directory_object_guid, anchor_kind, anchor_value) VALUES ($1::uuid, 'directory', 'x', 'system', '` + acctConn + `', '` + acctGUID + `', 'onprem_sid', '` + acctSID + `')`,
			"sso anchor without ref":    `(tenant_id, kind, display_name, created_by, sso_issuer, sso_subject, anchor_kind, anchor_value) VALUES ($1::uuid, 'sso', 'x', 'system', 'i', 's', 'onprem_sid', '` + acctSID + `')`,
			"sso ref without anchor":    `(tenant_id, kind, display_name, created_by, sso_issuer, sso_subject, directory_connection_id, directory_object_guid) VALUES ($1::uuid, 'sso', 'x', 'system', 'i', 's', '` + acctConn + `', '` + acctGUID + `')`,
			"oid without tid":           `(tenant_id, kind, display_name, created_by, sso_issuer, sso_subject, directory_connection_id, directory_object_guid, anchor_kind, anchor_value) VALUES ($1::uuid, 'sso', 'x', 'system', 'i', 's', '` + acctConn + `', '` + acctGUID + `', 'oid', '` + acctOID + `')`,
			"upn as anchor kind":        `(tenant_id, kind, display_name, created_by, sso_issuer, sso_subject, directory_connection_id, directory_object_guid, anchor_kind, anchor_value) VALUES ($1::uuid, 'sso', 'x', 'system', 'i', 's', '` + acctConn + `', '` + acctGUID + `', 'upn', 'a@b.c')`,
			"sid malformed":             `(tenant_id, kind, display_name, created_by, sso_issuer, sso_subject, directory_connection_id, directory_object_guid, anchor_kind, anchor_value) VALUES ($1::uuid, 'sso', 'x', 'system', 'i', 's', '` + acctConn + `', '` + acctGUID + `', 'onprem_sid', 'CN=x,DC=y')`,
			"created_by neither":        `(tenant_id, kind, display_name, created_by) VALUES ($1::uuid, 'local', 'x', 'bob')`,
			"ref to unknown connection": `(tenant_id, kind, display_name, created_by, directory_connection_id, directory_object_guid) VALUES ($1::uuid, 'directory', 'x', 'system', '` + acctGUID + `', '` + acctGUID + `')`,
		}
		for name, cols := range bad {
			if err := ownerAs(e.d, e.ten, `INSERT INTO public.authn_accounts `+cols, e.ten.String()); err == nil {
				t.Errorf("%s: the database accepted it", name)
			}
		}
	})
}

func TestAccountsTenantIsolation(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		ctx := context.Background()
		a, err := e.a.Create(ctx, NewAccount{Tenant: e.ten, Kind: KindLocal, DisplayName: "A", CreatedBy: "system"})
		if err != nil {
			t.Fatal(err)
		}
		if !a.MFARequired || a.State != AccountInvited {
			t.Fatalf("local account: mfa=%v state=%s", a.MFARequired, a.State)
		}
		other := tenanttest.Seed(t, e.d.ExecOwner, "t2")
		if _, err := e.a.Get(ctx, other, a.ID); !errors.Is(err, ErrAccountNotFound) {
			t.Fatalf("another tenant read the account: %v", err)
		}
	})
}

// Acceptance 2: an sso account bound by oid or onprem_sid reads back its anchor and resolved ref.
func TestSSOBindingRoundTrip(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		ctx := context.Background()
		ref := DirectoryRef{ConnectionID: acctConn, ObjectGUID: acctGUID}
		for _, tc := range []struct {
			name   string
			sub    string
			anchor Anchor
			ref    DirectoryRef
		}{
			{"oid", "sub-1", Anchor{Kind: AnchorOID, Value: acctOID, TenantID: acctTID}, ref},
			{"sid", "sub-2", Anchor{Kind: AnchorOnpremSID, Value: acctSID}, DirectoryRef{ConnectionID: acctConn, ObjectGUID: acctGUID2}},
		} {
			a, err := e.a.Create(ctx, NewAccount{Tenant: e.ten, Kind: KindSSO, DisplayName: tc.name, CreatedBy: "system",
				SSOIssuer: "https://idp.example/", SSOSubject: tc.sub, MFARequired: true})
			if err != nil {
				t.Fatal(err)
			}
			if a.Anchor != nil || a.Ref != nil {
				t.Fatalf("%s: new sso account should be unbound", tc.name)
			}
			if _, err := e.a.Bind(ctx, e.ten, a.ID, tc.anchor, tc.ref); err != nil {
				t.Fatalf("%s: bind: %v", tc.name, err)
			}
			got, err := e.a.LookupSSO(ctx, e.ten, "https://idp.example/", tc.sub)
			if err != nil {
				t.Fatal(err)
			}
			if got.Anchor == nil || *got.Anchor != tc.anchor || got.Ref == nil || *got.Ref != tc.ref {
				t.Fatalf("%s: read back anchor=%+v ref=%+v", tc.name, got.Anchor, got.Ref)
			}
			if _, err := e.a.Bind(ctx, e.ten, a.ID, tc.anchor, tc.ref); !errors.Is(err, ErrAlreadyBound) {
				t.Fatalf("%s: rebind = %v, want ErrAlreadyBound", tc.name, err)
			}
		}
		// The database, not just the store, refuses to rewrite a binding.
		if err := ownerAs(e.d, e.ten, `UPDATE public.authn_accounts SET anchor_value = 'S-1-5-21-1-2-3-4' WHERE anchor_kind = 'onprem_sid'`); err == nil {
			t.Fatal("trigger let an anchor be rewritten")
		}
	})
}

func TestAccountsUniquenessAndLifecycle(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		ctx := context.Background()
		d := NewAccount{Tenant: e.ten, Kind: KindDirectory, DisplayName: "D", CreatedBy: "system", Ref: &DirectoryRef{ConnectionID: acctConn, ObjectGUID: acctGUID}}
		a, err := e.a.Create(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.a.Create(ctx, d); !errors.Is(err, ErrAccountExists) {
			t.Fatalf("duplicate directory account = %v", err)
		}
		if _, err := e.a.Bind(ctx, e.ten, a.ID, Anchor{Kind: AnchorOnpremSID, Value: acctSID}, *d.Ref); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("binding a directory account = %v", err)
		}
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountActive); err != nil {
			t.Fatal(err)
		}
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountInvited); !errors.Is(err, ErrBadTransition) {
			t.Fatalf("active → invited = %v", err)
		}
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountDeleted); err != nil {
			t.Fatal(err)
		}
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountActive); !errors.Is(err, ErrBadTransition) {
			t.Fatalf("deleted → active = %v", err)
		}
		// A deleted account releases its directory object.
		if _, err := e.a.Create(ctx, d); err != nil {
			t.Fatalf("recreate after delete: %v", err)
		}
		for _, bad := range []NewAccount{
			{Tenant: e.ten, Kind: KindSSO, DisplayName: "x", CreatedBy: "system"},
			{Tenant: e.ten, Kind: KindLocal, DisplayName: "x", CreatedBy: "somebody"},
			{Tenant: e.ten, Kind: KindDirectory, DisplayName: "x", CreatedBy: "system", Ref: &DirectoryRef{ConnectionID: "CN=x", ObjectGUID: acctGUID}},
		} {
			if _, err := e.a.Create(ctx, bad); !errors.Is(err, ErrInvalidInput) {
				t.Errorf("Create(%+v) = %v, want ErrInvalidInput", bad, err)
			}
		}
	})
}
