package authn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
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

// fixtureAs runs one fixture statement through the runtime role inside the tenant's transaction, the
// way product code reaches the table. The constraint tests rely on the table's own checks, which
// bind every role.
func fixtureAs(db *store.DB, ten tenant.ID, sql string, args ...any) error {
	return db.WithTenant(context.Background(), ten, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

type acctEnv struct {
	d   *storetest.Database
	db  *store.DB
	ten tenant.ID
	a   *Accounts
	ss  *Store
	snk *flakySink
}

// flakySink records events and fails Append while fail is set.
type flakySink struct {
	recSink
	fail bool
}

func (f *flakySink) Append(ctx context.Context, tx store.Tx, ev audit.Event) error {
	if f.fail {
		return errors.New("sink down")
	}
	return f.recSink.Append(ctx, tx, ev)
}

func eachAcct(t *testing.T, fn func(t *testing.T, e *acctEnv)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		ten := tenanttest.Seed(t, d.ExecOwner, "t1")
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		if err := fixtureAs(db, ten, `INSERT INTO public.connections (tenant_id, id, kind, display_name, credential_id, transport_security)
			VALUES ($1::uuid, $2::uuid, 'ad_forest', 'c', $3::uuid, 'ldaps')`, ten.String(), acctConn, acctConn); err != nil {
			t.Fatal(err)
		}
		snk := &flakySink{}
		ss, err := New(Config{DB: db, Audit: snk, Policies: StaticPolicy(pol)})
		if err != nil {
			t.Fatal(err)
		}
		a, err := NewAccounts(db, ss)
		if err != nil {
			t.Fatal(err)
		}
		fn(t, &acctEnv{d: d, db: db, ten: ten, a: a, ss: ss, snk: snk})
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
		if err := fixtureAs(e.db, e.ten, `INSERT INTO public.authn_accounts (tenant_id, kind, display_name, created_by) VALUES ($1::uuid, 'local', 'ok', 'system')`, e.ten.String()); err != nil {
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
			if err := fixtureAs(e.db, e.ten, `INSERT INTO public.authn_accounts `+cols, e.ten.String()); err == nil {
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
			if _, err := e.a.Bind(ctx, e.ten, a.ID, tc.anchor, tc.ref, human); err != nil {
				t.Fatalf("%s: bind: %v", tc.name, err)
			}
			got, err := e.a.LookupSSO(ctx, e.ten, "https://idp.example/", tc.sub)
			if err != nil {
				t.Fatal(err)
			}
			if got.Anchor == nil || *got.Anchor != tc.anchor || got.Ref == nil || *got.Ref != tc.ref {
				t.Fatalf("%s: read back anchor=%+v ref=%+v", tc.name, got.Anchor, got.Ref)
			}
			if _, err := e.a.Bind(ctx, e.ten, a.ID, tc.anchor, tc.ref, human); !errors.Is(err, ErrAlreadyBound) {
				t.Fatalf("%s: rebind = %v, want ErrAlreadyBound", tc.name, err)
			}
		}
		// The database, not just the store, refuses to rewrite a binding.
		if err := fixtureAs(e.db, e.ten, `UPDATE public.authn_accounts SET anchor_value = 'S-1-5-21-1-2-3-4' WHERE anchor_kind = 'onprem_sid'`); err == nil {
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
		if _, err := e.a.Bind(ctx, e.ten, a.ID, Anchor{Kind: AnchorOnpremSID, Value: acctSID}, *d.Ref, human); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("binding a directory account = %v", err)
		}
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountActive, human); err != nil {
			t.Fatal(err)
		}
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountInvited, human); !errors.Is(err, ErrBadTransition) {
			t.Fatalf("active → invited = %v", err)
		}
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountDeleted, human); err != nil {
			t.Fatal(err)
		}
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountActive, human); !errors.Is(err, ErrBadTransition) {
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

func newSSO(t *testing.T, e *acctEnv, sub string) Account {
	t.Helper()
	a, err := e.a.Create(context.Background(), NewAccount{Tenant: e.ten, Kind: KindSSO, DisplayName: sub, CreatedBy: "system",
		SSOIssuer: "https://idp.example/", SSOSubject: sub, MFARequired: true})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func liveSession(t *testing.T, e *acctEnv, acct string) Token {
	t.Helper()
	r, err := e.ss.Create(context.Background(), CreateInput{Tenant: e.ten, Account: acct, Methods: []string{"password"}, ClientIP: netip.MustParseAddr("192.0.2.9"), Epoch: epochOf(t, e.ss, e.ten, acct)})
	if err != nil {
		t.Fatal(err)
	}
	return r.Token
}

// DM-31.I2: disabling or deleting an account ends its sessions in the same transaction.
func TestSetStateRevokesSessions(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		ctx := context.Background()
		for _, to := range []AccountState{AccountDisabled, AccountDeleted} {
			a := newSSO(t, e, "u-"+string(to))
			if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountActive, human); err != nil {
				t.Fatal(err)
			}
			tok := liveSession(t, e, a.ID)
			if _, err := e.ss.Lookup(ctx, tok); err != nil {
				t.Fatalf("live session: %v", err)
			}
			if _, err := e.a.SetState(ctx, e.ten, a.ID, to, human); err != nil {
				t.Fatal(err)
			}
			if _, err := e.ss.Lookup(ctx, tok); !errors.Is(err, ErrRevoked) {
				t.Fatalf("%s: Lookup = %v, want ErrRevoked", to, err)
			}
		}
		// Re-enabling does not touch sessions or fail.
		b := newSSO(t, e, "u-act")
		if _, err := e.a.SetState(ctx, e.ten, b.ID, AccountActive, human); err != nil {
			t.Fatal(err)
		}
		tb := liveSession(t, e, b.ID)
		if _, err := e.a.SetState(ctx, e.ten, b.ID, AccountDisabled, human); err != nil {
			t.Fatal(err)
		}
		if _, err := e.a.SetState(ctx, e.ten, b.ID, AccountActive, human); err != nil {
			t.Fatal(err)
		}
		if _, err := e.ss.Lookup(ctx, tb); !errors.Is(err, ErrRevoked) {
			t.Fatalf("revoked session came back: %v", err)
		}
	})
}

// Bind and SetState are attributed, and a failing audit sink rolls the change back.
func TestAccountChangesAuditedAndFailClosed(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		ctx := context.Background()
		an, ref := Anchor{Kind: AnchorOID, Value: acctOID, TenantID: acctTID}, DirectoryRef{ConnectionID: acctConn, ObjectGUID: acctGUID}
		a := newSSO(t, e, "audited")

		e.snk.fail = true
		if _, err := e.a.Bind(ctx, e.ten, a.ID, an, ref, human); err == nil {
			t.Fatal("Bind succeeded with the audit sink down")
		}
		if got, _ := e.a.Get(ctx, e.ten, a.ID); got.Anchor != nil || got.Ref != nil {
			t.Fatal("binding persisted despite audit failure")
		}
		e.snk.fail = false
		if _, err := e.a.Bind(ctx, e.ten, a.ID, an, ref, human); err != nil {
			t.Fatal(err)
		}
		evs := e.snk.of(KindAccountBound)
		if len(evs) != 1 || evs[0].Actor.Requester != human.Requester || evs[0].Target.GUID != a.ID ||
			evs[0].Details[1].Value != acctConn || evs[0].Details[2].Value != acctGUID {
			t.Fatalf("bound events = %+v", evs)
		}

		// State change: failing sink leaves the state and the session alone.
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountActive, human); err != nil {
			t.Fatal(err)
		}
		tok := liveSession(t, e, a.ID)
		e.snk.fail = true
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountDisabled, human); err == nil {
			t.Fatal("SetState succeeded with the audit sink down")
		}
		e.snk.fail = false
		if got, _ := e.a.Get(ctx, e.ten, a.ID); got.State != AccountActive {
			t.Fatalf("state = %s after failed change", got.State)
		}
		if _, err := e.ss.Lookup(ctx, tok); err != nil {
			t.Fatalf("session revoked by a rolled-back change: %v", err)
		}
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountDisabled, human); err != nil {
			t.Fatal(err)
		}
		sc := e.snk.of(KindAccountStateChanged)
		last := sc[len(sc)-1]
		if last.Actor.Requester != human.Requester || last.Details[0].Value != "active" || last.Details[1].Value != "disabled" {
			t.Fatalf("state_changed = %+v", last)
		}
		if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountActive, authority.Chain{}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("empty chain = %v", err)
		}
	})
}

// T-0408 / DM-31.I2: a session is minted only for an active account, and a refusal leaves no row.
func TestCreateRefusesNonActiveAccounts(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		ctx := context.Background()
		in := func(id string) CreateInput {
			return CreateInput{Tenant: e.ten, Account: id, Methods: []string{"password"}, ClientIP: netip.MustParseAddr("192.0.2.9"), Epoch: Epoch{ok: true}}
		}
		count := func(id string) int {
			var n int
			err := e.ss.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_sessions WHERE tenant_id = $1 AND account_id = $2::uuid`, e.ten.String(), id).Scan(&n)
			})
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		inv := newSSO(t, e, "inv")
		dis := newSSO(t, e, "dis")
		del := newSSO(t, e, "del")
		for _, s := range []struct {
			a  Account
			to []AccountState
		}{{dis, []AccountState{AccountActive, AccountDisabled}}, {del, []AccountState{AccountActive, AccountDeleted}}} {
			for _, to := range s.to {
				if _, err := e.a.SetState(ctx, e.ten, s.a.ID, to, human); err != nil {
					t.Fatal(err)
				}
			}
		}
		for name, id := range map[string]string{"invited": inv.ID, "disabled": dis.ID, "deleted": del.ID, "unknown": tenant.New().String()} {
			if _, err := e.ss.Create(ctx, in(id)); !errors.Is(err, ErrAccountInactive) {
				t.Errorf("%s: Create = %v, want ErrAccountInactive", name, err)
			}
			if n := count(id); n != 0 {
				t.Errorf("%s: %d session rows exist", name, n)
			}
		}
		// The caller's own transaction (CreateTx) is refused the same way.
		err := e.ss.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := e.ss.CreateTx(ctx, tx, in(dis.ID))
			return err
		})
		if !errors.Is(err, ErrAccountInactive) {
			t.Errorf("CreateTx on a disabled account = %v", err)
		}
		// Re-enabled, it works again.
		if _, err := e.a.SetState(ctx, e.ten, dis.ID, AccountActive, human); err != nil {
			t.Fatal(err)
		}
		if _, err := e.ss.Create(ctx, in(dis.ID)); err != nil {
			t.Fatalf("active again: %v", err)
		}
	})
}

// T-0408 / DM-31.I2 race: a sign-in that has already read the account as active and SetState(disabled)
// running together end with no live session. The barrier holds the sign-in's transaction open after
// its state read and its INSERT, so SetState has to wait for it and then revokes the new session.
func TestCreateSerialisedAgainstSetState(t *testing.T) {
	eachAcct(t, func(t *testing.T, e *acctEnv) {
		ctx := context.Background()
		for round := 0; round < 5; round++ {
			a := newSSO(t, e, fmt.Sprintf("race-%d", round))
			if _, err := e.a.SetState(ctx, e.ten, a.ID, AccountActive, human); err != nil {
				t.Fatal(err)
			}
			inserted, release := make(chan struct{}), make(chan struct{})
			var wg sync.WaitGroup
			var signErr, setErr error
			wg.Add(1)
			go func() {
				defer wg.Done()
				signErr = e.ss.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
					if _, err := e.ss.CreateTx(ctx, tx, CreateInput{Tenant: e.ten, Account: a.ID, Methods: []string{"password"}, Epoch: epochOf(t, e.ss, e.ten, a.ID)}); err != nil {
						return err
					}
					close(inserted)
					<-release
					return nil
				})
			}()
			select {
			case <-inserted:
			case <-time.After(10 * time.Second):
				t.Fatal("sign-in never reached the barrier")
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, setErr = e.a.SetState(ctx, e.ten, a.ID, AccountDisabled, human)
			}()
			time.Sleep(300 * time.Millisecond) // SetState is now blocked on the sign-in's row lock
			close(release)
			wg.Wait()
			if signErr != nil || setErr != nil {
				t.Fatalf("sign-in: %v, SetState: %v", signErr, setErr)
			}
			var live int
			err := e.ss.db.WithTenant(ctx, e.ten, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM public.authn_sessions WHERE tenant_id = $1 AND account_id = $2::uuid AND state = 'active'`, e.ten.String(), a.ID).Scan(&live)
			})
			if err != nil || live != 0 {
				t.Fatalf("round %d: %d live sessions on a disabled account (err %v)", round, live, err)
			}
		}
	})
}
