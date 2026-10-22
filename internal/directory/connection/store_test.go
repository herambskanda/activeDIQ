package connection_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

const (
	cred = "11111111-1111-4111-8111-111111111111"
	idA  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	idB  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

type env struct {
	db   *store.DB
	d    *storetest.Database
	reg  *connection.Registry
	a, b tenant.ID
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	a := tenanttest.Seed(t, d.ExecOwner, "A")
	b := tenanttest.Seed(t, d.ExecOwner, "B")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return &env{db: db, d: d, reg: connection.NewRegistry(db), a: a, b: b}
}

// raw runs SQL inside the tenant's transaction, bypassing the Go store, to prove the database
// refuses on its own. It returns the error and the rows affected.
func (e *env) raw(tid tenant.ID, sql string, args ...any) (int64, error) {
	var n int64
	err := e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
		tag, err := tx.Exec(ctx, sql, args...)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// platform runs fn with no tenant context, to prove a tenant query outside WithTenant fails.
func (e *env) platform(fn func(ctx context.Context, tx store.Tx) error) error {
	return e.db.WithPlatform(context.Background(), "test: a tenant query outside WithTenant", fn)
}

func forest(name string) connection.New {
	return connection.New{Kind: connection.KindADForest, DisplayName: name, CredentialID: cred, Transport: connection.TransportLDAPS}
}

func (e *env) verifying(t *testing.T, tid tenant.ID, name string, ident string) connection.Connection {
	t.Helper()
	ctx := context.Background()
	c, err := e.reg.Create(ctx, tid, forest(name))
	if err != nil {
		t.Fatal(err)
	}
	if c.State != connection.StateDraft || c.DirectoryIdentity != "" {
		t.Fatalf("new connection: %+v", c)
	}
	if _, err := e.reg.Transition(ctx, tid, c.ID, connection.StateDraft, connection.StateVerifying); err != nil {
		t.Fatal(err)
	}
	if ident != "" {
		if c, err = e.reg.SetDirectoryIdentity(ctx, tid, c.ID, connection.DirectoryIdentity(ident)); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// Acceptance 1, stored side: an illegal request is rejected and the state is unchanged; a stale
// "from" is a conflict, not a write.
func TestIllegalAndStaleTransitionsLeaveStateUnchanged(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		c, err := e.reg.Create(ctx, e.a, forest("corp"))
		if err != nil {
			t.Fatal(err)
		}
		for _, to := range []connection.State{connection.StateSuspended, connection.StateDecommissioning, connection.StateRemoved} {
			if _, err := e.reg.Transition(ctx, e.a, c.ID, connection.StateDraft, to); !errors.Is(err, connection.ErrIllegalTransition) {
				t.Errorf("draft → %s: %v, want ErrIllegalTransition", to, err)
			}
		}
		// draft → active needs a verified identity: refused, typed.
		if _, err := e.reg.Transition(ctx, e.a, c.ID, connection.StateDraft, connection.StateActive); !errors.Is(err, connection.ErrIllegalTransition) {
			t.Errorf("draft → active with no identity: %v", err)
		}
		if _, err := e.reg.Transition(ctx, e.a, c.ID, connection.StateVerifying, connection.StateDraft); !errors.Is(err, connection.ErrStateConflict) {
			t.Errorf("stale from: %v, want ErrStateConflict", err)
		}
		got, _ := e.reg.Get(ctx, e.a, c.ID)
		if got.State != connection.StateDraft {
			t.Fatalf("state changed to %s", got.State)
		}
	})
}

// The full happy path L2…L8 and the retired_at / last_stamp_at rules of I13.
func TestLifecycleAndRetirementStamp(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		c := e.verifying(t, e.a, "corp", idA)
		step := func(from, to connection.State) connection.Connection {
			t.Helper()
			n, err := e.reg.Transition(ctx, e.a, c.ID, from, to)
			if err != nil {
				t.Fatalf("%s → %s: %v", from, to, err)
			}
			return n
		}
		if n := step(connection.StateVerifying, connection.StateActive); n.RetiredAt != nil {
			t.Fatal("active has no retired_at")
		}
		step(connection.StateActive, connection.StateSuspended)
		step(connection.StateSuspended, connection.StateActive)
		dec := step(connection.StateActive, connection.StateDecommissioning)
		if dec.RetiredAt == nil || dec.LastStampAt == nil || !dec.RetiredAt.Equal(*dec.LastStampAt) {
			t.Fatalf("decommissioning must set retired_at from the ordering stamp: %+v", dec)
		}
		rem := step(connection.StateDecommissioning, connection.StateRemoved)
		if rem.RetiredAt == nil || !rem.RetiredAt.Equal(*dec.RetiredAt) {
			t.Fatal("retired_at is written once")
		}
		if _, err := e.reg.Transition(ctx, e.a, c.ID, connection.StateRemoved, connection.StateActive); !errors.Is(err, connection.ErrIllegalTransition) {
			t.Fatalf("removed is terminal: %v", err)
		}
		// The database refuses a terminal exit even if Go is bypassed.
		if n, err := e.raw(e.a, `UPDATE public.connections SET state = 'active' WHERE id = $1::uuid`, string(c.ID)); err == nil || n != 0 {
			t.Fatal("database let a removed connection leave its terminal state")
		}

		d := e.verifying(t, e.a, "draft-to-discard", "")
		_ = d
		dr, err := e.reg.Create(ctx, e.a, forest("scratch"))
		if err != nil {
			t.Fatal(err)
		}
		disc, err := e.reg.Transition(ctx, e.a, dr.ID, connection.StateDraft, connection.StateDiscarded)
		if err != nil || disc.RetiredAt == nil {
			t.Fatalf("discard: %+v %v", disc, err)
		}
		list, _ := e.reg.List(ctx, e.a, false)
		for _, l := range list {
			if l.ID == dr.ID {
				t.Fatal("a discarded draft is hidden from the list")
			}
		}
		all, _ := e.reg.List(ctx, e.a, true)
		if len(all) != len(list)+1 {
			t.Fatalf("includeDiscarded: %d vs %d", len(all), len(list))
		}
	})
}

// Acceptance 2: the second live connection with the same (kind, identity) is refused with
// duplicate_identity; a removed (or discarded) one does not block; another kind or tenant does not collide.
func TestDuplicateIdentityAmongLiveConnections(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		first := e.verifying(t, e.a, "first", idA)

		second := e.verifying(t, e.a, "second", "")
		_, err := e.reg.SetDirectoryIdentity(ctx, e.a, second.ID, idA)
		if !errors.Is(err, connection.ErrDuplicateIdentity) || err.Error() != "connection: "+connection.CodeDuplicateIdentity {
			t.Fatalf("second live connection: %v, want duplicate_identity", err)
		}
		// Another tenant may hold the same forest.
		other := e.verifying(t, e.b, "other-tenant", idA)
		if other.DirectoryIdentity != idA {
			t.Fatal("tenant B must be able to connect the same forest")
		}
		// An Entra tenant of the same UUID text is a different kind.
		ent, err := e.reg.Create(ctx, e.a, connection.New{Kind: connection.KindEntraTenant, DisplayName: "m365", CredentialID: cred})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = e.reg.Transition(ctx, e.a, ent.ID, connection.StateDraft, connection.StateVerifying); err != nil {
			t.Fatal(err)
		}
		if _, err = e.reg.SetDirectoryIdentity(ctx, e.a, ent.ID, idA); err != nil {
			t.Fatalf("same text, other kind: %v", err)
		}

		// Remove the first; the identity can be connected again.
		for _, st := range [][2]connection.State{{connection.StateVerifying, connection.StateActive}, {connection.StateActive, connection.StateDecommissioning}, {connection.StateDecommissioning, connection.StateRemoved}} {
			if _, err := e.reg.Transition(ctx, e.a, first.ID, st[0], st[1]); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := e.reg.SetDirectoryIdentity(ctx, e.a, second.ID, idA); err != nil {
			t.Fatalf("a removed connection must not block: %v", err)
		}
	})
}

// Acceptance 3 (I1): once set, the identity cannot change, by the API or by raw SQL.
func TestIdentityFixedAfterFirstVerification(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		c := e.verifying(t, e.a, "corp", idA)
		if _, err := e.reg.SetDirectoryIdentity(ctx, e.a, c.ID, idB); !errors.Is(err, connection.ErrIdentityFixed) {
			t.Fatalf("change: %v, want ErrIdentityFixed", err)
		}
		if n, err := e.reg.SetDirectoryIdentity(ctx, e.a, c.ID, idA); err != nil || n.DirectoryIdentity != idA {
			t.Fatalf("setting the same value again is a no-op: %v", err)
		}
		if _, err := e.reg.SetDirectoryIdentity(ctx, e.a, c.ID, "not-a-guid"); !errors.Is(err, connection.ErrInvalid) {
			t.Fatalf("malformed identity: %v", err)
		}
		// Back to draft (a verification ends there): still fixed.
		if _, err := e.reg.Transition(ctx, e.a, c.ID, connection.StateVerifying, connection.StateDraft); err != nil {
			t.Fatal(err)
		}
		if _, err := e.reg.SetDirectoryIdentity(ctx, e.a, c.ID, idB); !errors.Is(err, connection.ErrIdentityFixed) {
			t.Fatalf("after returning to draft: %v", err)
		}
		// The database is the backstop for any writer: a raw UPDATE is refused.
		for _, q := range []string{
			`UPDATE public.connections SET directory_identity = '` + idB + `' WHERE id = $1::uuid`,
			`UPDATE public.connections SET directory_identity = '' WHERE id = $1::uuid`,
			`UPDATE public.connections SET kind = 'entra_tenant', transport_security = NULL WHERE id = $1::uuid`,
		} {
			if n, err := e.raw(e.a, q, string(c.ID)); err == nil || n != 0 {
				t.Errorf("database accepted: %s", q)
			}
		}
		// An identity is set only while verifying.
		d, _ := e.reg.Create(ctx, e.a, forest("draft"))
		if _, err := e.reg.SetDirectoryIdentity(ctx, e.a, d.ID, idB); !errors.Is(err, connection.ErrIdentityState) {
			t.Fatalf("identity on a draft: %v", err)
		}
	})
}

// Acceptance 4: tenant A cannot see tenant B's connections, and a query with no tenant context fails.
func TestTenantIsolation(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		ca, err := e.reg.Create(ctx, e.a, forest("a-corp"))
		if err != nil {
			t.Fatal(err)
		}
		cb, err := e.reg.Create(ctx, e.b, forest("b-corp"))
		if err != nil {
			t.Fatal(err)
		}
		la, _ := e.reg.List(ctx, e.a, true)
		if len(la) != 1 || la[0].ID != ca.ID {
			t.Fatalf("A lists %v", la)
		}
		if _, err := e.reg.Get(ctx, e.a, cb.ID); !errors.Is(err, connection.ErrNotFound) {
			t.Fatalf("A reads B's connection: %v", err)
		}
		if _, err := e.reg.Transition(ctx, e.a, cb.ID, connection.StateDraft, connection.StateDiscarded); !errors.Is(err, connection.ErrNotFound) {
			t.Fatalf("A changes B's connection: %v", err)
		}
		if got, _ := e.reg.Get(ctx, e.b, cb.ID); got.State != connection.StateDraft {
			t.Fatal("B's connection changed")
		}

		// No WithTenant: the registry refuses a zero tenant, and the store refuses a transaction
		// that has no tenant context.
		if _, err := e.reg.List(ctx, tenant.ID{}, true); !errors.Is(err, connection.ErrNoTenant) {
			t.Fatalf("zero tenant: %v", err)
		}
		var st connection.Store
		err = e.platform(func(ctx context.Context, tx store.Tx) error {
			if _, err := st.List(ctx, tx, true); !errors.Is(err, connection.ErrNoTenant) {
				t.Errorf("List outside a tenant: %v", err)
			}
			if _, err := st.Create(ctx, tx, forest("x")); !errors.Is(err, connection.ErrNoTenant) {
				t.Errorf("Create outside a tenant: %v", err)
			}
			if _, err := st.Get(ctx, tx, connection.ID(ca.ID)); !errors.Is(err, connection.ErrNoTenant) {
				t.Errorf("Get outside a tenant: %v", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestCreateValidation(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ctx := context.Background()
		for name, n := range map[string]connection.New{
			"no transport for AD": {Kind: connection.KindADForest, DisplayName: "x", CredentialID: cred},
			"transport for Entra": {Kind: connection.KindEntraTenant, DisplayName: "x", CredentialID: cred, Transport: connection.TransportLDAPS},
			"empty name":          {Kind: connection.KindEntraTenant, CredentialID: cred},
			"bad credential":      {Kind: connection.KindEntraTenant, DisplayName: "x", CredentialID: "nope"},
			"unknown kind":        {Kind: "ldap", DisplayName: "x", CredentialID: cred},
			"plaintext LDAP (I4)": {Kind: connection.KindADForest, DisplayName: "x", CredentialID: cred, Transport: "ldap"},
		} {
			if _, err := e.reg.Create(ctx, e.a, n); !errors.Is(err, connection.ErrInvalid) {
				t.Errorf("%s: %v, want ErrInvalid", name, err)
			}
		}
	})
}

// The database enforces the DM-10 edge table and the no-delete rule itself, for any writer
// (security review of T-0099): every ordered pair is attempted by a raw UPDATE as the runtime role.
func TestDatabaseEnforcesTheDM10Table(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		ids := 0
		retiring := func(st connection.State) bool {
			return st == connection.StateDecommissioning || st == connection.StateRemoved || st == connection.StateDiscarded
		}
		for _, from := range connection.States() {
			for _, to := range connection.States() {
				if from == to {
					continue
				}
				ids++
				id := fmt.Sprintf("00000000-0000-4000-8000-%012d", ids)
				ident := fmt.Sprintf("00000000-0000-4000-9000-%012d", ids)
				if from == connection.StateDraft || from == connection.StateVerifying || from == connection.StateDiscarded {
					ident = ""
				}
				_, err := e.raw(e.a, `INSERT INTO public.connections (tenant_id, id, kind, display_name, directory_identity, credential_id, state, retired_at, last_stamp_at, transport_security)
					VALUES (current_setting('app.tenant_id')::uuid, $1::uuid, 'ad_forest', 'pair', $2, $3::uuid, $4,
					        CASE WHEN $5::bool THEN now() END, CASE WHEN $5::bool THEN now() END, 'ldaps')`,
					id, ident, cred, string(from), retiring(from))
				if err != nil {
					t.Fatalf("seed %s: %v", from, err)
				}
				// Supply what the CHECKs need for a legal target (identity, retirement stamp), so only the edge decides.
				n, err := e.raw(e.a, `UPDATE public.connections SET state = $2,
					directory_identity = CASE WHEN directory_identity = '' AND $2 NOT IN ('draft','verifying','discarded') THEN $3 ELSE directory_identity END,
					retired_at = CASE WHEN retired_at IS NULL AND $4::bool THEN now() ELSE retired_at END,
					last_stamp_at = CASE WHEN last_stamp_at IS NULL AND $4::bool THEN now() ELSE last_stamp_at END
					WHERE id = $1::uuid`, id, string(to), fmt.Sprintf("00000000-0000-4000-a000-%012d", ids), retiring(to))
				if connection.CanTransition(from, to) {
					if err != nil || n != 1 {
						t.Errorf("%s → %s is declared but the database refused: n=%d %v", from, to, n, err)
					}
					continue
				}
				if store.SQLState(err) != "AD403" || n != 0 {
					t.Errorf("%s → %s is not declared: want AD403, got n=%d %v", from, to, n, err)
				}
			}
		}
		// Removal is a state, never a delete: the runtime role has no DELETE.
		if n, err := e.raw(e.a, `DELETE FROM public.connections WHERE id = $1::uuid`, "00000000-0000-4000-8000-000000000001"); store.SQLState(err) != "42501" || n != 0 {
			t.Fatalf("DELETE as the runtime role: n=%d %v, want 42501", n, err)
		}
	})
}
