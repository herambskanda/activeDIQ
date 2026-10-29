package connection_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const cred2 = "22222222-2222-4222-8222-222222222222"

func (e *svcEnv) bindings(t *testing.T, id connection.ID) []connection.Binding {
	t.Helper()
	var bs []connection.Binding
	err := e.db.WithTenant(context.Background(), e.a, func(ctx context.Context, tx store.Tx) (err error) {
		bs, err = connection.Store{}.Bindings(ctx, tx, id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return bs
}

func (e *svcEnv) activeConn(t *testing.T) connection.Connection {
	t.Helper()
	c := e.draft(t)
	e.cl.set(passing(), nil)
	out, err := e.svc.Activate(context.Background(), e.a, c.ID, human("alice"))
	if err != nil || out.Connection.State != connection.StateActive {
		t.Fatalf("activate: %v %+v", err, out.Connection)
	}
	return out.Connection
}

// DM-13 / DM-10.I3: activation creates the embedded binding in its own transaction; a refused one
// leaves none.
func TestActivationCreatesTheEmbeddedBinding(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		refused := e.draft(t)
		e.cl.set(overPriv("g1"), nil)
		if _, err := e.svc.Activate(context.Background(), e.a, refused.ID, human("alice")); err == nil {
			t.Fatal("over-privileged activation succeeded")
		}
		if bs := e.bindings(t, refused.ID); len(bs) != 0 {
			t.Fatalf("a refused activation left bindings: %+v", bs)
		}
		e.cl.set(passing(), nil)
		out, err := e.svc.Activate(context.Background(), e.a, refused.ID, human("alice"))
		if err != nil || out.Connection.State != connection.StateActive {
			t.Fatalf("activate: %v", err)
		}
		bs := e.bindings(t, refused.ID)
		if len(bs) != 1 || bs[0].Target != connection.TargetEmbedded || bs[0].State != "active" {
			t.Fatalf("bindings after activation: %+v", bs)
		}
	})
}

// The database refuses an active connection with no live binding, whatever wrote the row.
func TestDatabaseRefusesActivationWithoutBinding(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		c := e.draft(t)
		e.cl.set(passing(), nil)
		if _, err := e.svc.Verify(context.Background(), e.a, c.ID, connection.KindOnboarding, human("alice")); err != nil {
			t.Fatal(err)
		}
		_, err := e.raw(e.a, `UPDATE public.connections SET state = 'active' WHERE id = $1::uuid`, string(c.ID))
		if err == nil {
			t.Fatal("raw activation without a binding succeeded")
		}
	})
}

// FR-21: a passing credential_change run swaps the credential; the run is the new pointer.
func TestCredentialChangePassSwaps(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		c := e.activeConn(t)
		before := len(e.rec.kinds())
		e.cl.set(passing(), nil)
		out, err := e.svc.ChangeCredential(context.Background(), e.a, c.ID, cred2, human("alice"))
		if err != nil {
			t.Fatal(err)
		}
		if out.Verification.Kind != connection.KindCredentialChange || out.Verification.CredentialID != cred2 {
			t.Fatalf("run: %+v", out.Verification)
		}
		got, _ := e.reg.Get(context.Background(), e.a, c.ID)
		if got.CredentialID != cred2 || got.LastVerificationID != string(out.Verification.ID) || got.VerifiedAt == nil || got.State != connection.StateActive {
			t.Fatalf("after swap: %+v", got)
		}
		kinds := e.rec.kinds()[before:]
		if len(kinds) != 2 || kinds[0] != connection.AuditVerificationCompleted || kinds[1] != connection.AuditCredentialChanged {
			t.Fatalf("audit kinds %v", kinds)
		}
		for _, ev := range e.rec.evs {
			if ev.Kind == audit.Kind(connection.AuditCredentialChanged) && ev.Changes[0].Before[0] != cred {
				t.Fatalf("event before = %v", ev.Changes[0].Before)
			}
		}
	})
}

// FR-21: any other outcome keeps the old credential, pointer and verified_at, and keeps the evidence.
func TestCredentialChangeFailureKeepsTheOldCredential(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		c := e.activeConn(t)
		was, _ := e.reg.Get(context.Background(), e.a, c.ID)
		wrongForest := passing()
		wrongForest.DirectoryIdentity = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		cases := map[string]connection.VerifyResult{
			"refused":        overPriv("g1"),
			"wrong identity": wrongForest,
		}
		for name, res := range cases {
			e.cl.set(res, nil)
			out, err := e.svc.ChangeCredential(context.Background(), e.a, c.ID, cred2, human("alice"))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if out.Verification.ID == "" || out.Verification.CredentialID != cred2 {
				t.Fatalf("%s: evidence not kept: %+v", name, out.Verification)
			}
			got, _ := e.reg.Get(context.Background(), e.a, c.ID)
			if got.CredentialID != cred || got.LastVerificationID != was.LastVerificationID || got.VerifiedAt == nil ||
				!got.VerifiedAt.Equal(*was.VerifiedAt) || got.State != connection.StateActive {
				t.Fatalf("%s: old credential not kept: %+v", name, got)
			}
		}
		// A connector error is an interrupted run: recorded failed, old credential kept.
		e.cl.set(connection.VerifyResult{}, errors.New("dc unreachable"))
		if _, err := e.svc.ChangeCredential(context.Background(), e.a, c.ID, cred2, human("alice")); !errors.Is(err, connection.ErrRunInterrupted) {
			t.Fatalf("err = %v, want interrupted", err)
		}
		got, _ := e.reg.Get(context.Background(), e.a, c.ID)
		if got.CredentialID != cred || got.LastVerificationID != was.LastVerificationID {
			t.Fatalf("interrupted run moved the connection: %+v", got)
		}
	})
}

func TestCredentialChangeRefusals(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := newSvc(t, s)
		c := e.activeConn(t)
		ctx := context.Background()
		e.cl.set(passing(), nil)
		if _, err := e.svc.ChangeCredential(ctx, e.a, c.ID, cred, human("alice")); !errors.Is(err, connection.ErrInvalid) {
			t.Fatalf("same credential: %v", err)
		}
		if _, err := e.svc.ChangeCredential(ctx, e.a, c.ID, "nope", human("alice")); err == nil {
			t.Fatal("malformed credential accepted")
		}
		d := e.draft(t)
		if _, err := e.svc.ChangeCredential(ctx, e.a, d.ID, cred2, human("alice")); !errors.Is(err, connection.ErrIllegalTransition) {
			t.Fatalf("draft: %v", err)
		}
		// Verify still refuses the kind: a swap goes only through ChangeCredential.
		if _, err := e.svc.Verify(ctx, e.a, c.ID, connection.KindCredentialChange, human("alice")); !errors.Is(err, connection.ErrInvalid) {
			t.Fatalf("Verify(credential_change): %v", err)
		}
	})
}
