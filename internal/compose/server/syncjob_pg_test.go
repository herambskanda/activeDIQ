package server

// Composition tests for the directory sync supervisor (T-1192): which connections it queues, and that an
// install with none is a no-op. The job body and its leases are tested in internal/directory/sync.

import (
	"context"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	dsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/jobs"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

const syncCred = "22222222-2222-4222-8222-222222222222"

func TestSyncSupervisorQueuesOnlyActiveADConnections(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		d := s.NewDatabase(t)
		d.Migrate(t)
		tid := tenanttest.Seed(t, d.ExecOwner, "A")
		db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		conns := connection.NewRegistry(db)
		jreg := jobs.NewRegistry()
		k, err := buildSync(db, conns, fixedConnectorSource{}, jreg, "node-1", time.Hour, 0)
		if err != nil {
			t.Fatal(err)
		}
		queued := func() string {
			out, err := d.OwnerStrings(ctx, `SELECT count(*)::text FROM public.jobs WHERE kind = $1 AND state = 'available'`, dsync.JobFull)
			if err != nil || len(out) != 1 {
				t.Fatalf("count jobs: %v %v", out, err)
			}
			return out[0]
		}

		// Boot with zero connections: a no-op, no error.
		if n, err := k.Supervisor.enqueueActive(ctx, tid); err != nil || n != 0 || queued() != "0" {
			t.Fatalf("zero connections: queued %d err %v rows %s", n, err, queued())
		}

		mk := func(name string) connection.Connection {
			c, err := conns.Create(ctx, tid, connection.New{Kind: connection.KindADForest, DisplayName: name, CredentialID: syncCred, Transport: connection.TransportLDAPS})
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
		activate := func(c connection.Connection, ident string, verdictID string) {
			if _, err := conns.Transition(ctx, tid, c.ID, connection.StateDraft, connection.StateVerifying); err != nil {
				t.Fatal(err)
			}
			if _, err := conns.SetDirectoryIdentity(ctx, tid, c.ID, connection.DirectoryIdentity(ident)); err != nil {
				t.Fatal(err)
			}
			if err := db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error {
				if _, err := (connection.Store{}).RecordVerification(ctx, tx, connection.NewVerification{
					ID: connection.VerificationID(verdictID), ConnectionID: c.ID, CredentialID: syncCred, Kind: connection.KindManual,
					RequestedBy: "principal-test", StartedAt: time.Now(), CheckListVersion: 1, Verdict: connection.VerdictPass,
					Outcomes: map[connection.Check]connection.Outcome{"V5": connection.OutcomePass,
						connection.CheckV7OverPrivilege: connection.OutcomePass, connection.CheckV8ReadSufficient: connection.OutcomePass},
				}); err != nil {
					return err
				}
				_, err := (connection.Store{}).Activate(ctx, tx, c.ID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		_ = mk("draft") // stays a draft
		active := mk("active")
		activate(active, "aaaaaaaa-0000-4000-8000-0000000000f1", "00000000-0000-4000-b000-000000000001")
		suspended := mk("suspended")
		activate(suspended, "aaaaaaaa-0000-4000-8000-0000000000f2", "00000000-0000-4000-b000-000000000002")
		if _, err := conns.Transition(ctx, tid, suspended.ID, connection.StateActive, connection.StateSuspended); err != nil {
			t.Fatal(err)
		}

		if n, err := k.Supervisor.enqueueActive(ctx, tid); err != nil || n != 1 || queued() != "1" {
			t.Fatalf("one active connection: queued %d err %v rows %s", n, err, queued())
		}
		// Boot, activation and the interval can all fire: the surplus is dropped, not queued twice.
		if n, err := k.Supervisor.enqueueActive(ctx, tid); err != nil || n != 0 || queued() != "1" {
			t.Fatalf("second pass: queued %d err %v rows %s", n, err, queued())
		}
		args, err := d.OwnerStrings(ctx, `SELECT args->>'connection' FROM public.jobs WHERE kind = $1`, dsync.JobFull)
		if err != nil || len(args) != 1 || args[0] != string(active.ID) {
			t.Fatalf("the queued job is for %v, want only the active connection %s (%v)", args, active.ID, err)
		}
	})
}

func TestSyncIntervalIsBounded(t *testing.T) {
	for _, bad := range []time.Duration{0, time.Minute, config.MinSyncInterval - time.Second, config.MaxSyncInterval + time.Second} {
		if _, err := newSyncSupervisor(nil, nil, nil, bad); err == nil {
			t.Errorf("interval %s accepted", bad)
		}
	}
	if _, err := newSyncSupervisor(nil, nil, nil, config.MinSyncInterval); err != nil {
		t.Errorf("the minimum interval was refused: %v", err)
	}
}
