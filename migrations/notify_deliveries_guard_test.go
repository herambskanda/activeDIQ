package migrations_test

import (
	"context"
	"sort"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// T-1108: the notify_deliveries_guard trigger (0062, ENABLE ALWAYS since 0066) is the database backstop for
// delivery-link authority (reports §7.2: who was sent what decides who may download). These tests prove, on
// every supported PostgreSQL version and as the runtime role, that it refuses a change to an identity column,
// any update of a finished delivery, and a decrease of attempts, each with SQLSTATE 23000
// (integrity_constraint_violation), and that it fires even in a session_replication_role = replica session.

const (
	guardTenant  = "00000000-0000-4000-8000-0000000000e1"
	guardTenant2 = "00000000-0000-4000-8000-0000000000e2"

	guardQueuedAccount = "00000000-0000-4000-8000-0000000000f1" // queued, recipient_kind account
	guardQueuedAddress = "00000000-0000-4000-8000-0000000000f2" // queued, recipient_kind address
	guardSent          = "00000000-0000-4000-8000-0000000000f3"
	guardGivenUp       = "00000000-0000-4000-8000-0000000000f4"
	guardFailed        = "00000000-0000-4000-8000-0000000000f5" // failed, attempts 2 of 3
	guardOtherUUID     = "00000000-0000-4000-8000-0000000000fa"
)

func guardDatabase(t *testing.T, s *storetest.Server) *storetest.Database {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	ctx := context.Background()
	a, err := d.Admin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(ctx)
	const cols = `(tenant_id, id, dedup_key, purpose, template_version, variables, recipient_kind, recipient_account,
		recipient_address, source_kind, source_id, requested_by, require_internal, state, attempts, max_attempts,
		next_attempt_at, sent_at, last_error_code)`
	for _, q := range []string{
		`INSERT INTO public.tenants (id, name) VALUES ('` + guardTenant + `', 'guard'), ('` + guardTenant2 + `', 'guard-two')`,
		`INSERT INTO public.notify_deliveries ` + cols + ` VALUES
		 ('` + guardTenant + `', '` + guardQueuedAccount + `', 'k-account', 'report.ready', 1, '{"report":"r1"}', 'account', '` + guardOtherUUID + `',
		  NULL, 'report_export', 'exp-1', 'alice', false, 'queued', 0, 3, now(), NULL, NULL),
		 ('` + guardTenant + `', '` + guardQueuedAddress + `', 'k-address', 'report.ready', 1, '{"report":"r2"}', 'address', NULL,
		  'bob@example.com', 'report_export', 'exp-2', 'alice', false, 'queued', 0, 3, now(), NULL, NULL),
		 ('` + guardTenant + `', '` + guardSent + `', 'k-sent', 'report.ready', 1, '{}', 'address', NULL,
		  'bob@example.com', 'report_export', 'exp-3', 'alice', false, 'sent', 1, 3, NULL, now(), NULL),
		 ('` + guardTenant + `', '` + guardGivenUp + `', 'k-given-up', 'report.ready', 1, '{}', 'address', NULL,
		  'bob@example.com', 'report_export', 'exp-4', 'alice', false, 'given_up', 3, 3, NULL, NULL, 'smtp_refused'),
		 ('` + guardTenant + `', '` + guardFailed + `', 'k-failed', 'report.ready', 1, '{}', 'address', NULL,
		  'bob@example.com', 'report_export', 'exp-5', 'alice', false, 'failed', 2, 3, now(), NULL, 'smtp_timeout')`,
	} {
		if _, err := a.Exec(ctx, q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	return d
}

// guardSnapshot returns the whole row as JSON text, read as the superuser, so "the row is unchanged" is one comparison.
func guardSnapshot(t *testing.T, d *storetest.Database, id string) string {
	t.Helper()
	ctx := context.Background()
	a, err := d.Admin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(ctx)
	var s string
	if err := a.QueryRow(ctx, `SELECT to_jsonb(d)::text FROM public.notify_deliveries d WHERE tenant_id = $1::uuid AND id = $2::uuid`, guardTenant, id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// guardUpdate runs one statement as the runtime role inside the tenant's context and returns its error.
// The statement is test fixture text.
func guardUpdate(t *testing.T, d *storetest.Database, stmt string, args ...any) error {
	t.Helper()
	ctx := context.Background()
	c, err := d.App(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	tx, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless committed below
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, guardTenant); err != nil {
		t.Fatal(err)
	}
	tag, err := tx.Exec(ctx, stmt, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("%s: %d rows affected; want 1 (row-level security hid the row, so the test would prove nothing)", stmt, tag.RowsAffected())
	}
	return tx.Commit(ctx)
}

func requireGuard(t *testing.T, what string, err error) {
	t.Helper()
	// store.SQLState is "" for anything that is not a PostgreSQL error (pgx stays behind the store boundary).
	switch code := store.SQLState(err); code {
	case "23000":
	case "":
		t.Errorf("%s: err = %v; want a PostgreSQL error with SQLSTATE 23000", what, err)
	default:
		t.Errorf("%s: SQLSTATE %s (%v); want 23000 from notify_deliveries_guard", what, code, err)
	}
}

// guardProgressColumns are the columns the delivery worker legitimately updates; every other column of
// notify_deliveries is identity and is covered by a case in TestNotifyDeliveriesGuardRefusesIdentityColumnChanges.
var guardProgressColumns = []string{"state", "attempts", "next_attempt_at", "lease_until", "last_error_code", "provider_message_id", "sent_at", "updated_at"}

// guardIdentityColumns are the columns that must never change after insert. Keep in step with the cases below.
var guardIdentityColumns = []string{"tenant_id", "id", "dedup_key", "channel", "purpose", "template_version", "variables",
	"recipient_kind", "recipient_account", "recipient_address", "source_kind", "source_id", "requested_by",
	"require_internal", "max_attempts", "created_at"}

// Column drift: a column added to notify_deliveries by a later migration must be classified here (identity,
// with a guard case, or progress) so it cannot go unguarded without a test failing.
func TestNotifyDeliveriesGuardCoversEveryColumn(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		ctx := context.Background()
		a, err := d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close(ctx)
		rows, err := a.Query(ctx, `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'notify_deliveries'`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		known := map[string]bool{}
		for _, c := range append(append([]string{}, guardIdentityColumns...), guardProgressColumns...) {
			known[c] = true
		}
		var actual, unclassified []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			actual = append(actual, c)
			if !known[c] {
				unclassified = append(unclassified, c)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		sort.Strings(unclassified)
		if len(unclassified) > 0 {
			t.Errorf("notify_deliveries has columns not classified as identity or progress: %v; guard them in notify_deliveries_guard (0062 trigger) and add a case here", unclassified)
		}
		have := map[string]bool{}
		for _, c := range actual {
			have[c] = true
		}
		for c := range known {
			if !have[c] {
				t.Errorf("column %s is listed in the guard test but not in notify_deliveries", c)
			}
		}
	})
}

// Acceptance 1: every identity column, one case each, against a queued delivery.
func TestNotifyDeliveriesGuardRefusesIdentityColumnChanges(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := guardDatabase(t, s)
		// Each SET clause names the column under test. Where the schema allows it the new row satisfies every
		// CHECK, so the trigger is the only thing standing in the way; a BEFORE trigger runs ahead of CHECK
		// constraints, which is why channel (CHECK channel = 'smtp') can still be probed with another value.
		cases := []struct{ column, row, set string }{
			{"tenant_id", guardQueuedAccount, `tenant_id = '` + guardTenant2 + `'::uuid`},
			{"id", guardQueuedAccount, `id = '` + guardOtherUUID + `'::uuid`},
			{"dedup_key", guardQueuedAccount, `dedup_key = 'k-other'`},
			{"channel", guardQueuedAccount, `channel = 'imap'`},
			{"purpose", guardQueuedAccount, `purpose = 'other.purpose'`},
			{"template_version", guardQueuedAccount, `template_version = 2`},
			{"variables", guardQueuedAccount, `variables = '{"report":"other"}'::jsonb`},
			{"recipient_kind", guardQueuedAccount, `recipient_kind = 'address', recipient_account = NULL, recipient_address = 'eve@example.net'`},
			{"recipient_account", guardQueuedAccount, `recipient_account = '` + guardTenant2 + `'::uuid`},
			{"recipient_address", guardQueuedAddress, `recipient_address = 'eve@example.net'`},
			{"source_kind", guardQueuedAccount, `source_kind = 'other_kind'`},
			{"source_id", guardQueuedAccount, `source_id = 'exp-other'`},
			{"requested_by", guardQueuedAccount, `requested_by = 'mallory'`},
			{"require_internal", guardQueuedAccount, `require_internal = true`},
			{"max_attempts", guardQueuedAccount, `max_attempts = 5`},
			{"created_at", guardQueuedAccount, `created_at = now() + interval '1 day'`},
		}
		covered := map[string]bool{}
		for _, tc := range cases {
			covered[tc.column] = true
		}
		for _, c := range guardIdentityColumns {
			if !covered[c] {
				t.Fatalf("identity column %s has no case", c)
			}
		}
		if len(cases) != len(guardIdentityColumns) {
			t.Fatalf("%d cases for %d identity columns", len(cases), len(guardIdentityColumns))
		}
		for _, tc := range cases {
			t.Run(tc.column, func(t *testing.T) {
				before := guardSnapshot(t, d, tc.row)
				err := guardUpdate(t, d, `UPDATE public.notify_deliveries SET `+tc.set+` WHERE id = $1::uuid`, tc.row)
				requireGuard(t, "update of "+tc.column, err)
				// tenant_id and id move the row's key: look the row up by its original key.
				if after := guardSnapshot(t, d, tc.row); after != before {
					t.Errorf("row changed after the refused update of %s:\nbefore %s\nafter  %s", tc.column, before, after)
				}
			})
		}

		// Control: progress columns are not guarded, so the guard is not simply refusing every update.
		t.Run("progress_columns_still_update", func(t *testing.T) {
			if err := guardUpdate(t, d, `UPDATE public.notify_deliveries SET state = 'failed', attempts = 1, last_error_code = 'smtp_timeout',
				next_attempt_at = now() + interval '1 minute', lease_until = NULL, updated_at = now() WHERE id = $1::uuid`, guardQueuedAddress); err != nil {
				t.Fatalf("progress update refused: %v", err)
			}
		})
	})
}

// Acceptance 2: a finished delivery is final, and attempts never decrease.
func TestNotifyDeliveriesGuardFinalityAndAttemptsMonotonic(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := guardDatabase(t, s)

		for _, tc := range []struct{ name, row string }{{"sent", guardSent}, {"given_up", guardGivenUp}} {
			t.Run("final_"+tc.name, func(t *testing.T) {
				for _, set := range []string{
					`updated_at = now()`,
					`attempts = attempts`,
					`last_error_code = 'other_code'`,
					`provider_message_id = 'mid-1'`,
				} {
					before := guardSnapshot(t, d, tc.row)
					err := guardUpdate(t, d, `UPDATE public.notify_deliveries SET `+set+` WHERE id = $1::uuid`, tc.row)
					requireGuard(t, tc.name+" delivery: SET "+set, err)
					if after := guardSnapshot(t, d, tc.row); after != before {
						t.Errorf("%s delivery changed after the refused update SET %s", tc.name, set)
					}
				}
			})
		}

		// A delivery reaches 'sent' through a legitimate update and is final from then on.
		t.Run("final_after_transition", func(t *testing.T) {
			if err := guardUpdate(t, d, `UPDATE public.notify_deliveries SET state = 'sent', attempts = 1, next_attempt_at = NULL,
				lease_until = NULL, sent_at = now(), updated_at = now() WHERE id = $1::uuid`, guardQueuedAccount); err != nil {
				t.Fatalf("queued -> sent refused: %v", err)
			}
			before := guardSnapshot(t, d, guardQueuedAccount)
			err := guardUpdate(t, d, `UPDATE public.notify_deliveries SET state = 'failed', last_error_code = 'smtp_timeout',
				next_attempt_at = now(), sent_at = NULL WHERE id = $1::uuid`, guardQueuedAccount)
			requireGuard(t, "sent -> failed", err)
			if after := guardSnapshot(t, d, guardQueuedAccount); after != before {
				t.Error("sent delivery changed after the refused re-open")
			}
		})

		t.Run("attempts_never_decrease", func(t *testing.T) {
			// Control: equal and increasing attempts are accepted (2 -> 3 of max 3).
			if err := guardUpdate(t, d, `UPDATE public.notify_deliveries SET attempts = 2, updated_at = now() WHERE id = $1::uuid`, guardFailed); err != nil {
				t.Fatalf("attempts 2 -> 2 refused: %v", err)
			}
			if err := guardUpdate(t, d, `UPDATE public.notify_deliveries SET attempts = 3, updated_at = now() WHERE id = $1::uuid`, guardFailed); err != nil {
				t.Fatalf("attempts 2 -> 3 refused: %v", err)
			}
			for _, n := range []int{2, 0} {
				before := guardSnapshot(t, d, guardFailed)
				err := guardUpdate(t, d, `UPDATE public.notify_deliveries SET attempts = $2 WHERE id = $1::uuid`, guardFailed, n)
				requireGuard(t, "attempts 3 -> lower", err)
				if after := guardSnapshot(t, d, guardFailed); after != before {
					t.Errorf("attempts changed after the refused decrease to %d", n)
				}
			}
		})
	})
}

// Acceptance 3: the guard is ENABLE ALWAYS, so a superuser in a replica-role session (which skips ordinary
// triggers) is refused too. Without 0066 this update would succeed.
func TestNotifyDeliveriesGuardFiresUnderReplicaRole(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := guardDatabase(t, s)
		ctx := context.Background()
		a, err := d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close(ctx)

		var enabled string
		if err := a.QueryRow(ctx, `SELECT tgenabled::text FROM pg_trigger WHERE tgname = 'notify_deliveries_guard' AND tgrelid = 'public.notify_deliveries'::regclass`).Scan(&enabled); err != nil || enabled != "A" {
			t.Errorf("notify_deliveries_guard tgenabled = %q (%v); want A (ENABLE ALWAYS)", enabled, err)
		}
		if _, err := a.Exec(ctx, `SET session_replication_role = replica`); err != nil {
			t.Fatal(err)
		}
		var role string
		if err := a.QueryRow(ctx, `SHOW session_replication_role`).Scan(&role); err != nil || role != "replica" {
			t.Fatalf("session_replication_role = %q (%v); want replica", role, err)
		}

		before := guardSnapshot(t, d, guardQueuedAddress)
		_, err = a.Exec(ctx, `UPDATE public.notify_deliveries SET recipient_address = 'eve@example.net' WHERE id = $1::uuid`, guardQueuedAddress)
		requireGuard(t, "replica-role update of recipient_address", err)
		if after := guardSnapshot(t, d, guardQueuedAddress); after != before {
			t.Error("recipient_address changed under session_replication_role = replica")
		}
	})
}
