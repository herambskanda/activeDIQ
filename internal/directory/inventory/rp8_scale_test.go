package inventory_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// T-1073 acceptance: password_state over a large directory reads the closure, not a per-row walk of
// links. ADIQ_PSO_SCALE_USERS sets the user count (T-1073 measured 200000); unset, the test skips.
func Test_password_state_reads_closure_at_scale(t *testing.T) {
	users, err := strconv.Atoi(os.Getenv("ADIQ_PSO_SCALE_USERS"))
	if err != nil || users <= 0 {
		t.Skip("set ADIQ_PSO_SCALE_USERS (200000 for the T-1073 measurement)")
	}
	const groups, psos = 200, 20
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		now := hBase.Add(100 * 24 * time.Hour)
		// Populate's cost per batch grows with the table (T-1611), so seeding 200,000 users through it never
		// finishes. The structure goes through Populate (one real user as the template, the groups with their
		// nesting, the PSOs); the other users and their member links are cloned with one bulk INSERT as the
		// owner role, the closure is then derived by the real RefreshClosure, a few groups at a time (a refresh
		// over all 220,000 links in one transaction exceeds the 30 s statement timeout).
		structure := []inventory.Observation{hUser{guid: hGUID(1, 1), sam: "u000000", rid: 10000, uac: i64(uacNormal), read: 15,
			pwdLastSet: now.Add(-day(0))}.obs()}
		for i := 0; i < groups; i++ {
			var m []string
			if i%2 == 0 {
				m = append(m, hGUID(2, i+2))
			}
			structure = append(structure, hGroup(hGUID(2, i+1), fmt.Sprintf("G%04d", i), uint32(2000+i), m...))
		}
		for i := 0; i < psos; i++ {
			structure = append(structure, hPSOObj(hGUID(3, i+1), fmt.Sprintf("PSO%02d", i)))
		}
		if _, err := e.populate(t, e.adA, now.Add(-time.Hour), structure...); err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		// n is the 1-based user number: GUID 01000000-0000-4000-8000-<n hex>, rid 10000+n-1 (little endian in the SID).
		const userGUID = `format('01000000-0000-4000-8000-%s', lpad(to_hex(n), 12, '0'))::uuid`
		const chunk = 20_000 // keeps each statement well inside the 30 s statement timeout
		for lo := 2; lo <= users; lo += chunk {
			hi := min(lo+chunk-1, users)
			if err := e.bulkExec(t, `INSERT INTO public.directory_objects (tenant_id, connection_id, object_guid, nc_guid, kind, object_class,
				parent_guid, ancestry, dn, rdn, sid, sam_account_name, enabled, pwd_last_set, attributes, when_created, observed_at, observed_dsa, state,
				ancestry_complete, user_account_control, primary_group_id, last_logon_timestamp, spn_present, inputs_read)
			SELECT t.tenant_id, t.connection_id, `+userGUID+`, t.nc_guid, t.kind, t.object_class, t.parent_guid, t.ancestry,
				'CN=u' || lpad((n-1)::text, 6, '0') || ',OU=People,DC=example,DC=test', 'CN=u' || lpad((n-1)::text, 6, '0'),
				substring(t.sid for 28) || decode(lpad(to_hex((9999+n) & 255), 2, '0') || lpad(to_hex(((9999+n) >> 8) & 255), 2, '0')
					|| lpad(to_hex(((9999+n) >> 16) & 255), 2, '0') || '00', 'hex'),
				'u' || lpad((n-1)::text, 6, '0'), t.enabled, $3::timestamptz - ((n-1) % 80) * interval '1 day', t.attributes, t.when_created, t.observed_at, t.observed_dsa, t.state,
				t.ancestry_complete, t.user_account_control, t.primary_group_id, t.last_logon_timestamp, t.spn_present, t.inputs_read
			FROM public.directory_objects t, generate_series($4::int, $6::int) AS n
			WHERE t.tenant_id = $1::uuid AND t.connection_id = $2::uuid AND t.object_guid = '01000000-0000-4000-8000-000000000001' AND $5::int > 0`,
				string(e.adA), now, lo, groups, hi); err != nil {
				t.Fatal(err)
			}
		}
		// About 1.1 groups per user, plus nesting two deep for half the groups, keeps the closure near 1.6 rows
		// per user, inside the declared budget (an over-budget closure makes every user unresolved: the other test).
		for lo := 1; lo <= users; lo += chunk {
			hi := min(lo+chunk-1, users)
			if err := e.bulkExec(t, `INSERT INTO public.links (tenant_id, connection_id, source_guid, link_attr, target_guid, state, observed_at)
			SELECT $1::uuid, $2::uuid, g, 'member', `+userGUID+`, 'active', $3::timestamptz
			FROM generate_series($4::int, $6::int) AS n,
			LATERAL (VALUES (format('02000000-0000-4000-8000-%s', lpad(to_hex(1 + ((n-1) % $5::int)), 12, '0'))::uuid),
				(CASE WHEN (n-1) % 10 = 0 THEN format('02000000-0000-4000-8000-%s', lpad(to_hex(1 + (((n-1)*7+1) % $5::int)), 12, '0'))::uuid END)) AS v(g)
			WHERE g IS NOT NULL ON CONFLICT DO NOTHING`, string(e.adA), now, lo, groups, hi); err != nil {
				t.Fatal(err)
			}
		}
		for _, tbl := range []string{"directory_objects", "links"} { // fresh statistics, as autovacuum would have by the time a customer reads
			if err := e.d.ExecOwner(context.Background(), "ANALYZE public."+tbl); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("bulk seed of %d users and their links: %s", users, time.Since(t0))
		for g := 0; g < groups; g += 10 {
			if err := e.bulkExec(t, `INSERT INTO public.inventory_group_closure_dirty (tenant_id, connection_id, group_guid)
				SELECT $1::uuid, $2::uuid, format('02000000-0000-4000-8000-%s', lpad(to_hex(i), 12, '0'))::uuid FROM generate_series($3::int, $4::int) AS i
				ON CONFLICT DO NOTHING`, string(e.adA), g+1, g+10); err != nil {
				t.Fatal(err)
			}
			if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
				_, err := inventory.Writer{}.RefreshClosure(ctx, tx, e.adA)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("seed incl. closure: %s", time.Since(t0))
		for _, stmt := range []string{"SELECT gin_clean_pending_list('directory_objects_by_ancestry')", "ANALYZE"} {
			if err := e.d.ExecOwner(context.Background(), stmt); err != nil {
				t.Fatal(err)
			}
		}
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			if err := pw.SetDomainPolicy(ctx, tx, e.adA, inventory.GUID(hDom),
				inventory.DomainPolicy{MaxPwdAge: days(42), LockoutDuration: mins(30), PSOsReadAt: hBase}, hBase); err != nil {
				return err
			}
			for i := 0; i < psos; i++ {
				if err := pw.SetPSO(ctx, tx, e.adA, inventory.GUID(hGUID(3, i+1)), inventory.GUID(hDom),
					inventory.PSO{Precedence: i64(int64(i + 1)), MaxPwdAge: days(int64(10 + i)), LockoutDuration: mins(5)}, hBase); err != nil {
					return err
				}
				if err := pw.SetPSOApplies(ctx, tx, e.adA, inventory.GUID(hGUID(3, i+1)), inventory.GUID(hGUID(2, i*10+1)), hBase); err != nil {
					return err
				}
			}
			return nil
		})
		if err := e.d.ExecOwner(context.Background(), "ANALYZE"); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: []report.ColumnID{"sam_account_name", "password_state", "policy_source"},
			scope: e.scopeNC(e.adA), now: now})
		took := time.Since(start)
		if len(res.rows) != users {
			t.Fatalf("%d rows, want %d", len(res.rows), users)
		}
		viaPSO := 0
		for _, r := range res.rows {
			if string(r["policy_source"].DigestValue()) != "Domain policy" {
				viaPSO++
			}
		}
		var plan strings.Builder
		if err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			rows, err := tx.Query(ctx, "EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF) "+res.sql[0], res.args[0]...)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var l string
				if err := rows.Scan(&l); err != nil {
					return err
				}
				plan.WriteString(l + "\n")
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		t.Logf("plan:\n%s", plan.String())
		t.Logf("T-1073 measurement: %d users, %d groups, %d PSOs: password_state run %s, %d users on a PSO", users, groups, psos, took, viaPSO)
		if !strings.Contains(plan.String(), "inventory_group_members") {
			t.Errorf("plan does not read inventory_group_members:\n%s", plan.String())
		}
		if strings.Contains(plan.String(), "WorkTable") || strings.Contains(plan.String(), "Recursive Union") {
			t.Errorf("plan still walks links recursively:\n%s", plan.String())
		}
	})
}

// bulkExec runs one bulk fixture statement in the tenant's transaction; $1 is the tenant, the rest follow.
func (e *env) bulkExec(t *testing.T, sql string, args ...any) error {
	t.Helper()
	return e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, sql, append([]any{e.a.String()}, args...)...)
		return err
	})
}
