package inventory_test

// Batch-2 library reports on a larger directory (T-0962; ADR-0010 budgets are calibrated by B13). The test
// loads 20,000 users, 5,000 computers, 1,000 groups (about 40 members each, one chain of nested groups) and
// 100 OUs, then runs every preset of the ten reports to the end and logs the time. It asserts the counts
// that must hold at any size, and that no preset takes longer than a generous bound that would catch a
// nested-loop plan (the planner needs statistics; see Test_group_member_counts_at_scale).

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func Test_reports_library_batch2_at_scale(t *testing.T) {
	if testing.Short() {
		t.Skip("loads 25,000 objects")
	}
	users, comps, groups, ous := 20000, 5000, 1000, 100
	if n, err := strconv.Atoi(os.Getenv("ADIQ_SCALE_USERS")); err == nil && n > 0 { // a smaller load to read plans quickly
		users, comps = n, n/4
	}
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		l, err := library.Load(library.Shipped(), library.Options{Datasets: inventory.Datasets(), Registry: reg})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		e.hStructure(t, e.adA)
		now := hBase.Add(200 * 24 * time.Hour)
		old := now.Add(-day(300))
		var batch []inventory.Observation
		flush := func() {
			if len(batch) > 0 {
				if _, err := e.populate(t, e.adA, hBase.Add(time.Hour), batch...); err != nil {
					t.Fatal(err)
				}
				batch = batch[:0]
			}
		}
		add := func(o inventory.Observation) {
			batch = append(batch, o)
			if len(batch) == 1000 {
				flush()
			}
		}
		members := make([][]string, groups)
		for i := 0; i < users; i++ {
			g := hGUID(1, i+1)
			u := hUser{guid: g, sam: fmt.Sprintf("u%05d", i), rid: uint32(10000 + i), uac: i64(uacNormal), read: allRead, pwdLastSet: now.Add(-day(i % 80))}.obs()
			u.WhenCreated = old
			u.LastLogonTimestamp = now.Add(-day(i % 200))
			members[i%groups] = append(members[i%groups], g)
			members[(i*7+1)%groups] = append(members[(i*7+1)%groups], g)
			add(u)
		}
		for i := 0; i < comps; i++ {
			attrs := map[string]any{"operatingSystem": []string{"Windows 11 Pro", "Windows Server 2022 Standard", "Ubuntu"}[i%3]}
			add(withAttrs(hComputer(hGUID(3, i+1), fmt.Sprintf("PC%05d", i), uint32(50000+i), 4096, attrs), old, attrs))
		}
		for i := 0; i < ous; i++ {
			add(ouObs(hGUID(6, i+1), fmt.Sprintf("ou%03d", i), hOU, hOU, hDom))
		}
		for i := 0; i < groups; i++ {
			m := members[i]
			if i%10 != 9 && i < 500 { // chains of nested groups, nine deep: 0 in 1 in 2 ...
				m = append(m, hGUID(2, i+2))
			}
			g := hGroup(hGUID(2, i+1), fmt.Sprintf("G%04d", i), uint32(2000+i), m...)
			gt := int32(-2147483646)
			g.Facts.GroupType = &gt
			g.WhenCreated = old
			add(g)
		}
		flush()
		// Autovacuum would analyse the tables within minutes; the app role may not ANALYZE them.
		// A bulk load leaves the GIN index's pending list full, which the planner prices as a scan; autovacuum
		// flushes it in production.
		for _, stmt := range []string{"SELECT gin_clean_pending_list('directory_objects_by_ancestry')", "ANALYZE"} {
			if err := e.d.ExecOwner(context.Background(), stmt); err != nil {
				t.Fatal(err)
			}
		}
		syncDays := 14
		e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
			return w.SetDomainPolicy(ctx, tx, e.adA, inventory.GUID(hDom),
				inventory.DomainPolicy{MaxPwdAge: days(domainMaxAge), LockoutDuration: mins(30), LogonSyncIntervalDays: &syncDays, PSOsReadAt: hBase}, hBase)
		})

		scope := e.scopeNC(e.adA)
		type run struct {
			id, preset string
			rp         report.RunParams
		}
		grpIDs := func(n int) (out []authz.ObjectID) {
			for i := 0; i < n; i++ {
				out = append(out, rpID(hGUID(2, i+1)))
			}
			return
		}
		var runs []run
		for _, id := range []string{"pwd-01", "pwd-02", "grp-01", "grp-04", "cmp-01", "cmp-02", "ctc-01", "ou-01"} {
			d, _ := l.Definition(id, 0)
			for _, p := range d.Def.Presets {
				runs = append(runs, run{id: id, preset: p.ID})
			}
		}
		runs = append(runs,
			run{"grp-02", "members", report.RunParams{Subjects: grpIDs(1)}},
			run{"grp-02", "detailed", report.RunParams{Subjects: grpIDs(1)}},
			run{"grp-02", "detailed", report.RunParams{Subjects: grpIDs(20)}},
			run{"grp-02", "users", report.RunParams{Subjects: grpIDs(1)}},
			run{"grp-03", "groups_for_users", report.RunParams{Subjects: []authz.ObjectID{rpID(hGUID(1, 1))}}},
			run{"grp-03", "groups_for_users", report.RunParams{Subjects: func() (out []authz.ObjectID) {
				for i := 0; i < 100; i++ {
					out = append(out, rpID(hGUID(1, i+1)))
				}
				return
			}()}})
		for _, r := range runs {
			start := time.Now()
			rows, err := e.runB2(t, l, r.id, r.preset, r.rp, scope, now)
			took := time.Since(start)
			if err != nil {
				t.Errorf("%s/%s: %v", r.id, r.preset, err)
				continue
			}
			t.Logf("%s/%s (%d subjects): %d rows in %v", r.id, r.preset, len(r.rp.Subjects), len(rows), took.Round(time.Millisecond))
			if took > 20*time.Second {
				t.Errorf("%s/%s took %v: check the query plan", r.id, r.preset, took)
			}
		}
		all := os.Getenv("ADIQ_SCALE_PLANS") != "" // every plan line, not only the scans of the objects table
		if testing.Verbose() {                     // the plans behind the slowest timings
			for _, k := range [][2]string{{"ou-01", "all"}, {"pwd-01", "never"}} {
				d, _ := l.Definition(k[0], 0)
				q, err := report.Resolve(d.Def, k[1], report.RunParams{}, d.Dataset)
				if err != nil {
					t.Fatal(err)
				}
				cq, err := reportsql.Compile(q, d.SQL, scope, reportsql.Inputs{Now: now})
				if err != nil {
					t.Fatal(err)
				}
				text, args := cq.Statement()
				_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
					rows, err := tx.Query(ctx, "EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF) "+text, args...)
					if err != nil {
						return err
					}
					defer rows.Close()
					for rows.Next() {
						var line string
						if err := rows.Scan(&line); err != nil {
							return err
						}
						if all || strings.Contains(line, "Scan on directory_objects") || strings.Contains(line, "Execution Time") || strings.Contains(line, "Bitmap Index") {
							t.Logf("plan %s/%s: %.170s", k[0], k[1], line)
						}
					}
					return rows.Err()
				})
			}
		}
		// counts that must hold at any size
		if rows, _ := e.runB2(t, l, "cmp-01", "all", report.RunParams{}, scope, now); len(rows) != comps {
			t.Errorf("cmp-01/all rows = %d, want %d", len(rows), comps)
		}
		if rows, _ := e.runB2(t, l, "grp-01", "all", report.RunParams{}, scope, now); len(rows) < groups {
			t.Errorf("grp-01/all rows = %d, want at least %d", len(rows), groups)
		}
		if rows, _ := e.runB2(t, l, "ou-01", "all", report.RunParams{}, scope, now); len(rows) < ous {
			t.Errorf("ou-01/all rows = %d, want at least %d", len(rows), ous)
		}
	})
}
