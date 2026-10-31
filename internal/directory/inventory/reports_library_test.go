package inventory_test

// Library reports against the inventory datasets (T-0960, spec reports-2a AC-16, AC-17, AC-23). This file
// lives here because the harness that writes a realistic inventory (env, hUser, populate) does. The
// expected sets are computed in plain Go from the seed table, independently of the SQL, and are the
// ground truth the reports are compared with. The live-Samba LDAP comparison is a lab ticket (filed with
// this change).

import (
	"context"
	"fmt"
	"slices"
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

type libUser struct {
	sam      string
	disabled bool
	spn      bool
	logon    time.Duration // age of lastLogonTimestamp; 0: none recorded
	readMask inventory.InputsRead
	created  time.Duration // age
	expires  time.Duration // signed: + in the future, - in the past; 0: never
	locked   time.Duration // age of lockoutTime; 0: none
}

const allRead = inventory.ReadLockoutTime | inventory.ReadPwdLastSet | inventory.ReadAccountExpires | inventory.ReadLastLogonTimestamp

func day(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func libSeed() []libUser {
	us := []libUser{
		{sam: "plain-old", logon: day(100), created: day(300)},
		{sam: "recent-user", logon: day(10), created: day(300)},
		{sam: "never-old", created: day(150)},
		{sam: "never-new", created: day(5)},
		{sam: "disabled-old", disabled: true, logon: day(100), created: day(300)},
		{sam: "unread-logon", readMask: allRead &^ inventory.ReadLastLogonTimestamp, created: day(300)},
		{sam: "expired-acct", logon: day(5), created: day(300), expires: -day(5)},
		{sam: "long-expired", logon: day(5), created: day(300), expires: -day(60)},
		{sam: "soon-acct", logon: day(5), created: day(300), expires: day(7)},
		{sam: "later-acct", logon: day(5), created: day(300), expires: day(60)},
		{sam: "disabled-soon", disabled: true, logon: day(5), created: day(300), expires: day(3)},
		{sam: "locked-1", logon: day(5), created: day(300), locked: 5 * time.Minute},
		{sam: "unlocked-old", logon: day(5), created: day(300), locked: 2 * time.Hour},
	}
	for i := 1; i <= 6; i++ {
		us = append(us, libUser{sam: fmt.Sprintf("svc-%d", i), spn: true, logon: day(100), created: day(300)})
	}
	return us
}

func (u libUser) read() inventory.InputsRead {
	if u.readMask != 0 {
		return u.readMask
	}
	return allRead
}

// libExpect is the ground truth: the set of logon names each preset must list, and what it must hide.
func libExpect(us []libUser, preset string) (rows []string, hidden map[string]int) {
	hidden = map[string]int{}
	for _, u := range us {
		listed := false
		switch preset {
		case "usr-01/all":
			listed = true
		case "usr-01/enabled":
			listed = !u.disabled
		case "usr-01/disabled":
			listed = u.disabled
		case "usr-01/recently_created":
			listed = u.created <= day(30)
		case "usr-02/expired":
			listed = u.expires < 0
		case "usr-02/recently_expired":
			listed = u.expires < 0 && -u.expires <= day(30)
		case "usr-02/soon":
			if u.expires > 0 && u.expires <= day(14) {
				if u.disabled {
					hidden["disabled_accounts"]++
				} else {
					listed = true
				}
			}
		case "usr-02/never":
			listed = u.expires == 0
		case "usr-03/inactive":
			recorded := u.read()&inventory.ReadLastLogonTimestamp != 0
			stale := recorded && ((u.logon != 0 && u.logon > day(90)) || (u.logon == 0 && u.created > day(90)))
			if !u.disabled && stale {
				if u.spn {
					hidden["service_accounts"]++
				} else {
					listed = true
				}
			}
		case "usr-03/recent":
			listed = u.logon != 0 && u.logon <= day(30)
		case "usr-03/never":
			listed = u.read()&inventory.ReadLastLogonTimestamp != 0 && u.logon == 0
		case "usr-05/locked_out":
			listed = u.locked != 0 && u.locked <= 30*time.Minute
		}
		if listed {
			rows = append(rows, u.sam)
		}
	}
	slices.Sort(rows)
	return rows, hidden
}

type libResult struct {
	sams   []string
	rows   []map[report.ColumnID]report.Cell
	hidden map[string]int
}

func (e *env) runLib(t *testing.T, l *library.Library, id, preset string, rp report.RunParams, scope authz.ReadScope, now time.Time) (libResult, error) {
	t.Helper()
	d, ok := l.Definition(id, 0)
	if !ok {
		t.Fatalf("no definition %s", id)
	}
	q, err := report.Resolve(d.Def, preset, rp, d.Dataset)
	if err != nil {
		return libResult{}, err
	}
	cq, err := reportsql.Compile(q, d.SQL, scope, reportsql.Inputs{Now: now})
	if err != nil {
		t.Fatalf("Compile %s/%s: %v", id, preset, err)
	}
	res := libResult{hidden: map[string]int{}}
	err = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		_, err := reportsql.Exec(ctx, tx, cq, 500, func(_ context.Context, rows []report.Row) error {
			for _, row := range rows {
				if i := slices.Index(row.Hidden, true); i >= 0 {
					res.hidden[q.Hidden[i].ID]++
					continue
				}
				m := map[report.ColumnID]report.Cell{}
				for i, c := range q.Columns {
					m[c] = row.Cells[i]
				}
				res.rows = append(res.rows, m)
				res.sams = append(res.sams, string(m["sam_account_name"].DigestValue()))
			}
			return nil
		})
		return err
	})
	if err != nil {
		t.Fatalf("run %s/%s: %v", id, preset, err)
	}
	slices.Sort(res.sams)
	return res, nil
}

func libSetup(t *testing.T, s *storetest.Server, syncDays int) (*env, *library.Library, time.Time) {
	e := setup(t, s)
	reg := e.registry(t)
	l, err := library.Load(library.Shipped(), library.Options{Datasets: inventory.Datasets(), Registry: reg})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	e.hStructure(t, e.adA)
	now := hBase.Add(200 * 24 * time.Hour)
	var obs []inventory.Observation
	for i, u := range libSeed() {
		uac := int64(uacNormal)
		if u.disabled {
			uac |= 2
		}
		hu := hUser{guid: hGUID(1, i+1), sam: u.sam, rid: uint32(2000 + i), uac: &uac, read: u.read(), pwdLastSet: now.Add(-day(20)), spn: &u.spn}
		o := hu.obs()
		o.DisplayName = u.sam + " Display"
		en := !u.disabled
		o.Enabled = &en
		o.WhenCreated = now.Add(-u.created)
		if u.logon != 0 {
			o.LastLogonTimestamp = now.Add(-u.logon)
		}
		if u.expires != 0 {
			o.AccountExpires = now.Add(u.expires)
		}
		if u.locked != 0 {
			o.LockoutTime = now.Add(-u.locked)
		}
		obs = append(obs, o)
	}
	if _, err := e.populate(t, e.adA, hBase, obs...); err != nil {
		t.Fatalf("populate: %v", err)
	}
	e.policyTx(t, func(ctx context.Context, tx store.Tx, w inventory.PolicyWriter) error {
		return w.SetDomainPolicy(ctx, tx, e.adA, inventory.GUID(hDom),
			inventory.DomainPolicy{MaxPwdAge: days(42), LockoutDuration: mins(30), LogonSyncIntervalDays: &syncDays, PSOsReadAt: hBase}, hBase)
	})
	return e, l, now
}

// AC-23 (ground truth per preset) and AC-17 (six service accounts hidden, reasons on Show).
func Test_reports_library_batch1_rows_equal_ground_truth(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, l, now := libSetup(t, s, 14)
		scope := e.scopeNC(e.adA)
		seed := libSeed()
		for _, item := range l.List() {
			for _, p := range item.Def.Presets {
				key := string(item.Def.ID) + "/" + p.ID
				t.Run(key, func(t *testing.T) {
					res, err := e.runLib(t, l, string(item.Def.ID), p.ID, report.RunParams{}, scope, now)
					if err != nil {
						t.Fatal(err)
					}
					want, wantHidden := libExpect(seed, key)
					if !slices.Equal(res.sams, want) {
						t.Errorf("rows %v, want %v", res.sams, want)
					}
					for g, n := range wantHidden {
						if res.hidden[g] != n {
							t.Errorf("hidden %s = %d, want %d", g, res.hidden[g], n)
						}
					}
					for g, n := range res.hidden {
						if wantHidden[g] != n {
							t.Errorf("unexpected hidden %s = %d", g, n)
						}
					}
				})
			}
		}

		// AC-17: Show lists each of the six with the reason "servicePrincipalName set".
		shown, err := e.runLib(t, l, "usr-03", "inactive", report.RunParams{ShowHidden: []string{"service_accounts"}}, scope, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(shown.rows) != 7+1 || len(shown.hidden) != 0 { // plain-old, never-old and six svc
			t.Fatalf("shown %v hidden %v", shown.sams, shown.hidden)
		}
		reasons := 0
		for _, r := range shown.rows {
			if cellKey(r["probable_service_account_reason"]) == cellKey(report.EnumCell("spn_set")) {
				reasons++
			}
		}
		if reasons != 6 {
			t.Errorf("%d rows carry the reason spn_set, want 6", reasons)
		}

		// "Days since" is whole days from the replicated logon; the never-logged-on rows have none.
		inactive, _ := e.runLib(t, l, "usr-03", "inactive", report.RunParams{}, scope, now)
		for _, r := range inactive.rows {
			if string(r["sam_account_name"].DigestValue()) == "plain-old" && cellKey(r["days_since_logon"]) != cellKey(report.IntCell(100)) {
				t.Errorf("days since for plain-old: %v", r["days_since_logon"])
			}
		}

		// The unread logon input is Unknown, never "none recorded": it is in no logon report.
		for _, p := range []string{"inactive", "never"} {
			res, _ := e.runLib(t, l, "usr-03", p, report.RunParams{}, scope, now)
			if slices.Contains(res.sams, "unread-logon") {
				t.Errorf("unread-logon is listed by %s", p)
			}
		}
	})
}

// AC-16: a domain whose msDS-LogonTimeSyncInterval is 0 is disabled for the logon reports.
func Test_reports_library_sync_interval_zero_disables_the_domain(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e, l, now := libSetup(t, s, 0)
		scope := e.scopeNC(e.adA)
		for p, wantHidden := range map[string]int{"inactive": 8, "recent": 8, "never": 2} {
			res, err := e.runLib(t, l, "usr-03", p, report.RunParams{}, scope, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.rows) != 0 || res.hidden["sync_off"] != wantHidden {
				t.Errorf("%s: rows %v hidden %v, want 0 rows and sync_off=%d", p, res.sams, res.hidden, wantHidden)
			}
			if _, err := e.runLib(t, l, "usr-03", p, report.RunParams{ShowHidden: []string{"sync_off"}}, scope, now); err == nil {
				t.Errorf("%s: sync_off could be shown", p)
			}
		}
		// The other reports do not depend on the replicated logon and still run.
		res, _ := e.runLib(t, l, "usr-05", "locked_out", report.RunParams{}, scope, now)
		if !slices.Equal(res.sams, []string{"locked-1"}) {
			t.Errorf("usr-05 under sync 0: %v", res.sams)
		}
	})
}
