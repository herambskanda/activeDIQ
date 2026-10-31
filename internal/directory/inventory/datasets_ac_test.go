package inventory_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/authz/authztest"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// stateOf runs the users dataset and returns the cell keys of cols for one user.
func (e *env) stateOf(t *testing.T, reg *reportsql.Registry, c inventory.ConnectionID, guid string, now time.Time, cols ...report.ColumnID) map[report.ColumnID]string {
	t.Helper()
	res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: cols, scope: e.scopeNC(c), now: now})
	row, ok := res.rows[strings.ToLower(guid)]
	if !ok {
		t.Fatalf("no row for %s", guid)
	}
	out := map[report.ColumnID]string{}
	for k, v := range row {
		out[k] = cellKey(v)
	}
	return out
}

func (e *env) observedAt(t *testing.T, guid string) (at time.Time) {
	t.Helper()
	err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT observed_at FROM public.directory_objects WHERE object_guid = $1::uuid`, guid).Scan(&at)
	})
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// AC-14: a PSO, or a group membership, changes with no write to the user; the next run shows the new
// policy.
func Test_policy_change_is_reflected_without_a_user_write(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		now := hBase.Add(100 * 24 * time.Hour)
		at := now.Add(-time.Hour)
		user, grp, pso := hGUID(1, 1), hGUID(2, 1), hGUID(3, 1)
		u := hUser{guid: user, sam: "bob", rid: 1200, uac: i64(uacNormal), read: 15, pwdLastSet: now.Add(-20 * 24 * time.Hour)}
		w := world8{dom: domPol{max: sec(42 * 86400), lock: sec(1800), psosRead: true}, users: []hUser{u}, groups: []grpM{{guid: grp, name: "G", rid: 2001}}}
		e.seed8(t, c, w, at)
		cols := []report.ColumnID{"password_state", "policy_source", "password_expires_at"}
		state := func() map[report.ColumnID]string { return e.stateOf(t, reg, c, user, now, cols...) }
		stamp := e.observedAt(t, user)
		step := at
		next := func() time.Time { step = step.Add(time.Minute); return step }
		check := func(label, pwd, src string) {
			t.Helper()
			got := state()
			if got["password_state"] != "e:"+pwd || got["policy_source"] != "s:"+src {
				t.Errorf("%s: state %v, want %s / %s", label, got, pwd, src)
			}
			if e.observedAt(t, user) != stamp {
				t.Errorf("%s: the user row was written", label)
			}
		}
		check("domain", "expires", "Domain policy")

		// the PSO appears and applies to the group, which has no member yet
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetPSO(ctx, tx, c, inventory.GUID(pso), inventory.GUID(hDom), inventory.PSO{Precedence: i64(1), MaxPwdAge: days(10), LockoutDuration: mins(5)}, next())
		})
		if _, err := e.populate(t, c, next(), hPSOObj(pso, "PSO-ten")); err != nil {
			t.Fatal(err)
		}
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetPSOApplies(ctx, tx, c, inventory.GUID(pso), inventory.GUID(grp), next())
		})
		check("pso applies to an empty group", "expires", "Domain policy")

		// the group gains the user: a membership change, no write to the user
		if _, err := e.populate(t, c, next(), hGroup(grp, "G", 2001, user)); err != nil {
			t.Fatal(err)
		}
		check("member added", "expired", "PSO-ten")

		// the PSO's age changes
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetPSO(ctx, tx, c, inventory.GUID(pso), inventory.GUID(hDom), inventory.PSO{Precedence: i64(1), MaxPwdAge: days(30), LockoutDuration: mins(5)}, next())
		})
		check("pso age lengthened", "expires", "PSO-ten")

		// the user leaves the group
		if _, err := e.populate(t, c, next(), hGroup(grp, "G", 2001)); err != nil {
			t.Fatal(err)
		}
		check("member removed", "expires", "Domain policy")

		// the member returns and the edge to the PSO is removed
		if _, err := e.populate(t, c, next(), hGroup(grp, "G", 2001, user)); err != nil {
			t.Fatal(err)
		}
		check("member again", "expires", "PSO-ten")
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.RemovePSOApplies(ctx, tx, c, inventory.GUID(pso), inventory.GUID(grp), next())
		})
		check("edge removed", "expires", "Domain policy")
	})
}

// AC-15: fault injection. Each missing input turns the dependent states into "unknown_input_missing"
// and the dependent columns into the unknown cell; nothing falls back to the domain policy.
func Test_missing_inputs_are_unknown(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		now := hBase.Add(100 * 24 * time.Hour)
		at := now.Add(-time.Hour)
		user, pso := hGUID(1, 1), hGUID(3, 1)
		u := hUser{guid: user, sam: "carol", rid: 1300, uac: i64(uacNormal), read: 15, pwdLastSet: now.Add(-20 * 24 * time.Hour), lockout: now.Add(-time.Minute)}
		w := world8{dom: domPol{max: sec(42 * 86400), lock: sec(1800), psosRead: true}, users: []hUser{u},
			psos: []psoM{{guid: pso, name: "PSO-x", prec: i64(1), max: sec(10 * 86400), lock: sec(600), stored: true, applies: []string{user}}}}
		e.seed8(t, c, w, at)
		cols := []report.ColumnID{"locked_out", "lockout_ends_at", "password_state", "password_expires_at", "days_to_password_expiry", "policy_source",
			"locked_out_reason", "password_state_reason", "account_expired_reason"}
		// reasons: the cause that comes with each unknown state, "none" when the state is known
		why := func(lock, pwd string) map[report.ColumnID]string {
			return map[report.ColumnID]string{"locked_out_reason": "e:" + lock, "password_state_reason": "e:" + pwd, "account_expired_reason": "e:none"}
		}
		with := func(m, extra map[report.ColumnID]string) map[report.ColumnID]string {
			for k, v := range extra {
				m[k] = v
			}
			return m
		}
		unknown := cellKey(report.Unknown())
		unkState := cellKey(report.Unknown())
		want := func(label string, got map[report.ColumnID]string, exp map[report.ColumnID]string) {
			t.Helper()
			for k, v := range exp {
				if got[k] != v {
					t.Errorf("%s: %s = %s, want %s", label, k, got[k], v)
				}
			}
		}
		base := e.stateOf(t, reg, c, user, now, cols...)
		want("resolved", base, map[report.ColumnID]string{"locked_out": "e:locked", "password_state": "e:expired", "policy_source": "s:PSO-x"})
		want("resolved reasons", base, why("none", "none"))

		// a second PSO applies to the user and its row was never read: the user's policy is unresolved
		// (it could be the winner), never quietly the first PSO or the domain
		ghost := hGUID(3, 2)
		if _, err := e.populate(t, c, at.Add(30*time.Second), hPSOObj(ghost, "PSO-ghost")); err != nil {
			t.Fatal(err)
		}
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetPSOApplies(ctx, tx, c, inventory.GUID(ghost), inventory.GUID(user), at.Add(30*time.Second))
		})
		want("pso row absent", e.stateOf(t, reg, c, user, now, cols...), map[report.ColumnID]string{
			"locked_out": unkState, "lockout_ends_at": unknown, "password_state": unkState, "password_expires_at": unknown,
			"days_to_password_expiry": unknown, "policy_source": "s:Unknown (policy not resolved)"})
		want("pso row absent: reasons", e.stateOf(t, reg, c, user, now, cols...), why("pso_not_read", "pso_not_read"))
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.RemovePSOApplies(ctx, tx, c, inventory.GUID(ghost), inventory.GUID(user), at.Add(40*time.Second))
		})

		// restore it, but without a precedence
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetPSO(ctx, tx, c, inventory.GUID(pso), inventory.GUID(hDom), inventory.PSO{MaxPwdAge: days(10), LockoutDuration: mins(10)}, at.Add(time.Minute))
		})
		want("no precedence", e.stateOf(t, reg, c, user, now, cols...), map[report.ColumnID]string{"locked_out": unkState, "password_state": unkState})
		want("no precedence: reasons", e.stateOf(t, reg, c, user, now, cols...), why("pso_precedence_not_read", "pso_precedence_not_read"))
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetPSO(ctx, tx, c, inventory.GUID(pso), inventory.GUID(hDom), inventory.PSO{Precedence: i64(1), MaxPwdAge: days(10), LockoutDuration: mins(10)}, at.Add(2*time.Minute))
		})
		want("restored", e.stateOf(t, reg, c, user, now, cols...), map[report.ColumnID]string{"locked_out": "e:locked", "password_state": "e:expired"})

		// the PSO's own interval is not read
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetPSO(ctx, tx, c, inventory.GUID(pso), inventory.GUID(hDom), inventory.PSO{Precedence: i64(1)}, at.Add(3*time.Minute))
		})
		want("pso intervals unread", e.stateOf(t, reg, c, user, now, cols...), with(why("pso_interval_not_read", "pso_interval_not_read"),
			map[report.ColumnID]string{"locked_out": unkState, "password_state": unkState}))

		// the domain's PSO set was never read
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetDomainPolicy(ctx, tx, c, inventory.GUID(hDom), inventory.DomainPolicy{MaxPwdAge: days(42), LockoutDuration: mins(30)}, at.Add(4*time.Minute))
		})
		want("psos never read", e.stateOf(t, reg, c, user, now, cols...), with(why("pso_set_not_read", "pso_set_not_read"), map[report.ColumnID]string{
			"locked_out": unkState, "password_state": unkState, "policy_source": "s:Unknown (policy not resolved)"}))

		// a user of a naming context with no domain policy row at all
		nc2, u2 := hGUID(9, 1), hGUID(1, 2)
		other := hUser{guid: u2, sam: "dave", rid: 1301, uac: i64(uacNormal), read: 15, pwdLastSet: now.Add(-time.Hour), lockout: now.Add(-time.Minute), parent: nc2}
		o2 := other.obs()
		o2.NC, o2.Ancestry = inventory.GUID(nc2), []inventory.GUID{inventory.GUID(nc2)}
		head := inventory.Observation{Object: inventory.GUID(nc2), NC: inventory.GUID(nc2), Kind: inventory.KindOther, Class: "domainDNS", State: inventory.ObjLive}
		if _, err := e.populate(t, c, at.Add(time.Minute), head, o2); err != nil {
			t.Fatal(err)
		}
		both := authztest.ReadScope(authz.ScopeGrant{Include: []authz.ScopeTerm{
			{Kind: authz.TermNamingContext, Connection: rpID(string(c)), Root: rpID(hDom)},
			{Kind: authz.TermNamingContext, Connection: rpID(string(c)), Root: rpID(nc2)}}})
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: cols, scope: both, now: now})
		for k, v := range with(why("domain_policy_not_read", "domain_policy_not_read"), map[report.ColumnID]string{
			"locked_out": unkState, "password_state": unkState, "policy_source": "s:Unknown (policy not resolved)"}) {
			if got := cellKey(res.rows[strings.ToLower(u2)][k]); got != v {
				t.Errorf("no domain row: %s = %s, want %s", k, got, v)
			}
		}

		// the lockout bit is unset: the same row, re-observed without it
		u.read &^= inventory.ReadLockoutTime
		u.lockout = time.Time{}
		if _, err := e.populate(t, c, at.Add(5*time.Minute), u.obs()); err != nil {
			t.Fatal(err)
		}
		e.setDom8(t, c, w.dom, at.Add(6*time.Minute))
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.RemovePSOApplies(ctx, tx, c, inventory.GUID(pso), inventory.GUID(user), at.Add(7*time.Minute))
		})
		got := e.stateOf(t, reg, c, user, now, cols...)
		want("lockout not read", got, map[report.ColumnID]string{"locked_out": unkState, "lockout_ends_at": unknown, "password_state": "e:expires", "policy_source": "s:Domain policy"})
		want("lockout not read: reasons", got, why("lockout_time_not_read", "none"))

		// pwdLastSet unread
		u.read &^= inventory.ReadPwdLastSet
		u.pwdLastSet = time.Time{}
		if _, err := e.populate(t, c, at.Add(8*time.Minute), u.obs()); err != nil {
			t.Fatal(err)
		}
		want("pwdLastSet not read", e.stateOf(t, reg, c, user, now, cols...), with(why("lockout_time_not_read", "pwd_last_set_not_read"),
			map[report.ColumnID]string{"password_state": unkState, "password_expires_at": unknown, "days_to_password_expiry": unknown}))

		// accountExpires unread
		u.read &^= inventory.ReadAccountExpires
		if _, err := e.populate(t, c, at.Add(9*time.Minute), u.obs()); err != nil {
			t.Fatal(err)
		}
		want("accountExpires not read", e.stateOf(t, reg, c, user, now, "account_expired", "account_expired_reason"),
			map[report.ColumnID]string{"account_expired": unkState, "account_expired_reason": "e:account_expires_not_read"})

		// the domain's own interval is not read
		u.read = 15
		u.lockout, u.pwdLastSet = now.Add(-time.Minute), now.Add(-20*24*time.Hour)
		if _, err := e.populate(t, c, at.Add(10*time.Minute), u.obs()); err != nil {
			t.Fatal(err)
		}
		e.setDom8(t, c, domPol{psosRead: true}, at.Add(11*time.Minute))
		want("domain intervals not read", e.stateOf(t, reg, c, user, now, cols...), with(why("domain_policy_not_read", "domain_policy_not_read"),
			map[report.ColumnID]string{"locked_out": unkState, "password_state": unkState, "policy_source": "s:Domain policy"}))
	})
}

// AC-49: 37 of the 40 lab users are locked out; filter, sort and page; the count is 37 and the
// compiled SQL carries the predicate with bound arguments.
func Test_locked_out_filter_count_and_page(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		now := hBase.Add(100 * 24 * time.Hour)
		at := now.Add(-time.Hour)
		var obs []inventory.Observation
		locked := map[string]bool{}
		for i := 0; i < 150; i++ {
			u := hUser{guid: hGUID(1, i+1), sam: fmt.Sprintf("user%03d", i), rid: uint32(2000 + i), uac: i64(uacNormal), read: 15, pwdLastSet: now.Add(-24 * time.Hour)}
			if i < 37 {
				u.lockout = now.Add(-time.Duration(i+1) * time.Minute)
				locked[strings.ToLower(u.guid)] = true
			}
			obs = append(obs, u.obs())
		}
		if _, err := e.populate(t, c, at, obs...); err != nil {
			t.Fatal(err)
		}
		// forever: a lockout that nothing lifts, so the 37 stay locked whatever their age
		e.setDom8(t, c, domPol{max: sec(42 * 86400), lock: sec(0), psosRead: true}, at)
		cols := []report.ColumnID{"sam_account_name", "locked_out"}
		where := report.Cmp{Column: "locked_out", Op: report.OpEq, Value: report.EnumV("locked")}
		sorted := []report.SortKey{{Column: "sam_account_name", Dir: report.Desc}}
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: cols, where: where, sort: sorted, scope: e.scopeNC(c), now: now, limit: 25})
		if res.count != 37 {
			t.Fatalf("count = %d, want 37", res.count)
		}
		if len(res.order) != 25 {
			t.Fatalf("page = %d rows, want 25", len(res.order))
		}
		for i, k := range res.order {
			if !locked[k] {
				t.Errorf("row %d (%s) is not a locked user", i, k)
			}
			if want := fmt.Sprintf("user%03d", 36-i); string(res.rows[k]["sam_account_name"].DigestValue()) != want {
				t.Errorf("row %d = %s, want %s", i, res.rows[k]["sam_account_name"].DigestValue(), want)
			}
		}

		// the predicate is in the SQL, the values are bound
		all := strings.Join(res.sql, "\n")
		for _, lit := range []string{now.Format("2006-01-02"), "2026-"} {
			if strings.Contains(all, lit) {
				t.Errorf("the compiled SQL carries the literal %q", lit)
			}
		}
		if !strings.Contains(all, "lockout_time") || !strings.Contains(all, "inputs_read") {
			t.Errorf("the predicate is not evaluated in the query")
		}
		var bound []string
		for _, as := range res.args {
			for _, a := range as {
				bound = append(bound, fmt.Sprint(a))
			}
		}
		joined := strings.Join(bound, "|")
		if !strings.Contains(joined, "locked") || !strings.Contains(joined, "2026-") {
			t.Errorf("the filter value and now are not bound arguments: %v", bound)
		}
	})
}

// The service-account signal (spec §6.7) and the computer activity rule (CMP-02).
func Test_service_account_signal_and_computer_activity(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		c := e.adA
		e.hStructure(t, c)
		now := hBase.Add(100 * 24 * time.Hour)
		at := now.Add(-time.Hour)
		yes, no := true, false
		mk := func(k int, sam string, rid uint32, spn *bool) inventory.Observation {
			return hUser{guid: hGUID(1, k), sam: sam, rid: rid, uac: i64(uacNormal), read: 15, spn: spn}.obs()
		}
		unread := mk(4, "spn-unread", 1104, nil)
		unread.InputsRead = 0
		unread.HasSPN = nil
		if _, err := e.populate(t, c, at, mk(1, "svc-sql", 1101, &yes), mk(2, "plain", 1102, &no), mk(3, "krbtgt", 502, &yes), unread); err != nil {
			t.Fatal(err)
		}
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: []report.ColumnID{"sam_account_name", "probable_service_account", "probable_service_account_reason"}, scope: e.scopeNC(c), now: now})
		for sam, want := range map[string][2]string{
			"svc-sql": {"b:true", "e:spn_set"}, "plain": {"b:false", "e:none"}, "krbtgt": {"b:false", "e:none"}, "spn-unread": {"a:", "a:"}} {
			found := false
			for _, r := range res.rows {
				if string(r["sam_account_name"].DigestValue()) != sam {
					continue
				}
				found = true
				if got := [2]string{cellKey(r["probable_service_account"]), cellKey(r["probable_service_account_reason"])}; got != want {
					t.Errorf("%s: %v, want %v", sam, got, want)
				}
			}
			if !found {
				t.Errorf("%s: no row", sam)
			}
		}

		// computers: the later of the replicated logon and pwdLastSet, whenCreated when neither is set
		comp := func(k int, sam string, read inventory.InputsRead, logon, pwd time.Time) inventory.Observation {
			o := hUser{guid: hGUID(4, k), sam: sam, rid: uint32(3000 + k), uac: i64(uacWks), read: read, pwdLastSet: pwd, kind: inventory.KindComputer, class: "computer"}.obs()
			o.LastLogonTimestamp = logon
			return o
		}
		d := func(n int) time.Time { return now.Add(-time.Duration(n) * 24 * time.Hour) }
		if _, err := e.populate(t, c, at,
			comp(1, "logon-later", 15, d(5), d(30)), comp(2, "pwd-later", 15, d(40), d(3)), comp(3, "neither", 15, time.Time{}, time.Time{}),
			comp(4, "unread", 1|4, time.Time{}, time.Time{}),
			comp(5, "logon-unread", 1|2|4, time.Time{}, d(3)), comp(6, "pwd-unread", 1|4|8, d(3), time.Time{})); err != nil {
			t.Fatal(err)
		}
		cres := e.run(t, reg, hQuery{dataset: inventory.DatasetComputers, cols: []report.ColumnID{"sam_account_name", "last_activity", "activity_source", "activity_source_reason"}, scope: e.scopeNC(c), now: now})
		created := report.TimeCell(hBase.Add(-24 * time.Hour))
		for sam, want := range map[string][3]string{
			"logon-later": {cellKey(report.TimeCell(d(5))), "e:logon", "e:none"}, "pwd-later": {cellKey(report.TimeCell(d(3))), "e:password_set", "e:none"},
			"neither":      {cellKey(created), "e:created", "e:none"},
			"unread":       {cellKey(report.Unknown()), cellKey(report.Unknown()), "e:activity_inputs_not_read"},
			"logon-unread": {cellKey(report.Unknown()), cellKey(report.Unknown()), "e:last_logon_not_read"},
			"pwd-unread":   {cellKey(report.Unknown()), cellKey(report.Unknown()), "e:pwd_last_set_not_read"}} {
			found := false
			for _, r := range cres.rows {
				if string(r["sam_account_name"].DigestValue()) != sam {
					continue
				}
				found = true
				if got := [3]string{cellKey(r["last_activity"]), cellKey(r["activity_source"]), cellKey(r["activity_source_reason"])}; got != want {
					t.Errorf("%s: %v, want %v", sam, got, want)
				}
			}
			if !found {
				t.Errorf("%s: no row", sam)
			}
		}
	})
}
