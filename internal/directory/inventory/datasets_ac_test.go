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
		cols := []report.ColumnID{"locked_out", "lockout_ends_at", "password_state", "password_expires_at", "days_to_password_expiry", "policy_source"}
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
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.RemovePSOApplies(ctx, tx, c, inventory.GUID(ghost), inventory.GUID(user), at.Add(40*time.Second))
		})

		// restore it, but without a precedence
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetPSO(ctx, tx, c, inventory.GUID(pso), inventory.GUID(hDom), inventory.PSO{MaxPwdAge: days(10), LockoutDuration: mins(10)}, at.Add(time.Minute))
		})
		want("no precedence", e.stateOf(t, reg, c, user, now, cols...), map[report.ColumnID]string{"locked_out": unkState, "password_state": unkState})
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetPSO(ctx, tx, c, inventory.GUID(pso), inventory.GUID(hDom), inventory.PSO{Precedence: i64(1), MaxPwdAge: days(10), LockoutDuration: mins(10)}, at.Add(2*time.Minute))
		})
		want("restored", e.stateOf(t, reg, c, user, now, cols...), map[report.ColumnID]string{"locked_out": "e:locked", "password_state": "e:expired"})

		// the PSO's own interval is not read
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetPSO(ctx, tx, c, inventory.GUID(pso), inventory.GUID(hDom), inventory.PSO{Precedence: i64(1)}, at.Add(3*time.Minute))
		})
		want("pso intervals unread", e.stateOf(t, reg, c, user, now, cols...), map[report.ColumnID]string{"locked_out": unkState, "password_state": unkState})

		// the domain's PSO set was never read
		e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
			return pw.SetDomainPolicy(ctx, tx, c, inventory.GUID(hDom), inventory.DomainPolicy{MaxPwdAge: days(42), LockoutDuration: mins(30)}, at.Add(4*time.Minute))
		})
		want("psos never read", e.stateOf(t, reg, c, user, now, cols...), map[report.ColumnID]string{"locked_out": unkState, "password_state": unkState,
			"policy_source": "s:Unknown (policy not resolved)"})

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
		for k, v := range map[report.ColumnID]string{"locked_out": unkState, "password_state": unkState, "policy_source": "s:Unknown (policy not resolved)"} {
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
