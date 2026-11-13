package inventory_test

import (
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// pwUser builds a user observation carrying a classified Cannot Change Password state.
func pwUser(i int, sam string, st sd.PasswordChange, at time.Time) inventory.Observation {
	o := hUser{guid: hGUID(1, i), sam: sam, rid: uint32(1100 + i), uac: i64(uacNormal), read: 15, pwdLastSet: hBase}.obs()
	o.PasswordChange, o.PasswordChangeAt = st, at
	return o
}

func (e *env) pwRead(t *testing.T) map[string]map[report.ColumnID]report.Cell {
	t.Helper()
	cols := []report.ColumnID{"sam_account_name", "password_change_right", "descriptor_as_of"}
	return e.run(t, e.registry(t), hQuery{dataset: inventory.DatasetUsers, cols: cols, scope: e.scopeNC(e.adA), now: hBase.Add(time.Hour)}).rows
}

func hasEnum(c report.Cell, v string) bool { return strings.HasSuffix(cellKey(c), ":"+v) }

// AC1/AC2: all four values read back as stored; an unreadable descriptor (typed error, recorded as
// NotConfirmed with a time) and a row never read are Not confirmed, never No deny ACE.
func Test_inventory_users_password_change_state(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		at := hBase.Add(time.Minute)
		never := pwUser(5, "never-read", sd.PasswordChangeNotConfirmed, time.Time{})
		obs := []inventory.Observation{
			pwUser(1, "both", sd.PasswordChangeBlocked, at), pwUser(2, "one", sd.PasswordChangeBlockedOneACE, at),
			pwUser(3, "none", sd.PasswordChangeNoDenyACE, at), pwUser(4, "unreadable", sd.PasswordChangeNotConfirmed, at), never,
		}
		if _, err := e.populate(t, e.adA, hBase.Add(time.Minute), obs...); err != nil {
			t.Fatal(err)
		}
		rows := e.pwRead(t)
		for i, want := range map[int]string{1: "blocked", 2: "blocked_one_ace", 3: "no_deny_ace", 4: "not_confirmed", 5: "not_confirmed"} {
			r := rows[hGUID(1, i)]
			if !hasEnum(r["password_change_right"], want) {
				t.Errorf("user %d: %s, want %s", i, cellKey(r["password_change_right"]), want)
			}
		}
		if got := cellKey(rows[hGUID(1, 5)]["descriptor_as_of"]); strings.Contains(got, "2026") {
			t.Errorf("never-read user has an as-of: %s", got)
		}
		if got := cellKey(rows[hGUID(1, 1)]["descriptor_as_of"]); !strings.Contains(got, "2026-05-01") {
			t.Errorf("as-of = %s", got)
		}
	})
}

// AC3: the next pass follows a changed descriptor and advances the as-of.
func Test_inventory_users_password_change_follows_next_pass(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		t1, t2 := hBase.Add(time.Minute), hBase.Add(2*time.Hour)
		if _, err := e.populate(t, e.adA, t1, pwUser(1, "u", sd.PasswordChangeNoDenyACE, t1)); err != nil {
			t.Fatal(err)
		}
		before := cellKey(e.pwRead(t)[hGUID(1, 1)]["descriptor_as_of"])
		if _, err := e.populate(t, e.adA, t2, pwUser(1, "u", sd.PasswordChangeBlocked, t2)); err != nil {
			t.Fatal(err)
		}
		r := e.pwRead(t)[hGUID(1, 1)]
		if !hasEnum(r["password_change_right"], "blocked") || cellKey(r["descriptor_as_of"]) == before {
			t.Errorf("state %s as-of %s (was %s)", cellKey(r["password_change_right"]), cellKey(r["descriptor_as_of"]), before)
		}
	})
}

func Test_inventory_password_change_observation_is_validated(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		e.hStructure(t, e.adA)
		noTime := pwUser(1, "a", sd.PasswordChangeBlocked, time.Time{})
		group := hGroup(hGUID(2, 1), "g", 2000)
		group.PasswordChange, group.PasswordChangeAt = sd.PasswordChangeBlocked, hBase
		outOfRange := pwUser(2, "b", sd.PasswordChange(9), hBase)
		for name, o := range map[string]inventory.Observation{"state without time": noTime, "on a group": group, "out of range": outOfRange} {
			if _, err := e.populate(t, e.adA, hBase.Add(time.Minute), o); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})
}
