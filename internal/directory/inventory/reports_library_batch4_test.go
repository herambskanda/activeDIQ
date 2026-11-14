package inventory_test

// Library batch 4: PWD-04, Users with Cannot Change Password (T-1107, reports-2-second-slice AC-S04, AC-S05).
// The seed carries the stored four-valued descriptor state (T-1472). The expected sets are written from the
// DACL states of the seed, not from the userAccountControl bit, which one seeded user has set with no ACEs.
// The live-Samba descriptor comparison needs the lab; this oracle is the same expectation.

import (
	"slices"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/directory/sd"
	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const uacPasswdCantChange = 0x40 // the flag AD ignores

func Test_reports_library_batch4_cannot_change_password_equals_dacl_truth(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		e := setup(t, srv)
		l, err := library.Load(library.Shipped(), library.Options{Datasets: inventory.Datasets(), Registry: e.registry(t)})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		e.hStructure(t, e.adA)
		at := hBase.Add(time.Minute)
		bitOnly := pwUser(3, "bit-only", sd.PasswordChangeNoDenyACE, at)
		uac := int64(uacNormal | uacPasswdCantChange)
		bitOnly = hUser{guid: hGUID(1, 3), sam: "bit-only", rid: 1103, uac: &uac, read: 15, pwdLastSet: hBase}.obs()
		bitOnly.PasswordChange, bitOnly.PasswordChangeAt = sd.PasswordChangeNoDenyACE, at
		obs := []inventory.Observation{
			pwUser(1, "both", sd.PasswordChangeBlocked, at),
			pwUser(2, "one", sd.PasswordChangeBlockedOneACE, at),
			bitOnly,
			pwUser(4, "none", sd.PasswordChangeNoDenyACE, at),
			pwUser(5, "unreadable", sd.PasswordChangeNotConfirmed, at),
			pwUser(6, "never-read", sd.PasswordChangeNotConfirmed, time.Time{}),
		}
		if _, err := e.populate(t, e.adA, hBase.Add(time.Minute), obs...); err != nil {
			t.Fatal(err)
		}
		rows, err := e.runB2(t, l, "pwd-04", "blocked", report.RunParams{}, e.scopeNC(e.adA), hBase.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		by := map[string]string{}
		for _, o := range obs {
			by[string(o.Object)] = o.SAMAccountName
		}
		var listed, notConfirmed []string
		for _, r := range rows {
			if slices.Contains(r.hidden, "not_confirmed") {
				notConfirmed = append(notConfirmed, by[r.key])
				continue
			}
			listed = append(listed, by[r.key])
			want := map[string]string{"both": "blocked", "one": "blocked_one_ace"}[by[r.key]]
			if !hasEnum(r.c["password_change_right"], want) {
				t.Errorf("%s shows %s, want %s", by[r.key], r.s("password_change_right"), want)
			}
		}
		slices.Sort(listed)
		slices.Sort(notConfirmed)
		if !slices.Equal(listed, []string{"both", "one"}) {
			t.Errorf("listed %v, want [both one]; the bit-only and the no-deny users are never listed", listed)
		}
		if !slices.Equal(notConfirmed, []string{"never-read", "unreadable"}) {
			t.Errorf("counted as not confirmed %v, want [never-read unreadable]", notConfirmed)
		}
	})
}
