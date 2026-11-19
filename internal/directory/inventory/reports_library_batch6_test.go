package inventory_test

// Library batch 6: user-attribute reports USR-07, USR-08, USR-09 and USR-11 (T-1112, reports-2-second-slice
// §5). The seed is one user per attribute state; the expected sets are written from the seed (which user was
// given which attribute), not from the SQL. The live-Samba comparison needs the lab (see T-1112 note).

import (
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func Test_reports_library_batch6_user_attributes_equal_seed_truth(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, srv *storetest.Server) {
		e := setup(t, srv)
		l, err := library.Load(library.Shipped(), library.Options{Datasets: inventory.Datasets(), Registry: e.registry(t)})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		e.hStructure(t, e.adA)
		restricted := strings.Repeat("1", 167) + "0"
		open := strings.Repeat("1", 168)
		type seed struct {
			sam  string
			uac  int64
			attr map[string]any
		}
		seeds := []seed{
			{"full", uacNormal, map[string]any{"msNPAllowDialin": true, "msRTCSIP-UserEnabled": true, "scriptPath": "l.bat", "hasThumbnailPhoto": true,
				"logonHours": restricted, "mail": "a@x.test", "employeeID": "1", "department": "d", "title": "t", "company": "c",
				"telephoneNumber": "1", "mobile": "2", "description": "x", "manager": "CN=B,DC=x"}},
			{"denied", uacNormal | 0x40000, map[string]any{"msNPAllowDialin": false, "msRTCSIP-UserEnabled": false, "hasJpegPhoto": true, "logonHours": open}},
			{"bare", uacNormal, map[string]any{}},
			{"unsynced", uacNormal, map[string]any{}}, // no read marker: not yet resynced, so never listed as lacking an attribute (T-2216)
		}
		marked := []string{"mail", "employeeID", "department", "title", "company", "telephoneNumber", "mobile", "description", "manager",
			"scriptPath", "msNPAllowDialin", "msRTCSIP-UserEnabled", "logonHours", "thumbnailPhoto", "jpegPhoto"}
		withMarker := func(attr map[string]any) map[string]any {
			rd := map[string]any{}
			for _, k := range marked {
				rd[k] = "not_observed"
			}
			for k := range attr {
				switch k {
				case "hasThumbnailPhoto":
					rd["thumbnailPhoto"] = "observed"
				case "hasJpegPhoto":
					rd["jpegPhoto"] = "observed"
				default:
					rd[k] = "observed"
				}
			}
			attr["attrRead"] = rd
			return attr
		}
		var batch []inventory.Observation
		for i, s := range seeds {
			o := hUser{guid: hGUID(1, i+1), sam: s.sam, rid: uint32(1100 + i), uac: i64(s.uac), read: 15, pwdLastSet: hBase}.obs()
			o.Attributes = s.attr
			if s.sam != "unsynced" {
				o.Attributes = withMarker(s.attr)
			}
			batch = append(batch, o)
		}
		if _, err := e.populate(t, e.adA, hBase, batch...); err != nil {
			t.Fatal(err)
		}
		want := map[string]map[string][]string{
			"usr-07": {"dialin_allow": {"full"}, "dialin_deny": {"denied"}, "smartcard": {"denied"}, "logon_hours": {"full"}},
			"usr-08": {"photo_with": {"denied", "full"}, "photo_without": {"bare"}, "script_with": {"full"}, "script_without": {"bare", "denied"}},
			"usr-09": {"enabled": {"full"}, "disabled": {"denied"}},
			"usr-11": {"empty_mail": {"bare", "denied"}, "empty_employee_id": {"bare", "denied"}, "empty_department": {"bare", "denied"}, "empty_title": {"bare", "denied"},
				"empty_company": {"bare", "denied"}, "empty_telephone_number": {"bare", "denied"}, "empty_mobile": {"bare", "denied"}, "empty_description": {"bare", "denied"},
				"empty_manager": {"bare", "denied"}},
		}
		for id, presets := range want {
			for preset, sams := range presets {
				rows, err := e.runB2(t, l, id, preset, report.RunParams{Columns: []report.ColumnID{"sam_account_name"}}, e.scopeNC(e.adA), hBase)
				if err != nil {
					t.Fatalf("%s/%s: %v", id, preset, err)
				}
				var got []string
				for _, r := range rows {
					if len(r.hidden) == 0 { // a hidden row is counted in the header, not listed
						got = append(got, r.s("sam_account_name"))
					}
				}
				slices.Sort(got)
				w := slices.Clone(sams)
				slices.Sort(w)
				if !slices.Equal(got, w) {
					t.Errorf("%s/%s: rows %v, want %v", id, preset, got, w)
				}
			}
		}
		// Dial-in Deny counts the NPS-controlled users (no value) in the header and never lists them.
		rows, err := e.runB2(t, l, "usr-07", "dialin_deny", report.RunParams{Columns: []report.ColumnID{"sam_account_name"}}, e.scopeNC(e.adA), hBase)
		if err != nil {
			t.Fatal(err)
		}
		var nps []string
		for _, r := range rows {
			if slices.Contains(r.hidden, "nps_controlled") {
				nps = append(nps, r.s("sam_account_name"))
			}
		}
		if !slices.Equal(nps, []string{"bare"}) {
			t.Errorf("NPS-controlled users counted in the header = %v, want [bare]", nps)
		}
	})
}
