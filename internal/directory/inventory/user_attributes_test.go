package inventory_test

import (
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// userAttrCols are the columns T-1111 registers on inventory.users, with the attribute bag key each reads.
var userAttrCols = map[report.ColumnID]string{
	"mail": "mail", "employee_id": "employeeID", "department": "department", "title": "title", "company": "company",
	"telephone_number": "telephoneNumber", "mobile": "mobile", "description": "description", "manager": "manager",
	"logon_script": "scriptPath", "dialin_allowed": "msNPAllowDialin", "skype_enabled": "msRTCSIP-UserEnabled", "logon_hours": "logonHours",
}

// T-1111 AC1/AC2: a user with every attribute and one with none. Each registered column equals the synced
// value, a user without the attribute has an empty cell, and a photo is only a boolean.
func Test_user_attribute_columns_equal_the_synced_values(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		hours := strings.Repeat("1", 167) + "0"
		full := hUser{guid: hGUID(1, 1), sam: "full", rid: 1100, uac: i64(uacNormal), read: 15, pwdLastSet: hBase}.obs()
		full.Attributes = map[string]any{"mail": "full@example.test", "employeeID": "004211", "department": "Finance", "title": "Analyst",
			"company": "Example", "telephoneNumber": "+44 20 7946 0000", "mobile": "+44 7700 900000", "description": "d",
			"manager": "CN=Boss,OU=People,DC=example,DC=test", "scriptPath": "logon.bat", "msNPAllowDialin": true,
			"msRTCSIP-UserEnabled": false, "logonHours": hours, "hasThumbnailPhoto": true}
		none := hUser{guid: hGUID(1, 2), sam: "none", rid: 1101, uac: i64(uacNormal), read: 15, pwdLastSet: hBase}.obs()
		if _, err := e.populate(t, e.adA, hBase, full, none); err != nil {
			t.Fatal(err)
		}
		cols := []report.ColumnID{"sam_account_name", "logon_hours_restricted", "has_thumbnail_photo", "has_jpeg_photo"}
		for c := range userAttrCols {
			cols = append(cols, c)
		}
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: cols, scope: e.scopeNC(e.adA), now: hBase})
		f, n := res.rows[hGUID(1, 1)], res.rows[hGUID(1, 2)]
		if f == nil || n == nil {
			t.Fatalf("rows = %v", res.order)
		}
		for c, key := range userAttrCols {
			want := full.Attributes[key]
			var wantCell string
			switch v := want.(type) {
			case bool:
				wantCell = map[bool]string{true: "true", false: "false"}[v]
			default:
				wantCell = v.(string)
			}
			if got := string(f[c].DigestValue()); got != wantCell {
				t.Errorf("full.%s = %q, want %q", c, got, wantCell)
			}
			if got := f[c]; got.Tag() == "" {
				t.Errorf("full.%s has no tag", c)
			}
			if got := n[c]; string(got.DigestValue()) != "" {
				t.Errorf("none.%s = %q, want an empty cell", c, got.DigestValue())
			}
		}
		if got := string(f["logon_hours_restricted"].DigestValue()); got != "true" {
			t.Errorf("logon_hours_restricted = %q", got)
		}
		if got := string(n["logon_hours_restricted"].DigestValue()); got != "" {
			t.Errorf("a user with no logonHours is %q, want unknown", got)
		}
		for id, want := range map[report.ColumnID][2]string{"has_thumbnail_photo": {"true", "false"}, "has_jpeg_photo": {"false", "false"}} {
			if string(f[id].DigestValue()) != want[0] || string(n[id].DigestValue()) != want[1] {
				t.Errorf("%s = %q / %q, want %v", id, f[id].DigestValue(), n[id].DigestValue(), want)
			}
		}
	})
}

// T-1111 AC2/AC3: no registered column names a secret attribute, no column type can carry binary content, and
// the photo columns are booleans.
func Test_user_attribute_columns_carry_no_secret_or_binary(t *testing.T) {
	var users report.Dataset
	for _, d := range inventory.Datasets() {
		if d.ID == inventory.DatasetUsers {
			users = d
		}
	}
	byID := map[report.ColumnID]report.Column{}
	for _, c := range users.Columns {
		byID[c.ID] = c
		if j, ok := c.Source.(report.JSONAttr); ok && inventory.SecretKey(j.Key) {
			t.Errorf("column %s reads the secret key %s", c.ID, j.Key)
		}
		switch c.Type {
		case report.TypeText, report.TypeBool, report.TypeInt, report.TypeTime, report.TypeGUID, report.TypeEnum:
		default:
			t.Errorf("column %s has type %s", c.ID, c.Type)
		}
	}
	for _, id := range []report.ColumnID{"has_thumbnail_photo", "has_jpeg_photo", "dialin_allowed", "skype_enabled", "logon_hours_restricted"} {
		if byID[id].Type != report.TypeBool {
			t.Errorf("%s is %s, want bool", id, byID[id].Type)
		}
	}
	for _, id := range []report.ColumnID{"thumbnail_photo", "jpeg_photo", "thumbnailPhoto", "jpegPhoto"} {
		if _, ok := byID[id]; ok {
			t.Errorf("a column %s holds a photo", id)
		}
	}
	for id := range userAttrCols {
		if _, ok := byID[id]; !ok {
			t.Errorf("column %s is not registered", id)
		}
	}
}

// T-2216 AC1/AC2: a seeded unread attribute stores as not_observed, distinguishable from a row with no
// marker (NULL); the existing columns are unchanged.
func Test_user_read_state_columns(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		seen := hUser{guid: hGUID(1, 1), sam: "seen", rid: 1100, uac: i64(uacNormal), read: 15, pwdLastSet: hBase}.obs()
		seen.Attributes = map[string]any{"mail": "s@example.test", "attrRead": map[string]any{"mail": "observed", "scriptPath": "not_observed"}}
		old := hUser{guid: hGUID(1, 2), sam: "old", rid: 1101, uac: i64(uacNormal), read: 15, pwdLastSet: hBase}.obs()
		if _, err := e.populate(t, e.adA, hBase, seen, old); err != nil {
			t.Fatal(err)
		}
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: []report.ColumnID{"sam_account_name", "mail", "mail_read_state", "logon_script", "logon_script_read_state"}, scope: e.scopeNC(e.adA), now: hBase})
		a, b := res.rows[hGUID(1, 1)], res.rows[hGUID(1, 2)]
		if a == nil || b == nil {
			t.Fatalf("rows = %v", res.order)
		}
		for c, want := range map[report.ColumnID]string{"mail_read_state": "observed", "logon_script_read_state": "not_observed", "mail": "s@example.test", "logon_script": ""} {
			if got := string(a[c].DigestValue()); got != want {
				t.Errorf("seen.%s = %q, want %q", c, got, want)
			}
		}
		if got := string(b["mail_read_state"].DigestValue()); got != "" {
			t.Errorf("a row with no marker reads %q, want empty", got)
		}
	})
}
