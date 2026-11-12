package sync_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/secretattr"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"github.com/skenzeriq/activediq/internal/platform/report"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// AC3: no member of the closed list is a secret, or an attribute the ScopedSearch handler refuses.
// This fails the build if a secret name is added to the list.
func Test_closed_list_holds_no_secret(t *testing.T) {
	refused := []string{"nTSecurityDescriptor"} // internal/connector/read/search.go: held for T-0118
	for _, a := range dirsync.Attributes() {
		for _, s := range append(secretattr.Static(), refused...) {
			if strings.EqualFold(a, s) {
				t.Errorf("closed list carries %q", a)
			}
		}
		if inventory.SecretKey(a) {
			t.Errorf("the inventory writer would refuse %q as a secret key", a)
		}
		if a == "*" || a == "+" || strings.ContainsAny(a, ";=") {
			t.Errorf("%q is not a plain attribute name", a)
		}
	}
	if !slices.Contains(dirsync.Attributes(), "objectClass") {
		t.Error("objectClass is the kind")
	}
}

// The list covers what the inventory datasets read from the attribute bag today (T-0958, T-0961, T-0962).
func Test_closed_list_covers_the_datasets(t *testing.T) {
	need := map[string]bool{
		// read inside SQL fragments of the datasets (datasets_sql.go, datasets_groups.go)
		"groupType": true, "managedBy": true, "msDS-AllowedToDelegateTo": true, "operatingSystem": true,
		"userAccountControl": true, "primaryGroupID": true, "lockoutTime": true, "pwdLastSet": true, "accountExpires": true,
		"lastLogonTimestamp": true, "servicePrincipalName": true, "member": true, "whenCreated": true,
		// search keys (searchkeys.go)
		"sAMAccountName": true, "userPrincipalName": true, "displayName": true, "mail": true, "dNSHostName": true,
		"objectSid": true, "mS-DS-ConsistencyGuid": true,
	}
	for _, ds := range inventory.Datasets() {
		for _, c := range ds.Columns {
			if j, ok := c.Source.(report.JSONAttr); ok {
				need[j.Key] = true
			}
		}
	}
	have := map[string]bool{}
	for _, a := range dirsync.Attributes() {
		have[strings.ToLower(a)] = true
	}
	for a := range need {
		if !have[strings.ToLower(a)] {
			t.Errorf("a dataset reads %q but the sync does not request it", a)
		}
	}
}

const secretValue = "S3cr3t-Value-That-Must-Not-Appear"

// AC3: an entry that nevertheless carries secret attributes maps to an Observation with no trace of the
// name or the value in any field, in Attributes, or in an error.
func Test_hostile_entry_leaves_no_trace(t *testing.T) {
	hostile := attrs(nil).classes("top", "person", "organizationalPerson", "user").
		with("sAMAccountName", txt("praman")).with("userAccountControl", i32(0x200))
	names := append(secretattr.Static(), "nTSecurityDescriptor", "customerFlagged", "unicodepwd", "UNICODEPWD", "ms-mcs-admpwd;range=0-*")
	for _, n := range names {
		hostile = hostile.with(n, txt(secretValue), &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Octets{Octets: []byte(secretValue)}})
	}
	e := entry(60, "CN=U,OU=Staff,DC=lab,DC=test", gid(ouGUID), hostile)

	for _, m := range []*dirsync.Mapper{mapper(dirsync.Config{}), mapper(dirsync.Config{SchemaSecrets: []string{"customerFlagged"}})} {
		got, err := m.Map(e)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(got.Observation)
		dump := string(b) + fmt.Sprintf("%#v %+v", got, got)
		for _, bad := range append(names, secretValue, fmt.Sprint([]byte(secretValue))) {
			if strings.Contains(strings.ToLower(dump), strings.ToLower(bad)) {
				t.Errorf("the observation mentions %q", bad)
			}
		}
		if len(got.Observation.Attributes) != 0 {
			t.Errorf("Attributes = %v", got.Observation.Attributes)
		}
	}
}

// A malformed secret does not even get looked at: it cannot make an entry fail, or name itself in the error.
func Test_malformed_unrequested_attribute_is_not_examined(t *testing.T) {
	e := entry(61, "CN=U,OU=Staff,DC=lab,DC=test", gid(ouGUID),
		attrs(nil).classes("top", "user").with("unicodePwd", sidv(domSID(1)), sidv(domSID(2))).with("objectSid", sidv(domSID(5))))
	if _, err := mapper(dirsync.Config{}).Map(e); err != nil {
		t.Fatalf("Map: %v", err)
	}
}

func Test_request_validation(t *testing.T) {
	nc := inventory.GUID(gtext(domainNC))
	for _, bad := range []string{"unicodePwd", "UNICODEPWD", "ms-Mcs-AdmPwd", "nTSecurityDescriptor", "supplementalCredentials", "*", "+", "thumbnailPhoto", "objectGUID"} {
		_, err := dirsync.NewMapper(dirsync.Config{NC: nc, Requested: []string{"objectClass", bad}})
		if !errors.Is(err, dirsync.ErrNotAllowed) {
			t.Errorf("Requested %q: err = %v, want ErrNotAllowed", bad, err)
		}
	}
	for _, c := range []dirsync.Config{{}, {NC: "not-a-guid"}, {NC: "00000000-0000-0000-0000-000000000000"}, {NC: inventory.GUID(strings.ToUpper(gtext(0xabc)))},
		{NC: nc, Requested: []string{"mail"}}} {
		if _, err := dirsync.NewMapper(c); !errors.Is(err, dirsync.ErrConfig) {
			t.Errorf("config %+v: err = %v, want ErrConfig", c, err)
		}
	}
}

// A schema-flagged attribute is dropped from the request instead of being asked for.
func Test_schema_secrets_leave_the_request(t *testing.T) {
	m := mapper(dirsync.Config{SchemaSecrets: []string{"DESCRIPTION", "mail"}})
	got := m.Attributes()
	for _, a := range got {
		if strings.EqualFold(a, "description") || strings.EqualFold(a, "mail") {
			t.Errorf("%q is requested although this schema flags it", a)
		}
	}
	if len(got) != len(dirsync.Attributes())-2 {
		t.Errorf("request has %d attributes, want %d", len(got), len(dirsync.Attributes())-2)
	}
	e := entry(62, "CN=U,OU=Staff,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("top", "user").with("mail", txt("a@b.test")).with("description", txt("x")))
	if o := mustMap(t, m, e).Observation; len(o.Attributes) != 0 {
		t.Errorf("Attributes = %v", o.Attributes)
	}
}
