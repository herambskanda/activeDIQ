package sync_test

import (
	"reflect"
	"strings"
	"testing"

	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1129: the search identifiers reach the attribute bag as strings; what the entry did not carry is not in
// it (never read), and nothing outside the closed list does.
func Test_map_search_identifiers(t *testing.T) {
	m := mapper(dirsync.Config{})
	full := attrs(nil).classes("top", "person", "organizationalPerson", "user").
		with("givenName", txt("Priya")).with("sn", txt("Raman")).with("title", txt("Analyst")).
		with("department", txt("Finance")).with("physicalDeliveryOfficeName", txt("London")).
		with("mail", txt("priya@example.test")).with("mailNickname", txt("priya")).
		with("employeeID", txt("004211")).with("employeeNumber", txt("77")).
		with("proxyAddresses", txt("SMTP:priya@example.test"), txt("smtp:p@alias.test")).
		with("servicePrincipalName", txt("HTTP/web01.example.test")).
		with("sIDHistory", sidv(domSID(1105)))
	got := mustMap(t, m, entry(70, "CN=Priya Raman,OU=People,DC=lab,DC=test", gid(ouGUID), full))
	b := got.Observation.Attributes
	for k, want := range map[string]any{"givenName": "Priya", "sn": "Raman", "title": "Analyst", "department": "Finance",
		"physicalDeliveryOfficeName": "London", "mailNickname": "priya", "employeeID": "004211", "employeeNumber": "77"} {
		if b[k] != want {
			t.Errorf("%s = %v, want %v", k, b[k], want)
		}
	}
	if !reflect.DeepEqual(b["proxyAddresses"], []string{"SMTP:priya@example.test", "smtp:p@alias.test"}) {
		t.Errorf("proxyAddresses = %v", b["proxyAddresses"])
	}
	if !reflect.DeepEqual(b["servicePrincipalName"], []string{"HTTP/web01.example.test"}) {
		t.Errorf("servicePrincipalName = %v", b["servicePrincipalName"])
	}
	if !reflect.DeepEqual(b["sIDHistory"], []string{"S-1-5-21-1-2-3-1105"}) {
		t.Errorf("sIDHistory = %v", b["sIDHistory"])
	}

	// Never read: the attributes are absent from the bag, not empty strings. Present but empty: also absent.
	bare := mustMap(t, m, entry(71, "CN=Bare,OU=People,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("user").with("title", txt(""))))
	for _, k := range []string{"title", "department", "physicalDeliveryOfficeName", "givenName", "sn", "sIDHistory", "proxyAddresses"} {
		if _, ok := bare.Observation.Attributes[k]; ok {
			t.Errorf("%s is in the bag of an entry that did not carry a value", k)
		}
	}

	// A huge multi-value attribute cannot push the entry over the bag limit: the first values are kept.
	var spns []*connectorv1.AttributeValue
	for i := 0; i < 5000; i++ {
		spns = append(spns, txt("HOST/"+strings.Repeat("h", 200)))
	}
	big := mustMap(t, m, entry(72, "CN=Big,OU=People,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("computer").with("servicePrincipalName", spns...)))
	if n := len(big.Observation.Attributes["servicePrincipalName"].([]string)); n != 64 {
		t.Errorf("kept %d SPNs", n)
	}
}

// T-1129: the BitLocker recovery key material is never requested by the sync.
func Test_closed_list_has_no_recovery_attribute(t *testing.T) {
	for _, a := range dirsync.Attributes() {
		if strings.HasPrefix(strings.ToLower(a), "msfve-") {
			t.Errorf("%s is on the closed list", a)
		}
	}
}
