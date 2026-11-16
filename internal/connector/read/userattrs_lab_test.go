//go:build lab

package read_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1111 AC1/AC2: a lab user with every user-attribute-report attribute and one with none, read through
// the real ScopedSearch handler and mapped. Each attribute in the bag equals an administrator's own LDAP
// read of it; a photo is only a flag; the absent user has none of them. msRTCSIP-UserEnabled needs the
// Lync/Skype schema, which Samba cannot add: that attribute is covered by the mapper test and a Windows lab
// ticket (see the ticket note).
//
//	make lab-up && go test -tags lab ./internal/connector/read -run TestLabUserAttributes
func TestLabUserAttributes(t *testing.T) {
	l := newSearchLab(t)
	ou := "OU=userattrs-" + l.stamp + "," + labDom
	l.add(t, ou, map[string][]string{"objectClass": {"organizationalUnit"}})
	t.Cleanup(func() { l.delTree(ou) })

	bossDN := "CN=Boss " + l.stamp + "," + ou
	l.add(t, bossDN, map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"boss" + l.stamp}})
	hours := bytes.Repeat([]byte{0xff}, 21)
	hours[0], hours[20] = 0xfe, 0x7f
	photo := string(bytes.Repeat([]byte{0xd8}, 2048))
	fullDN := "CN=Ramán\\, Full " + l.stamp + "," + ou
	l.add(t, fullDN, map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"full" + l.stamp},
		"scriptPath": {"logon.bat"}, "telephoneNumber": {"+44 20 7946 0000"}, "mobile": {"+44 7700 900000"}, "manager": {bossDN},
		"msNPAllowDialin": {"TRUE"}, "logonHours": {string(hours)}, "thumbnailPhoto": {photo}, "jpegPhoto": {photo}})
	bareDN := "CN=Bare " + l.stamp + "," + ou
	l.add(t, bareDN, map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"bare" + l.stamp}})

	m, err := dirsync.NewMapper(dirsync.Config{NC: inventory.GUID(guidText(t, l.guid(t, labDom)))})
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := rpc(t, l.client, l.request(l.guid(t, ou), connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE, "user", m.Attributes()...))
	if err != nil {
		t.Fatalf("ScopedSearch: %v", err)
	}
	bag := map[string]map[string]any{}
	for _, e := range got {
		mapped, err := m.Map(e)
		if err != nil {
			t.Fatalf("Map %s: %v", e.GetDn().GetDisplayDn(), err)
		}
		bag[strings.ToLower(e.GetDn().GetDisplayDn())] = mapped.Observation.Attributes
	}
	read := func(dn string) *ldap.Entry {
		r, err := l.adm.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)",
			[]string{"scriptPath", "telephoneNumber", "mobile", "manager", "msNPAllowDialin", "logonHours", "thumbnailPhoto", "jpegPhoto"}, nil))
		if err != nil || len(r.Entries) != 1 {
			t.Fatalf("LDAP read of %s: %v", dn, err)
		}
		return r.Entries[0]
	}
	for _, dn := range []string{fullDN, bareDN} {
		b, ld := bag[strings.ToLower(dn)], read(dn)
		if b == nil && dn == fullDN {
			t.Fatalf("no mapped entry for %s (have %d)", dn, len(bag))
		}
		for _, p := range [][2]string{{"scriptPath", "scriptPath"}, {"telephoneNumber", "telephoneNumber"}, {"mobile", "mobile"}} {
			want := ld.GetAttributeValue(p[0])
			if g, _ := b[p[1]].(string); g != want {
				t.Errorf("%s: %s = %q, LDAP says %q", dn, p[1], g, want)
			}
		}
		if g, _ := b["manager"].(string); !strings.EqualFold(g, ld.GetAttributeValue("manager")) {
			t.Errorf("%s: manager = %q, LDAP says %q", dn, g, ld.GetAttributeValue("manager"))
		}
		dial, hasDial := b["msNPAllowDialin"].(bool)
		if ldv := ld.GetAttributeValue("msNPAllowDialin"); hasDial != (ldv != "") || (hasDial && dial != strings.EqualFold(ldv, "TRUE")) {
			t.Errorf("%s: msNPAllowDialin = %v/%v, LDAP says %q", dn, dial, hasDial, ldv)
		}
		lh, _ := b["logonHours"].(string)
		var wantBits strings.Builder
		for _, by := range ld.GetRawAttributeValue("logonHours") {
			for i := 0; i < 8; i++ {
				wantBits.WriteByte('0' + (by>>i)&1)
			}
		}
		if lh != wantBits.String() {
			t.Errorf("%s: logonHours = %q, LDAP says %q", dn, lh, wantBits.String())
		}
		for _, p := range [][2]string{{"thumbnailPhoto", "hasThumbnailPhoto"}, {"jpegPhoto", "hasJpegPhoto"}} {
			_, flag := b[p[1]].(bool)
			if want := len(ld.GetRawAttributeValue(p[0])) > 0; flag != want {
				t.Errorf("%s: %s = %v, LDAP has a value: %v", dn, p[1], flag, want)
			}
		}
		for k, v := range b {
			if s, ok := v.(string); ok && strings.Contains(s, "\xd8") {
				t.Errorf("%s: %s holds photo bytes", dn, k)
			}
		}
	}
	if b := bag[strings.ToLower(fullDN)]; b["hasThumbnailPhoto"] != true || b["hasJpegPhoto"] != true || b["msNPAllowDialin"] != true || len(b["logonHours"].(string)) != 168 {
		t.Errorf("the full user did not map every attribute: %v", b)
	}
	for _, k := range []string{"scriptPath", "telephoneNumber", "mobile", "manager", "msNPAllowDialin", "logonHours", "hasThumbnailPhoto", "hasJpegPhoto"} {
		if _, ok := bag[strings.ToLower(bareDN)][k]; ok {
			t.Errorf("the bare user has %s", k)
		}
	}
}
