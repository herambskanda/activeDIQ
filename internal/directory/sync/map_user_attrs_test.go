package sync_test

import (
	"bytes"
	"strings"
	"testing"

	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
)

// T-1111: the user-attribute report attributes reach the bag; a photo is only a flag, logonHours is 168 bits.
func Test_map_user_attributes(t *testing.T) {
	m := mapper(dirsync.Config{})
	hours := bytes.Repeat([]byte{0xff}, 21)
	hours[0] = 0xfe // Sunday 00:00 UTC denied
	photo := bytes.Repeat([]byte{0xab}, 4096)
	full := attrs(nil).classes("top", "person", "organizationalPerson", "user").
		with("msNPAllowDialin", boolean(true)).with("msRTCSIP-UserEnabled", boolean(false)).
		with("scriptPath", txt("logon.bat")).with("telephoneNumber", txt("+44 20 7946 0000")).with("mobile", txt("+44 7700 900000")).
		with("manager", dnv("CN=Boss,OU=People,DC=lab,DC=test", nil)).
		with("logonHours", octets(hours)).with("thumbnailPhoto", octets(photo)).with("jpegPhoto", octets(photo))
	got := mustMap(t, m, entry(80, "CN=Priya,OU=People,DC=lab,DC=test", gid(ouGUID), full))
	b := got.Observation.Attributes
	for k, want := range map[string]any{"msNPAllowDialin": true, "msRTCSIP-UserEnabled": false, "scriptPath": "logon.bat",
		"telephoneNumber": "+44 20 7946 0000", "mobile": "+44 7700 900000", "manager": "CN=Boss,OU=People,DC=lab,DC=test",
		"hasThumbnailPhoto": true, "hasJpegPhoto": true} {
		if b[k] != want {
			t.Errorf("%s = %v, want %v", k, b[k], want)
		}
	}
	lh, _ := b["logonHours"].(string)
	if len(lh) != 168 || !strings.HasPrefix(lh, "01111111") || strings.Count(lh, "0") != 1 {
		t.Errorf("logonHours = %q", lh)
	}
	// No photo byte, in any form, reaches the bag.
	for k, v := range b {
		if s, ok := v.(string); ok && (strings.Contains(s, "\xab") || len(s) > 600) && k != "logonHours" {
			t.Errorf("%s carries binary content", k)
		}
		if _, ok := v.([]byte); ok {
			t.Errorf("%s is a byte slice", k)
		}
	}
	if _, ok := b["thumbnailPhoto"]; ok {
		t.Error("the photo itself is in the bag")
	}

	// Absent, empty and zero-length values add nothing.
	bare := mustMap(t, m, entry(81, "CN=Bare,OU=People,DC=lab,DC=test", gid(ouGUID),
		attrs(nil).classes("user").with("thumbnailPhoto", octets(nil)).with("scriptPath", txt(""))))
	for _, k := range []string{"hasThumbnailPhoto", "hasJpegPhoto", "scriptPath", "logonHours", "msNPAllowDialin", "msRTCSIP-UserEnabled", "manager"} {
		if _, ok := bare.Observation.Attributes[k]; ok {
			t.Errorf("%s is in the bag of an entry that did not carry a value", k)
		}
	}

	// A logonHours of the wrong size refuses the entry.
	if _, err := m.Map(entry(82, "CN=Odd,OU=People,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("user").with("logonHours", octets([]byte{1, 2, 3})))); err == nil {
		t.Error("a 3-byte logonHours was accepted")
	}
}

// T-1111: nothing on the closed list is a secret and the photos are the only binary content read.
func Test_closed_list_user_attributes(t *testing.T) {
	have := map[string]bool{}
	for _, a := range dirsync.Attributes() {
		have[strings.ToLower(a)] = true
	}
	for _, a := range []string{"msnpallowdialin", "msrtcsip-userenabled", "logonhours", "thumbnailphoto", "jpegphoto", "telephonenumber", "mobile", "manager", "scriptpath"} {
		if !have[a] {
			t.Errorf("%s is not on the closed list", a)
		}
	}
}

// T-2216: a user's bag records per attribute whether a value was observed; an omitted attribute is
// not_observed (absent or unreadable), and unknown_denied is never written. Non-users carry no marker.
func Test_map_user_read_marker(t *testing.T) {
	m := mapper(dirsync.Config{})
	got := mustMap(t, m, entry(90, "CN=Marker,OU=People,DC=lab,DC=test", gid(ouGUID),
		attrs(nil).classes("user").with("mail", txt("m@lab.test")).with("scriptPath", txt(""))))
	rm, ok := got.Observation.Attributes["attrRead"].(map[string]any)
	if !ok {
		t.Fatalf("no attrRead marker: %v", got.Observation.Attributes)
	}
	if rm["mail"] != "observed" {
		t.Errorf("mail = %v, want observed", rm["mail"])
	}
	for _, k := range []string{"scriptPath", "manager", "logonHours", "thumbnailPhoto"} {
		if rm[k] != "not_observed" {
			t.Errorf("%s = %v, want not_observed", k, rm[k])
		}
	}
	for k, v := range rm {
		if v == "unknown_denied" {
			t.Errorf("%s: unknown_denied must never be written", k)
		}
	}
	grp := mustMap(t, m, entry(91, "CN=G,OU=People,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("group")))
	if _, ok := grp.Observation.Attributes["attrRead"]; ok {
		t.Error("a group carries a user read marker")
	}
}
