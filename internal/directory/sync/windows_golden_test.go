package sync_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1787 (split from T-1205): the entries in testdata/windows are what the connector's ScopedSearch handler
// streamed for the Windows lab DC (dc1), captured by internal/connector/read TestWindowsLabSyncCapture (tags
// lab windowslab, SYNC_CAPTURE_DIR). Samba cannot show these: a real DC's accountExpires 0 vs
// 9223372036854775807 vs a future value on real accounts, and lastLogonTimestamp present vs absent.
// Expectations are read off each entry's own time value (sentinel or instant), never typed in, so a
// recapture with a new stamp still passes while a mapper that fabricates or drops a time fails.

func loadWin(t *testing.T, name string) *connectorv1.DirectoryEntry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "windows", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	e := &connectorv1.DirectoryEntry{}
	if err := protojson.Unmarshal(b, e); err != nil {
		t.Fatal(err)
	}
	return e
}

// timeAttr returns the single time value of attribute name on the entry, or nil if the DC sent none.
func timeAttr(t *testing.T, e *connectorv1.DirectoryEntry, name string) *connectorv1.TimeValue {
	t.Helper()
	for _, a := range e.GetAttributes() {
		if !strings.EqualFold(a.GetName(), name) {
			continue
		}
		if len(a.GetValues()) != 1 || a.GetValues()[0].GetTime() == nil {
			t.Fatalf("%s: want exactly one time value, got %v", name, a.GetValues())
		}
		return a.GetValues()[0].GetTime()
	}
	return nil
}

func Test_windows_dc_time_entries_map_to_what_the_dc_said(t *testing.T) {
	dom := loadWin(t, "domain")
	m, err := dirsync.NewMapper(dirsync.Config{NC: inventory.GUID(rfcText(dom.GetObjectGuid()))})
	if err != nil {
		t.Fatal(err)
	}
	// wantExpires: kind of the DC's accountExpires value, as the entry itself shows it.
	cases := []struct {
		file         string
		wantSentinel connectorv1.TimeSentinel // checked against the entry first, so the case cannot rot silently
		wantAt       bool
		wantLogon    bool
	}{
		{"user-expires-zero", connectorv1.TimeSentinel_TIME_SENTINEL_ZERO, false, false},
		{"user-expires-max", connectorv1.TimeSentinel_TIME_SENTINEL_MAX, false, false},
		{"user-expires-future", 0, true, false},
		{"user-never-logged-on", connectorv1.TimeSentinel_TIME_SENTINEL_MAX, false, false}, // a fresh Windows account defaults to MAX
		{"user-lastlogon-present", connectorv1.TimeSentinel_TIME_SENTINEL_MAX, false, true},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			e := loadWin(t, c.file)
			ae := timeAttr(t, e, "accountExpires")
			if ae == nil {
				t.Fatal("fixture has no accountExpires: the DC always returns it for a user")
			}
			if c.wantAt && ae.GetAt() == nil || !c.wantAt && ae.GetSentinel() != c.wantSentinel {
				t.Fatalf("fixture accountExpires = %v, case expects at=%v sentinel=%v", ae, c.wantAt, c.wantSentinel)
			}
			o := mustMap(t, m, e).Observation
			if o.Kind != inventory.KindUser || o.State != inventory.ObjLive {
				t.Errorf("kind/state = %s/%s", o.Kind, o.State)
			}
			// accountExpires: both sentinels mean "no expiry" (zero time) and the attribute counts as read; a real
			// instant is carried exactly.
			var wantExp time.Time
			if c.wantAt {
				wantExp = ae.GetAt().AsTime()
			}
			if !o.AccountExpires.Equal(wantExp) {
				t.Errorf("AccountExpires = %v, want %v", o.AccountExpires, wantExp)
			}
			if o.InputsRead&inventory.ReadAccountExpires == 0 {
				t.Errorf("accountExpires was returned by the DC but its read bit is clear")
			}
			// lastLogonTimestamp: present is carried exactly; absent is "not read", never a fabricated zero-and-read.
			ll := timeAttr(t, e, "lastLogonTimestamp")
			if (ll != nil) != c.wantLogon {
				t.Fatalf("fixture lastLogonTimestamp present=%v, case expects %v", ll != nil, c.wantLogon)
			}
			if ll != nil {
				if !o.LastLogonTimestamp.Equal(ll.GetAt().AsTime()) || o.InputsRead&inventory.ReadLastLogonTimestamp == 0 {
					t.Errorf("LastLogonTimestamp = %v (read=%v), want %v", o.LastLogonTimestamp, o.InputsRead&inventory.ReadLastLogonTimestamp != 0, ll.GetAt().AsTime())
				}
			} else if !o.LastLogonTimestamp.IsZero() || o.InputsRead&inventory.ReadLastLogonTimestamp != 0 {
				t.Errorf("DC sent no lastLogonTimestamp but the mapper reports %v read=%v", o.LastLogonTimestamp, o.InputsRead&inventory.ReadLastLogonTimestamp != 0)
			}
		})
	}
}
