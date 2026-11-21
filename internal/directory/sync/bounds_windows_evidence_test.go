package sync_test

// T-1880 offline half of the Windows lab evidence (internal/connector/ad/schema_bounds_windows_lab_test.go
// measures dc1; this package may not touch LDAP, so the mapper side is pinned here with the measured values).

import (
	"errors"
	"strings"
	"testing"

	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
)

func mapComputerAttr(attr, v string) error {
	e := entry(92, "CN=T1880PC,CN=Computers,DC=win,DC=activediq,DC=test", gid(ouGUID),
		attrs(nil).classes("top", "computer").with(attr, txt(v)))
	_, err := mapper(dirsync.Config{}).Map(e)
	return err
}

// Windows rangeUpper measured on dc1 (T-1880, sync-refusal-bounds.md): a value of exactly that many
// multi-byte characters must map (a byte count would refuse it).
func TestMapperAcceptsWindowsRangeUpperChars(t *testing.T) {
	for attr, upper := range map[string]int{"displayName": 256, "mail": 256, "company": 64, "description": 1024, "dNSHostName": 2048} {
		if err := mapComputerAttr(attr, strings.Repeat("é", upper)); err != nil {
			t.Errorf("%s at %d chars: %v", attr, upper, err)
		}
	}
}

// A lone UTF-16 surrogate read back over LDAP is CESU-8 (invalid UTF-8): the mapper must refuse it with
// bad_text, never store it; a valid pair (control) must map.
func TestMapperRefusesLoneSurrogateBytes(t *testing.T) {
	for _, attr := range []string{"description", "displayName"} {
		for name, raw := range map[string]string{"high": "\xed\xa0\x80", "low": "\xed\xb0\x80"} {
			var me *dirsync.Error
			if err := mapComputerAttr(attr, raw); !errors.As(err, &me) || me.Code != dirsync.CodeBadText {
				t.Errorf("%s lone %s surrogate: want bad_text, got %v", attr, name, err)
			}
		}
		if err := mapComputerAttr(attr, "\U0001F600"); err != nil {
			t.Errorf("%s valid pair refused: %v", attr, err)
		}
	}
}
