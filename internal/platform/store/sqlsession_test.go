package store

import (
	"strings"
	"testing"
	"unicode"
)

func TestChangesSessionSetting(t *testing.T) {
	for sql, want := range map[string]bool{
		"SET transaction_read_only = off":                       true,
		"SET LOCAL default_transaction_read_only TO 'off'":      true,
		"SET LOCAL client_encoding = 'SJIS'":                    true,
		"SET NAMES 'BIG5'":                                      true,
		"SELECT set_config('transaction_read_only','off',true)": true,
		"SELECT set_config('x','y',true)":                       true,
		"RESET client_encoding":                                 true,
		"SELECT 'set_config' FROM t":                            false, // quoted text is blanked
		"SELECT names FROM t":                                   false, // NAMES only counts after SET
		"UPDATE t SET a = 1":                                    false,
		"SELECT 1":                                              false,
	} {
		words := strings.FieldsFunc(strings.ToUpper(strings.Join(Statements(sql), ";")),
			func(r rune) bool { return !unicode.IsLetter(r) && r != '_' })
		if got := ChangesSessionSetting(words); got != want {
			t.Errorf("ChangesSessionSetting(%q) = %v, want %v", sql, got, want)
		}
	}
}
