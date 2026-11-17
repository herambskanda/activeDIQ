package migration_test

import (
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/modules/migration"
)

func TestSizeGate(t *testing.T) {
	const mib = 1 << 20
	cases := []struct {
		kind  migration.SourceKind
		size  int64
		limit string
	}{
		{migration.SourceCSV, 256 * mib, ""},
		{migration.SourceCSV, 257 * mib, "upload_size_256mib"},
		{migration.SourceXLSX, 256*mib + 1, "upload_size_256mib"},
		{migration.SourceDBDump, 300 * mib * 10, ""},
		{migration.SourceDBDump, 4<<30 + 1, "upload_size_4gib"},
		{migration.SourceHTML, 0, ""},
	}
	for _, c := range cases {
		got, err := migration.SizeGate(c.kind, c.size)
		if err != nil || got != c.limit {
			t.Errorf("%s %d: got %q, %v; want %q", c.kind, c.size, got, err, c.limit)
		}
	}
	for _, bad := range []struct {
		k migration.SourceKind
		n int64
	}{{"exe", 1}, {migration.SourceCSV, -1}} {
		if _, err := migration.SizeGate(bad.k, bad.n); !errors.Is(err, migration.ErrInvalid) {
			t.Errorf("%v: want ErrInvalid, got %v", bad, err)
		}
	}
}
