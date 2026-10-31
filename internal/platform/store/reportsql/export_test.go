package reportsql

import (
	"time"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

// SQL and Args expose a compiled query to the external tests.
func SQL(q Query) string { return string(q.sql) }
func Args(q Query) []any { return q.args }

func testBuilder(ds Dataset, now time.Time) *builder {
	return &builder{d: ds.d, idx: map[argKey]int{}, now: now, relSQL: map[report.AnchorID]string{}}
}

// OrderBy and Cmp render one clause the way Compile does, so a hostile key or an operator that
// report.Resolve would have refused can still be driven through the renderer.
func OrderBy(ds Dataset, keys []report.SortKey) (string, []any, error) {
	b := testBuilder(ds, time.Time{})
	s, err := b.orderBy(keys)
	return s, b.args, err
}

func Cmp(ds Dataset, c report.Cmp, now time.Time) (string, []any, error) {
	b := testBuilder(ds, now.UTC())
	s, err := b.cmp(c)
	return s, b.args, err
}
