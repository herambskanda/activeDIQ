package audit

import "time"

// A time partition is a span of the chain's time axis; the default is one UTC calendar month (ADR-0005
// rule 11: "time partitions are seq ranges", because the chain's `at` is monotonic per tenant). A partition
// is purgeable only when its last event carries a signed checkpoint (the partition-boundary checkpoint).
type Partitions struct {
	// Start is the first instant of the partition t falls in; End is the first instant after it.
	Start, End func(t time.Time) time.Time
}

// Monthly is the partitioning the product runs with: UTC calendar months.
var Monthly = Partitions{Start: PartitionStart, End: PartitionEnd}

// Fixed partitions time into spans of d counted from the Unix epoch. Tests use it to cross partitions in
// seconds; the product uses Monthly.
func Fixed(d time.Duration) Partitions {
	return Partitions{
		Start: func(t time.Time) time.Time { return t.UTC().Truncate(d) },
		End:   func(t time.Time) time.Time { return t.UTC().Truncate(d).Add(d) },
	}
}

// PartitionStart returns the first instant of the calendar month t falls in, in UTC.
func PartitionStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// PartitionEnd returns the first instant after the calendar month t falls in, in UTC.
func PartitionEnd(t time.Time) time.Time { return PartitionStart(t).AddDate(0, 1, 0) }
