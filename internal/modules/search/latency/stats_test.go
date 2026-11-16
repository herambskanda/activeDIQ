package latency_test

import (
	"testing"
	"time"
)

// The early stop is exact: overToMiss samples at the budget decide a miss of the p95 of n whatever the rest
// are, and one fewer does not.
func TestOverToMissDecidesTheP95(t *testing.T) {
	for _, n := range []int{1, 2, 19, 20, 21, 30, 100, 150, 999, 1000, 1001} {
		k := overToMiss(n, 95)
		fill := func(over int) []time.Duration {
			ds := make([]time.Duration, n)
			for i := range over {
				ds[i] = budget
			}
			return ds
		}
		if got := summarize(fill(k)).p95; got < budget {
			t.Errorf("n=%d: %d samples at the budget leave p95 %s under it", n, k, got)
		}
		if k > 0 {
			if got := summarize(fill(k - 1)).p95; got >= budget {
				t.Errorf("n=%d: %d samples at the budget already decide p95 %s: the stop is late", n, k-1, got)
			}
		}
	}
	if k := overToMiss(1000, 95); k != 51 {
		t.Errorf("overToMiss(1000, 95) = %d, want 51", k)
	}
}

// A search that ran into the service timeout is a slow sample; any other non-200 still stops the run.
func TestTimedOutIsOnlyTheSearchUnavailableProblem(t *testing.T) {
	unavail := []byte(`{"instance":"/api/v1/directory/search","status":503,"title":"Search is unavailable","type":"/problems/search-unavailable"}`)
	if !timedOut(503, unavail) {
		t.Error("the contract's search-unavailable 503 is not recognised")
	}
	if timedOut(500, unavail) || timedOut(503, []byte(`{"type":"/problems/internal"}`)) || timedOut(200, nil) {
		t.Error("a status other than the search-unavailable 503 was taken for a timeout")
	}
}
