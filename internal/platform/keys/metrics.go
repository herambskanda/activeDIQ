package keys

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Unwrap outcomes for the per-tenant unwrap counter (TM-TB5-T3).
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// UnwrapMetricName is the exported counter name.
const UnwrapMetricName = "activediq_keys_dek_unwraps_total"

type unwrapKey struct {
	tenant  tenant.ID
	outcome string
}

var unwraps = struct {
	mu sync.Mutex
	m  map[unwrapKey]uint64
}{m: map[unwrapKey]uint64{}}

func countUnwrap(t tenant.ID, outcome string) {
	unwraps.mu.Lock()
	unwraps.m[unwrapKey{t, outcome}]++
	unwraps.mu.Unlock()
}

// UnwrapCount returns how many UnwrapDEK calls for tenant t ended in outcome
// (OutcomeSuccess or OutcomeFailure) in this process. Counted for every provider profile because
// the count is taken in UnwrapDEK, not in an adapter.
func UnwrapCount(t tenant.ID, outcome string) uint64 {
	unwraps.mu.Lock()
	defer unwraps.mu.Unlock()
	return unwraps.m[unwrapKey{t, outcome}]
}

// WriteMetrics writes the unwrap counter in Prometheus text exposition format. The only labels are
// tenant and outcome: no key reference, key id or wrapped material ever appears.
func WriteMetrics(w io.Writer) error {
	unwraps.mu.Lock()
	rows := make([]unwrapKey, 0, len(unwraps.m))
	vals := make(map[unwrapKey]uint64, len(unwraps.m))
	for k, v := range unwraps.m {
		rows = append(rows, k)
		vals[k] = v
	}
	unwraps.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.tenant != b.tenant {
			return a.tenant.String() < b.tenant.String()
		}
		return a.outcome < b.outcome
	})
	if _, err := fmt.Fprintf(w, "# HELP %s DEK unwrap calls per tenant and outcome.\n# TYPE %s counter\n", UnwrapMetricName, UnwrapMetricName); err != nil {
		return err
	}
	for _, k := range rows {
		if _, err := fmt.Fprintf(w, "%s{tenant=\"%s\",outcome=\"%s\"} %d\n", UnwrapMetricName, escapeLabel(k.tenant.String()), escapeLabel(k.outcome), vals[k]); err != nil {
			return err
		}
	}
	return nil
}

// labelEscaper applies the Prometheus text-format label-value escapes: backslash, double quote and
// line feed. Go's %q is not the same format (it also escapes non-ASCII and control bytes as \x.. or \u....).
var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func escapeLabel(v string) string { return labelEscaper.Replace(v) }
