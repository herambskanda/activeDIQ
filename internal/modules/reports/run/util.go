package run

import (
	"slices"
	"sort"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
)

func sortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortDetails puts details in strictly increasing key order, as audit.Event requires.
func sortDetails(d []chain.Detail) []chain.Detail {
	slices.SortFunc(d, func(a, b chain.Detail) int {
		switch {
		case a.Key < b.Key:
			return -1
		case a.Key > b.Key:
			return 1
		}
		return 0
	})
	return d
}
