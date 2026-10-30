package updateverify

import (
	"fmt"
	"strconv"
	"strings"
)

// compareVersions compares dotted numeric product versions ("1.6", "1.10.2"); missing parts are 0.
func compareVersions(a, b string) (int, error) {
	pa, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y uint64
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

func parseVersion(v string) ([]uint64, error) {
	if v == "" {
		return nil, fmt.Errorf("updateverify: empty product version")
	}
	parts := strings.Split(v, ".")
	out := make([]uint64, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil || p != strconv.FormatUint(n, 10) {
			return nil, fmt.Errorf("updateverify: product version %q is not dotted numeric", v)
		}
		out[i] = n
	}
	return out, nil
}
