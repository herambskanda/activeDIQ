package server

import (
	"fmt"
	"slices"
	"strings"
)

// guidSetDiff reports the members only in want (missing from got) and only in got (extra), as sorted
// object GUIDs and nothing else: a failing comparison must never print a DN or an attribute value
// (lab logs and CI output are read by people who may not read the directory). ok is true when the sets
// are equal.
func guidSetDiff(want, got map[string]struct{}) (msg string, ok bool) {
	var missing, extra []string
	for g := range want {
		if _, in := got[g]; !in {
			missing = append(missing, g)
		}
	}
	for g := range got {
		if _, in := want[g]; !in {
			extra = append(extra, g)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return "", true
	}
	slices.Sort(missing)
	slices.Sort(extra)
	return fmt.Sprintf("only in the LDAP ground truth (%d): [%s]; only in the report (%d): [%s]",
		len(missing), strings.Join(missing, " "), len(extra), strings.Join(extra, " ")), false
}
