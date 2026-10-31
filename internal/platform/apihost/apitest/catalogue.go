package apitest

import (
	"slices"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

// Catalogue is the permission catalogue a handler test passes to apihost.Build: every concrete
// x-permission the document declares. A test that builds the shared router to exercise one tag must
// not hand-list the permissions of every other module's operations: that list goes stale each time a
// contract lands (T-1032). The real catalogue (roles plus module declarations) is checked against the
// same document by the server composition's Build, so a typo in the contract is still caught there.
func Catalogue(doc apihost.Document) apihost.Permissions {
	var set []string
	for _, op := range doc.Operations() {
		switch op.Permission {
		case "", "anonymous", "authenticated":
			continue
		}
		set = append(set, op.Permission)
	}
	slices.Sort(set)
	return apihost.Permissions(slices.Compact(set))
}
