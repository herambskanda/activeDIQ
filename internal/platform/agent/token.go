package agent

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// PinnedPrivileges is the whole set of privileges the agent's token may hold (ADR-0006 decision 3,
// and the MSI's RequiredPrivileges). Every other privilege, notably SeBackup, SeRestore,
// SeTakeOwnership, SeDebug, SeImpersonate, SeLoadDriver and SeTcb, must be absent.
var PinnedPrivileges = []string{"SeChangeNotifyPrivilege"}

// ErrPrivileges: the process token holds a privilege outside PinnedPrivileges. The agent exits before
// it opens a subscription or a connection.
var ErrPrivileges = errors.New("agent: process token holds privileges outside the pinned list")

// CheckPrivileges compares the privilege names present in the token (enabled or not) with the pinned
// list. The error names the extra privileges; privilege names are not secret.
func CheckPrivileges(held []string) error {
	var extra []string
	for _, p := range held {
		if !slices.Contains(PinnedPrivileges, p) {
			extra = append(extra, p)
		}
	}
	if len(extra) == 0 {
		return nil
	}
	slices.Sort(extra)
	return fmt.Errorf("%w: %s", ErrPrivileges, strings.Join(slices.Compact(extra), ", "))
}
