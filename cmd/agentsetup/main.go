// Command agentsetup is run by the MSI custom actions, as SYSTEM, at install and uninstall. It is a
// separate binary so that the service executable carries no code that changes host configuration
// (TM-D13). Each subcommand takes no free-text argument: the service account and the channel are
// compiled in, and the data directory comes from the single `--data-dir` flag, validated absolute.
//
//	agentsetup grant-channel     add a read-only ACE for the service SID to the Security channel
//	agentsetup revoke-channel    remove it
//	agentsetup prepare-datadir   create the data directory with the pinned DACL
//	agentsetup write-config      write agent.json (local ceilings) next to the executable
//
// Any failure exits non-zero and the MSI custom action is marked fail-closed: the install does not
// continue with a service that cannot read its channel, and LocalSystem is never the fallback
// (ADR-0006 decision 2).
package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func usage() int {
	fmt.Fprintln(os.Stderr, "usage: agentsetup grant-channel | revoke-channel | write-config | prepare-datadir --data-dir <absolute path>")
	return 2
}
