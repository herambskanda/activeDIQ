// Command agentsetup is run by the MSI custom actions, as SYSTEM, at install and uninstall. It is a
// separate binary so that the service executable carries no code that changes host configuration
// (TM-D13). Each subcommand takes no free-text argument: the service account and the channel are
// compiled in, and the data directory is derived from the ProgramData known folder. Any argument beyond
// the verb is refused.
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

	"github.com/skenzeriq/activediq/internal/platform/prochardening"
)

func main() {
	if err := prochardening.Apply(os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "agentsetup:", err)
		os.Exit(2)
	}
	os.Exit(run(os.Args[1:]))
}

func usage() int {
	fmt.Fprintln(os.Stderr, "usage: agentsetup grant-channel | revoke-channel | write-config | prepare-datadir")
	return 2
}

// verbs are the only commands. A command line is exactly one of them and nothing else (T-0688 ruling 4a).
var verbs = map[string]bool{"grant-channel": true, "revoke-channel": true, "write-config": true, "prepare-datadir": true}

// parseVerb returns the verb of args, or false when args is not exactly one known verb.
func parseVerb(args []string) (string, bool) {
	if len(args) != 1 || !verbs[args[0]] {
		return "", false
	}
	return args[0], true
}
