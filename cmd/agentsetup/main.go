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
//	agentsetup repin <pin>       adopt a new server-CA pin received out of band, keeping the identity
//
// repin is the one verb with an argument, and the argument is only ever a pin (sha256:<64 hex>),
// parsed strictly; it is an operator action after a server-CA compromise (ADR-0008 obligation 5),
// not an MSI custom action. Each use is audited (event 4102 in the Application log).
//
// Any failure exits non-zero and the MSI custom action is marked fail-closed: the install does not
// continue with a service that cannot read its channel, and LocalSystem is never the fallback
// (ADR-0006 decision 2).
package main

import (
	"fmt"
	"os"

	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
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
	fmt.Fprintln(os.Stderr, "usage: agentsetup grant-channel | revoke-channel | write-config | prepare-datadir | repin sha256:<hex>")
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

// parseRepin returns the pin of a command line that is exactly `repin <pin>`. The pin is validated
// here, so nothing but 64 lower-case hex digits ever reaches the state directory code.
func parseRepin(args []string) (string, bool) {
	if len(args) != 2 || args[0] != "repin" {
		return "", false
	}
	if _, err := dial.ParsePin(args[1]); err != nil {
		return "", false
	}
	return args[1], true
}
