// Command agenthost is fitness-agent-host (ADR-0006, T-0555). It judges, without a Windows host:
//
//	A1  the MSI source runs the service as NT SERVICE\activeDIQAgent with a restricted SID and exactly
//	    the pinned privilege list, never LocalSystem or another account, and uses no PowerShell
//	A4  cmd/agent links no LDAP, SMB, RPC, SSPI, service-control, registry or process-spawning package
//	R3  the addc module imports none of those either, and opens no listener
//
// A2 and A3 (token refusal, channel ACE read, no write outside the data directory) need a Windows
// host and are the lab items of the ticket; this check reports them as NOT RUN, never as passed.
package main

import (
	"fmt"
	"os"
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	v := Check(root)
	for _, s := range v {
		fmt.Fprintln(os.Stderr, s)
	}
	fmt.Println("fitness-agent-host: A2, A3 (Windows lab) NOT RUN")
	if len(v) > 0 {
		fmt.Fprintf(os.Stderr, "fitness-agent-host: FAIL: %d problem(s)\n", len(v))
		os.Exit(1)
	}
	fmt.Println("fitness-agent-host: ok (A1, A4, R3)")
}
