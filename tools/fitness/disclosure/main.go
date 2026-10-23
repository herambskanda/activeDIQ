// Command disclosure is the T-0258 fitness function for vulnerability intake: the public repo must
// carry SECURITY.md and an RFC 9116 .well-known/security.txt with a Contact named in SECURITY.md,
// exactly one RFC 3339 Expires that is in the future, under a year ahead and more than 30 days
// away (so CI forces renewal before the file goes stale), and a Policy pointing at SECURITY.md.
// T-0260 adds the advisories (advisory.go): security/advisories/TEMPLATE/ must exist, and every
// published security/advisories/<CVE-ID>/ must carry the same CVE ID and one CVSS v3.1 vector and
// score in advisory.md and record.json, be published on the fix day, and state target_met honestly.
package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	v := Check(root, time.Now().UTC())
	for _, s := range v {
		fmt.Fprintln(os.Stderr, s)
	}
	if len(v) > 0 {
		fmt.Fprintf(os.Stderr, "fitness-disclosure: FAIL: %d problem(s) with the vulnerability intake or advisory files\n", len(v))
		os.Exit(1)
	}
	fmt.Println("fitness-disclosure: ok")
}
