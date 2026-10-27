// Command packaging is the T-0104 fitness function for the API TLS directory (TM-TB16-T3): the Windows
// ACL script must lock the directory to Administrators and the service identity, the linux-oci prepare
// script must hand it to a non-root uid at mode 0700 (and is run for real), and the Compose fragment must
// run the server as a numeric non-root user with the directory bind-mounted. The Windows behaviour itself
// (a non-administrator is denied) is the lab test packaging/windows/Test-ApiTlsDirAcl.ps1.
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
	if len(v) > 0 {
		fmt.Fprintf(os.Stderr, "fitness-packaging: FAIL: %d problem(s)\n", len(v))
		os.Exit(1)
	}
	fmt.Println("fitness-packaging: ok")
}
