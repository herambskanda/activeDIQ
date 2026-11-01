// Command sso is the T-0211 fitness function for console SSO (console-sso.md §13).
//
// FIT-SSO-1: the SAML libraries (goxmldsig, gosaml2, etree, xml-roundtrip-validator) are imported only
// under internal/platform/authn/sso/saml, the JOSE libraries (go-oidc, go-jose) only under
// internal/platform/authn/sso/oidc, and encoding/xml nowhere under internal/platform/authn except
// sso/saml; go.mod does not pin goxmldsig below v1.6.0 or gosaml2 below v0.12.0.
//
// FIT-SSO-2: every OIDC-n and SAML-n check of the spec's §4/§5 is cited by a corpus record, each
// protocol has a record of every class, and every record runs as a passing subtest of its package's
// TestCorpus.
//
// -static skips the `go test` half of FIT-SSO-2. It exists for tools/ci/proof.sh, which runs this
// command on synthetic trees that are not Go modules; `make fitness-sso` never passes it.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/skenzeriq/activediq/tools/fitness/internal/boundtest"
)

func main() {
	root := flag.String("root", ".", "repository root")
	static := flag.Bool("static", false, "skip the bound-test half of FIT-SSO-2 (proof harness only)")
	flag.Parse()

	var all []string
	imp, err := CheckImports(*root)
	fatal(err)
	mod, err := CheckModule(*root)
	fatal(err)
	all = append(all, imp...)
	all = append(all, mod...)
	if len(imp)+len(mod) == 0 {
		fmt.Println("fitness-sso: FIT-SSO-1 ok (import fence, go.mod floors)")
	}

	res, err := CheckCorpus(*root)
	fatal(err)
	all = append(all, res.Violations...)
	if len(res.Violations) == 0 && !*static {
		// The subtests are only worth running once the records themselves are sound.
		bound, err := CheckSubtests(context.Background(), *root, res, boundtest.GoTest)
		fatal(err)
		all = append(all, bound...)
		if len(bound) == 0 {
			fmt.Println("fitness-sso: FIT-SSO-2 ok (every check cited, every class present, every record a passing subtest)")
		}
	} else if len(res.Violations) == 0 {
		fmt.Println("fitness-sso: FIT-SSO-2 static half ok")
	}

	for _, v := range all {
		fmt.Fprintln(os.Stderr, "fitness-sso: FAIL:", v)
	}
	if len(all) > 0 {
		fmt.Fprintf(os.Stderr, "fitness-sso: FAIL: %d violation(s) (console-sso.md §13)\n", len(all))
		os.Exit(1)
	}
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fitness-sso:", err)
		os.Exit(2)
	}
}
