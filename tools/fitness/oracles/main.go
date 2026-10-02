// Command oracles is FF-SP6 of the safe-primitives fitness set (T-0034): independent parsers check
// what the primitives produce.
//
//	oracles pslit      [-source golden|report] [-engine docker|pwsh|powershell]   PowerShell's own parser
//	oracles ldapfilter [-source golden|report]                                     go-ldap's parser
//	oracles winids -unit attr.sid|attr.guid -engine powershell                     Windows APIs (Windows runner)
//	oracles lab        [-source golden|report]                                     the Samba lab (P1)
//
// -source report reads the outputs an implementation actually produced (the reports its corpus test
// wrote to -reports); -source golden checks the corpus's expected values themselves, which is what
// runs before an implementation exists. Exit 1: an output fails an oracle. Exit 2: the oracle could not
// run (no Docker, no PowerShell, no lab); a missing oracle is a failure, never a skip.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: oracles pslit|ldapfilter|winids|lab [flags]")
		os.Exit(2)
	}
	sub := os.Args[1]
	fl := flag.NewFlagSet(sub, flag.ExitOnError)
	root := fl.String("root", ".", "repository root")
	source := fl.String("source", "golden", "golden (the corpus's expected outputs) report (an implementation's actual outputs) or auto (reports when present)")
	reports := fl.String("reports", "", "directory of implementation reports, for -source report")
	engine := fl.String("engine", "", "PowerShell engine: docker, pwsh or powershell (default: pwsh if installed, else docker; winids: powershell)")
	unit := fl.String("unit", "", "winids: attr.sid or attr.guid")
	verifyAs := fl.String("verify-as", "", "write passing record ids to -out as verified on this platform (samba or windows)")
	ifPresent := fl.Bool("if-present", false, "exit 0 with a note when the unit has no corpus file yet (the make targets use it until the corpus is authored)")
	out := fl.String("out", "", "results file for fitness-corpus -set-verified")
	_ = fl.Parse(os.Args[2:])

	if *ifPresent {
		u := map[string]string{"pslit": "pslit", "ldapfilter": "ldapfilter", "lab": "ldapfilter", "winids": *unit}[sub]
		if _, err := os.Stat(filepath.Join(*root, filepath.FromSlash(corpus.Dir), u+".jsonl")); err != nil {
			fmt.Printf("oracles %s: no corpus file for %s yet, nothing to check\n", sub, u)
			return
		}
	}
	var err error
	var checked int
	var failures, passed []string
	var u string
	switch sub {
	case "pslit":
		u = "pslit"
		var cases []Case
		if cases, _, err = loadCases(*root, u, *source, *reports); err == nil {
			e := pickEngine(*engine)
			fmt.Printf("oracle pslit: PowerShell %s via %s, source %s\n", e.Version(), e.Name, label(cases))
			checked, failures, err = checkPslit(e, cases)
		}
	case "ldapfilter":
		u = "ldapfilter"
		var cases []Case
		if cases, _, err = loadCases(*root, u, *source, *reports); err == nil {
			checked, failures = checkLDAPFilter(cases)
			if checked == 0 {
				err = fmt.Errorf("no ldapfilter record with a rendered output to check")
			}
		}
	case "winids":
		u = *unit
		if u != "attr.sid" && u != "attr.guid" {
			fmt.Fprintln(os.Stderr, "oracles winids: -unit attr.sid or attr.guid")
			os.Exit(2)
		}
		var cases []Case
		if cases, _, err = loadCases(*root, u, *source, *reports); err == nil {
			e := Engine{Name: "powershell"}
			if *engine != "" {
				e.Name = *engine
			}
			passed, failures, err = checkWinIDs(e, u, cases)
			checked = len(passed) + len(failures)
		}
	case "lab":
		u = "ldapfilter"
		var cases []Case
		if cases, _, err = loadCases(*root, u, *source, *reports); err == nil {
			passed, failures, err = checkLab(*root, cases)
			checked = len(passed) + len(failures)
		}
	default:
		fmt.Fprintf(os.Stderr, "oracles: unknown oracle %q\n", sub)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "oracles", sub+":", err)
		os.Exit(2)
	}
	if *out != "" && *verifyAs != "" && len(failures) == 0 {
		if err := writeResults(*out, u, *verifyAs, passed); err != nil {
			fmt.Fprintln(os.Stderr, "oracles:", err)
			os.Exit(2)
		}
	}
	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Fprintf(os.Stderr, "%s: FF-SP6 [%s] %s\n", u, sub, f)
		}
		fmt.Fprintf(os.Stderr, "oracles %s: %d of %d records fail\n", sub, len(failures), checked)
		os.Exit(1)
	}
	fmt.Printf("oracles %s: ok (%d records checked)\n", sub, checked)
}

func label(cs []Case) string {
	if len(cs) > 0 {
		return cs[0].Source
	}
	return "none"
}

func pickEngine(name string) Engine {
	if name != "" {
		return Engine{Name: name}
	}
	if _, err := exec.LookPath("pwsh"); err == nil {
		return Engine{Name: "pwsh"}
	}
	return Engine{Name: "docker"}
}

func writeResults(path, unit, platform string, ids []string) error {
	sort.Strings(ids)
	m := map[string]map[string]string{unit: {}}
	for _, id := range ids {
		m[unit][id] = platform
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
