// Command builtmsi is `fitness-built-msi` (T-0697): it opens a built MSI and fails when the service
// account, SID type, privileges, custom actions, binaries, DACLs or registry writes differ from the
// reviewed pin. Needs `msidump` (msitools) on PATH unless -idt-dir is given.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	glob := flag.String("glob", "", "glob of built MSIs to judge, e.g. dist/*.msi")
	idt := flag.String("idt-dir", "", "judge an already dumped directory of .idt files (tests, the proof script)")
	require := flag.Bool("require", false, "fail when no MSI matched (the release job once the packaging ticket produces one)")
	allowFile := flag.String("installer-allow", "tools/fitness/agenthost/installer-allow.txt", "reviewed CustomAction Ids and permission parents")
	pinFile := flag.String("pinned", "tools/fitness/builtmsi/pinned-actions.txt", "reviewed CustomAction table rows")
	noAgent := flag.Bool("no-require-agent", false, "do not demand the agent service (self-tests of other tables)")
	flag.Parse()
	die := func(err error) { fmt.Fprintln(os.Stderr, "fitness-built-msi:", err); os.Exit(2) }
	ab, err := os.ReadFile(*allowFile)
	if err != nil {
		die(err)
	}
	pb, err := os.ReadFile(*pinFile)
	if err != nil {
		die(err)
	}
	o := Options{Pinned: ParsePinned(string(pb)), RequireAgent: !*noAgent}
	o.Allow = splitLines(string(ab))

	type job struct{ name, dir string }
	var jobs []job
	var cleanup []string
	defer func() {
		for _, d := range cleanup {
			os.RemoveAll(d)
		}
	}()
	if *idt != "" {
		jobs = append(jobs, job{*idt, *idt})
	}
	if *glob != "" {
		ms, err := filepath.Glob(*glob)
		if err != nil {
			die(err)
		}
		for _, m := range ms {
			d, err := os.MkdirTemp("", "builtmsi-")
			if err != nil {
				die(err)
			}
			cleanup = append(cleanup, d)
			if out, err := exec.Command("msidump", "-t", "-d", d, m).CombinedOutput(); err != nil {
				die(fmt.Errorf("msidump %s: %v\n%s (install msitools: apt-get install msitools)", m, err, out))
			}
			jobs = append(jobs, job{m, d})
		}
	}
	if len(jobs) == 0 {
		if *require {
			fmt.Fprintln(os.Stderr, "fitness-built-msi: FAIL: no built MSI found (-require)")
			os.Exit(1)
		}
		fmt.Println("fitness-built-msi: inactive (no built MSI; ADR-0006 A1 is not accepted until one is judged)")
		return
	}
	fails := 0
	for _, j := range jobs {
		tabs, err := LoadDir(j.dir)
		if err != nil {
			die(err)
		}
		vs := Judge(tabs, o)
		for _, v := range vs {
			fmt.Fprintf(os.Stderr, "fitness-built-msi: %s: %s\n", j.name, v)
		}
		fails += len(vs)
		if len(vs) == 0 {
			fmt.Printf("fitness-built-msi: %s: ok\n", j.name)
		}
	}
	if fails > 0 {
		fmt.Fprintf(os.Stderr, "fitness-built-msi: FAIL: %d violation(s)\n", fails)
		os.Exit(1)
	}
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}
