package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// dbHint names the likely cause and the override. The scan never skips: a run that could not read
// the database is a failed run.
func dbHint() string {
	db := os.Getenv("GOVULNDB")
	if db == "" {
		db = "https://vuln.go.dev"
	}
	return "cause: the vulnerability database (" + db + ") could not be read, or govulncheck failed. " +
		"Check the network, or point GOVULNDB at a mirror (an https:// URL or a file:// path to a vulndb copy). " +
		"The scan never skips: fix the cause and re-run"
}

func main() {
	root := flag.String("root", ".", "directory holding the Go module to scan (go.mod)")
	allowPath := flag.String("allow", "tools/ci/vuln-allow.json", "allow list; relative paths are taken from the working directory")
	toolsDir := flag.String("tools", "tools/vulntools", "tools module that pins govulncheck; relative paths are taken from the working directory")
	today := flag.String("today", "", "override today's date (YYYY-MM-DD); for tests and proofs")
	flag.Parse()
	if err := run(*root, *allowPath, *toolsDir, *today); err != nil {
		fmt.Fprintln(os.Stderr, "vuln-scan:", err)
		os.Exit(1)
	}
}

func run(root, allowPath, toolsDir, todayFlag string) error {
	now := time.Now().UTC()
	if todayFlag != "" {
		d, err := time.Parse(time.DateOnly, todayFlag)
		if err != nil {
			return fmt.Errorf("-today must be YYYY-MM-DD: %w", err)
		}
		now = d
	}
	raw, err := os.ReadFile(allowPath)
	if err != nil {
		return fmt.Errorf("cannot read the allow list: %w", err)
	}
	allow, err := ParseAllow(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", allowPath, err)
	}
	absTools, err := filepath.Abs(toolsDir)
	if err != nil {
		return err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	bin, err := exec.Command("go", "-C", absTools, "tool", "-n", "govulncheck").Output()
	if err != nil {
		return fmt.Errorf("cannot build the pinned govulncheck from %s: %w%s", toolsDir, err, stderrOf(err))
	}
	args := []string{"-format", "json"}
	if db := os.Getenv("GOVULNDB"); db != "" {
		args = append(args, "-db", db)
	}
	args = append(args, "./...")
	cmd := exec.Command(strings.TrimSpace(string(bin)), args...)
	cmd.Dir = absRoot
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w (%v): %s\n%s", ErrScan, err, strings.TrimSpace(tail(errb.String(), 1500)), dbHint())
	}
	findings, err := ParseStream(&out)
	if err != nil {
		return fmt.Errorf("%w: %v\n%s", ErrScan, err, dbHint())
	}
	problems := Verdict(findings, allow, now)
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, p)
		}
		return fmt.Errorf("%d problem(s): %d called vulnerabilit(ies), %d allow entr(ies)", len(problems), len(findings), len(allow.Entries))
	}
	fmt.Printf("vuln-scan: ok (%d called vulnerabilit(ies), all covered by unexpired allow entries; %d entr(ies) in %s)\n",
		len(findings), len(allow.Entries), allowPath)
	return nil
}

func stderrOf(err error) string {
	if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
		return ": " + strings.TrimSpace(string(ee.Stderr))
	}
	return ""
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
