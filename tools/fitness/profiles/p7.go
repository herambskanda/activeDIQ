package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// Branches lists the branch names of the checkout: local heads and remote-tracking branches with
// the remote name removed. It returns an error when root is not a git checkout.
func Branches(root string) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git for-each-ref: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	seen := map[string]bool{}
	for _, ref := range strings.Fields(string(out)) {
		switch {
		case strings.HasPrefix(ref, "refs/heads/"):
			seen[strings.TrimPrefix(ref, "refs/heads/")] = true
		case strings.HasPrefix(ref, "refs/remotes/"):
			rest := strings.TrimPrefix(ref, "refs/remotes/")
			_, name, ok := strings.Cut(rest, "/")
			if !ok || name == "HEAD" {
				continue
			}
			seen[name] = true
		}
	}
	var names []string
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// checkP7 fails any branch other than main and factory/T-NNNN: no long-lived variant branches
// (ADR-0002 rule 1; PatchIQ kept per-customer branches).
func (c *Ctx) checkP7(branches []string) []Violation {
	var allow []*regexp.Regexp
	for _, p := range c.Cfg.BranchAllow {
		allow = append(allow, regexp.MustCompile("^(?:"+p+")$"))
	}
	var vs []Violation
	for _, b := range branches {
		ok := false
		for _, re := range allow {
			if re.MatchString(b) {
				ok = true
				break
			}
		}
		if !ok {
			vs = append(vs, Violation{"P7", "branch " + b, fmt.Sprintf("branch %q is not main or factory/T-NNNN; one codebase, no long-lived variant branches (ADR-0002 rule 1). Delete it, or rename the ticket branch", b)})
		}
	}
	return vs
}

func runGit(root string, args ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput()
	return string(out), err
}
