// Command contractfreeze is U4 of fitness-profiles (ADR-0002, T-2418): the contract-freeze gate.
//
// Clause: skenzeriq/agent/v1 may carry the marker line `// contract: frozen` only while
// knowledge/development/architecture/agent-contract-review.md exists and has `status: accepted`
// in its frontmatter. A frozen contract without the accepted UEM-owner review fails.
//
//	contractfreeze [-repo .]
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	protoDir   = "proto/skenzeriq/agent/v1"
	reviewFile = "knowledge/development/architecture/agent-contract-review.md"
	clause     = "ADR-0002 U4 (contract-freeze gate)"
)

var markerRe = regexp.MustCompile(`^\s*//\s*contract:\s*frozen\s*$`)

// frozenFiles lists the .proto files under protoDir that carry the freeze marker.
func frozenFiles(root string) ([]string, error) {
	ms, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(protoDir), "*.proto"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range ms {
		f, err := os.Open(m)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if markerRe.MatchString(sc.Text()) {
				rel, _ := filepath.Rel(root, m)
				out = append(out, filepath.ToSlash(rel))
				break
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// reviewStatus returns the frontmatter status of the review file, "" when absent or without one.
func reviewStatus(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(reviewFile)))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return "", nil
	}
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) == "---" {
			break
		}
		if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "status" {
			return strings.Trim(strings.TrimSpace(v), `"'`), nil
		}
	}
	return "", nil
}

// check returns the violations for the repository at root; empty means U4 passes.
func check(root string) ([]string, error) {
	frozen, err := frozenFiles(root)
	if err != nil {
		return nil, err
	}
	if len(frozen) == 0 {
		return nil, nil
	}
	st, err := reviewStatus(root)
	if err != nil {
		return nil, err
	}
	if st == "accepted" {
		return nil, nil
	}
	have := "absent or without a status"
	if st != "" {
		have = "status: " + st
	}
	return []string{fmt.Sprintf("%s: %s is marked `// contract: frozen` but %s is %s; the contract cannot be frozen until the UEM owners' review is `status: accepted`", clause, strings.Join(frozen, ", "), reviewFile, have)}, nil
}

func main() {
	repo := flag.String("repo", ".", "repository root")
	flag.Parse()
	vs, err := check(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "contractfreeze:", err)
		os.Exit(2)
	}
	for _, v := range vs {
		fmt.Fprintln(os.Stderr, "FAIL", v)
	}
	if len(vs) > 0 {
		os.Exit(1)
	}
	fmt.Println("contractfreeze: U4 ok")
}
