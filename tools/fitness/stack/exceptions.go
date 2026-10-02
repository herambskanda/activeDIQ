package main

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// checkExceptions is F5 (ADR-0001 rule 5): every manifest exception names an ADR file in the
// decisions directory whose frontmatter status is ratified or accepted, and the thing it excepts
// exists, so a stale entry cannot hide a real one. Undeclared third_party/ directories fail too.
func (c *Ctx) checkExceptions() []Violation {
	var vs []Violation
	add := func(msg string) { vs = append(vs, Violation{"F5", c.ManifestPath, msg}) }
	for _, e := range c.M.allExceptions() {
		switch {
		case strings.TrimSpace(e.adr) == "":
			add(e.label + " names no ADR; every exception cites a ratified or accepted ADR file in " + c.M.DecisionsDir)
		case e.adr != path.Base(e.adr) || !strings.HasSuffix(e.adr, ".md"):
			add(fmt.Sprintf("%s cites %q, which is not an ADR file name inside %s", e.label, e.adr, c.M.DecisionsDir))
		default:
			status, err := adrStatus(filepath.Join(c.abs(c.M.DecisionsDir), e.adr))
			switch {
			case os.IsNotExist(err):
				add(fmt.Sprintf("%s cites %s, which does not exist in %s", e.label, e.adr, c.M.DecisionsDir))
			case err != nil:
				add(fmt.Sprintf("%s cites %s, which cannot be read: %v", e.label, e.adr, err))
			case status != "ratified" && status != "accepted":
				add(fmt.Sprintf("%s cites %s, whose status is %q; only a ratified or accepted ADR can grant an exception", e.label, e.adr, status))
			}
		}
		if e.path != "" {
			fi, err := os.Stat(c.abs(e.path))
			switch {
			case err != nil:
				add(fmt.Sprintf("%s: the path does not exist; remove the stale entry", e.label))
			case e.kind == "buildScripts" && fi.IsDir():
				add(fmt.Sprintf("%s: a build script entry names one file, not a directory", e.label))
			}
		}
	}
	declared := map[string]bool{}
	for _, e := range c.M.Exceptions.ThirdParty {
		declared[path.Clean(e.Path)] = true
	}
	seen := map[string]bool{}
	for _, f := range c.Files {
		parts := strings.Split(f, "/")
		if len(parts) < 3 || parts[0] != "third_party" {
			continue
		}
		dir := parts[0] + "/" + parts[1]
		if !declared[dir] && !seen[dir] {
			seen[dir] = true
			vs = append(vs, Violation{"F5", dir, "third_party entry is not declared in manifest exceptions.thirdParty (copied code needs a ratified ADR and a LICENSE file)"})
		}
	}
	return vs
}

// adrStatus reads the status key from an ADR's YAML frontmatter.
func adrStatus(file string) (string, error) {
	fh, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != "---" {
		return "", fmt.Errorf("no frontmatter")
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "---" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "status" {
			if i := strings.Index(v, "#"); i >= 0 {
				v = v[:i]
			}
			return strings.Trim(strings.TrimSpace(v), `"'`), nil
		}
	}
	return "", fmt.Errorf("frontmatter has no status")
}
