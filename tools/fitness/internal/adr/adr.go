// Package adr reads the status of an ADR from its YAML frontmatter. The fitness jobs share it so
// "an exception cites a ratified or accepted ADR" means the same thing in every job.
package adr

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Status reads the status key from the frontmatter of the ADR file.
func Status(file string) (string, error) {
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

// Grants reports whether a status lets an ADR grant an exception.
func Grants(status string) bool { return status == "ratified" || status == "accepted" }
