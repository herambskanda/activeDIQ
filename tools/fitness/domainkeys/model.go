package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Entity is what the domain model's heading line says about one entity:
//
//	### DM-18 ChangeRecord · D · append-only · owner `directory/inventory`
//
// Kind is the single letter the heading names, or "" when the heading is not exactly one letter
// ("P (platform work) and T (tenant work)"): the kind cross-check skips those.
type Entity struct {
	ID         string
	Name       string
	Kind       string
	AppendOnly bool // "append-only" or "insert-only"
}

var headingPattern = regexp.MustCompile("^### (DM-[0-9]{2}) (\\S+) · (.+)$")

// LoadEntities reads the entity headings of the domain model. A missing file is an error: the check
// has no table-kind truth without it, and skipping silently would turn the cross-check off.
func LoadEntities(path string) (map[string]Entity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("domain model: %w", err)
	}
	defer f.Close()
	out := map[string]Entity{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		m := headingPattern.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		parts := strings.Split(m[3], " · ")
		e := Entity{ID: m[1], Name: m[2]}
		if k := strings.TrimSpace(parts[0]); len(k) == 1 && strings.Contains("PTDR", k) {
			e.Kind = k
		}
		for _, p := range parts[1:] {
			if p = strings.TrimSpace(p); p == "append-only" || p == "insert-only" {
				e.AppendOnly = true
			}
		}
		out[e.ID] = e
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("domain model: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("domain model %s: no `### DM-nn Name · kind · …` entity heading found", path)
	}
	return out, nil
}
