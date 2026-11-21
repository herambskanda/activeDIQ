package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// exemptPath is the exemption registry of ADR-0003 (migration backfills and similar). M11 judges it.
const exemptPath = "tools/fitness/modules/exempt.json"

// noExemption lists the rules an entry may never target: blueprint §2.5 and ADR-0003 M1, M2, M3, M6
// and M9 admit no exemption (ADR-0013 decision 5). Narrowing one takes a superseding ADR.
var noExemption = map[string]bool{"2.5": true, "M1": true, "M2": true, "M3": true, "M6": true, "M9": true}

// now is the clock M11 reads expiry against; tests replace it.
var now = time.Now

type exemption struct {
	Rule    string `json:"rule"`
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
	Ticket  string `json:"ticket"`
	Expires string `json:"expires"` // YYYY-MM-DD
}

// normaliseRule maps "§2.5", "rule 2.5", "m3" and similar spellings to "2.5" or "M3".
func normaliseRule(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "§")
	s = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(s), "rule"))
	s = strings.TrimPrefix(s, "§")
	return strings.ToUpper(strings.TrimSpace(s))
}

// checkExemptions is M11: every entry has a reason, a ticket and a future expiry, and none targets a
// rule that admits no exemption. A missing file is an empty registry.
func checkExemptions(root string) ([]Violation, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(exemptPath)))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []exemption
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("%s: %w", exemptPath, err)
	}
	var vs []Violation
	for i, e := range entries {
		pos := fmt.Sprintf("%s:entry %d", exemptPath, i+1)
		add := func(f string, a ...any) { vs = append(vs, Violation{Rule: "M11", Pos: pos, Msg: fmt.Sprintf(f, a...)}) }
		if r := normaliseRule(e.Rule); r == "" {
			add("entry names no rule")
		} else if noExemption[r] {
			add("entry targets %s, which admits no exemption (ADR-0003 M11, ADR-0013 decision 5); a narrower escape needs a superseding ADR", e.Rule)
		}
		if strings.TrimSpace(e.Reason) == "" {
			add("entry has no reason")
		}
		if strings.TrimSpace(e.Ticket) == "" {
			add("entry has no ticket")
		}
		exp, perr := time.Parse("2006-01-02", e.Expires)
		switch {
		case perr != nil:
			add("entry expiry %q is not a YYYY-MM-DD date", e.Expires)
		case !exp.After(now().Truncate(24 * time.Hour)):
			add("entry expired on %s", e.Expires)
		}
	}
	return vs, nil
}
