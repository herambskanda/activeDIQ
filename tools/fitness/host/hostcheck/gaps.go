package hostcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Gap is a case the product cannot yet satisfy, with the ticket that delivers the control. It is a
// ratchet, not a waiver: while the case fails the build tolerates it; once it passes the entry must go.
type Gap struct {
	Case    string `json:"case"`
	Profile string `json:"profile"`
	Ticket  string `json:"ticket"`
	Reason  string `json:"reason"`
}

// LoadGaps reads the gap list for one profile. A missing file is an empty list.
func LoadGaps(path, profile string) (map[string]Gap, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var all struct {
		Gaps []Gap `json:"gaps"`
	}
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m := map[string]Gap{}
	for _, g := range all.Gaps {
		if g.Case == "" || g.Ticket == "" || g.Reason == "" || g.Profile == "" {
			return nil, fmt.Errorf("%s: every gap needs case, profile, ticket and reason: %+v", path, g)
		}
		known := false
		for _, c := range Cases {
			known = known || c == g.Case
		}
		if !known {
			return nil, fmt.Errorf("%s: unknown case %q", path, g.Case)
		}
		if g.Profile == profile {
			m[g.Case] = g
		}
	}
	return m, nil
}

// Verdict is a Result after the gap list is applied.
type Verdict struct {
	Result
	Gap   *Gap
	Stale bool // a known gap that passes
}

// Judge applies the gap list.
func Judge(rs []Result, gaps map[string]Gap) []Verdict {
	var out []Verdict
	for _, r := range rs {
		v := Verdict{Result: r}
		if g, ok := gaps[r.Case]; ok {
			v.Gap = &g
			v.Stale = len(r.Failures) == 0 && r.Inactive == ""
		}
		out = append(out, v)
	}
	return out
}

// Findings are the verdict's failures as self-contained lines, `FAIL <case>: <failure>`, for the
// pre-merge gate (factory/lib/premerge.mjs), which compares findings line by line (T-0973). A tolerated
// gap contributes none.
func (v Verdict) Findings() []string {
	if v.Stale {
		return []string{fmt.Sprintf("FAIL %s: known gap for %s no longer fails: delete it from known-gaps.json", v.Case, v.Gap.Ticket)}
	}
	if v.Gap != nil {
		return nil
	}
	var out []string
	for _, f := range v.Failures {
		out = append(out, fmt.Sprintf("FAIL %s: %s", v.Case, f))
	}
	return out
}

// Fails reports whether this verdict fails the build.
func (v Verdict) Fails() bool {
	if v.Gap != nil {
		return v.Stale
	}
	return len(v.Failures) > 0
}

// Line is the one-line report; failures follow indented.
func (v Verdict) Line() string {
	switch {
	case v.Stale:
		return fmt.Sprintf("FAIL   %-30s known gap for %s no longer fails: delete it from known-gaps.json", v.Case, v.Gap.Ticket)
	case v.Gap != nil && len(v.Failures) > 0:
		return fmt.Sprintf("GAP    %-30s tolerated until %s (%s)\n         - %s", v.Case, v.Gap.Ticket, v.Gap.Reason, strings.Join(v.Failures, "\n         - "))
	case v.Gap != nil:
		return fmt.Sprintf("GAP    %-30s %s (inactive: %s)", v.Case, v.Gap.Ticket, v.Inactive)
	case len(v.Failures) > 0:
		return fmt.Sprintf("FAIL   %-30s\n         - %s", v.Case, strings.Join(v.Failures, "\n         - "))
	case v.Inactive != "":
		return fmt.Sprintf("INACTIVE %-28s %s", v.Case, v.Inactive)
	}
	return fmt.Sprintf("ok     %-30s", v.Case)
}
