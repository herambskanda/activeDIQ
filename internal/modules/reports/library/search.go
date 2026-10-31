package library

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/skenzeriq/activediq/internal/platform/report"
)

// crossRow is one line of crosswalk.tsv: a ManageEngine report name (exact as ME lists it, spec 6.2),
// the report that answers it and the preset. The file covers every name of spec 6.2, shipped or not, so
// an admin who searches an ME name always gets an answer: the report, or the honest "not yet".
//
// Columns (tab separated): ME name, report ID, report title, preset ID ("-" when the report is not
// shipped yet), pending note (empty when the preset ships). A shipped report with a pending note has no
// such preset yet and the note says what it waits for.
type crossRow struct {
	Name, Report, Title, Preset, Pending string
}

func loadCrosswalk(fsys fs.FS) ([]crossRow, error) {
	raw, err := fs.ReadFile(fsys, "crosswalk.tsv")
	if err != nil {
		return nil, fmt.Errorf("library: no crosswalk.tsv: %w", err)
	}
	var out []crossRow
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) == 4 {
			f = append(f, "")
		}
		if len(f) != 5 || f[0] == "" || f[1] == "" || f[2] == "" || f[3] == "" {
			return nil, fmt.Errorf("library: crosswalk.tsv line %d needs 5 tab-separated fields", n)
		}
		key := normalize(f[0])
		if seen[key] {
			return nil, fmt.Errorf("library: crosswalk.tsv line %d: %q is listed twice", n, f[0])
		}
		seen[key] = true
		out = append(out, crossRow{f[0], f[1], f[2], f[3], f[4]})
	}
	return out, sc.Err()
}

// checkCrosswalk makes the crosswalk and the presets say the same thing, both ways.
func (l *Library) checkCrosswalk() error {
	known := map[string]bool{}
	for _, r := range l.cross {
		known[r.Report+"/"+r.Preset+"/"+normalize(r.Name)] = true
		es := l.byID[report.DefinitionID(r.Report)]
		if len(es) == 0 {
			if r.Preset != "-" || r.Pending != "" {
				return fmt.Errorf("library: crosswalk %q: report %s is not shipped, so its preset is \"-\" and it has no pending note", r.Name, r.Report)
			}
			continue
		}
		latest := es[len(es)-1].def
		pr, ok := latest.Preset(r.Preset)
		switch {
		case r.Pending != "" && ok:
			return fmt.Errorf("library: crosswalk %q is marked pending but %s has preset %s", r.Name, r.Report, r.Preset)
		case r.Pending != "":
		case !ok || r.Preset == "-":
			return fmt.Errorf("library: crosswalk %q names preset %q, which %s does not have", r.Name, r.Preset, r.Report)
		case !slices.ContainsFunc(pr.Names, func(n string) bool { return normalize(n) == normalize(r.Name) }):
			return fmt.Errorf("library: crosswalk %q is not among the names of %s/%s", r.Name, r.Report, r.Preset)
		}
		if latest.Title != r.Title {
			return fmt.Errorf("library: crosswalk %q gives the title %q, the definition says %q", r.Name, r.Title, latest.Title)
		}
	}
	for _, id := range l.order {
		es := l.byID[id]
		for _, p := range es[len(es)-1].def.Presets {
			for _, n := range p.Names {
				if !known[string(id)+"/"+p.ID+"/"+normalize(n)] {
					return fmt.Errorf("library: preset %s/%s answers %q, which crosswalk.tsv does not list", id, p.ID, n)
				}
			}
		}
	}
	return nil
}

var folder = cases.Fold()

// normalize makes two spellings of an ME name equal: Unicode NFC, case folded, every run of
// non-letters-or-digits a single space ("Locked-Out Users" and "Locked-out Users" are one name).
func normalize(s string) string {
	s = folder.String(norm.NFC.String(s))
	var b strings.Builder
	space := true
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			space = false
		} else if !space {
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSuffix(b.String(), " ")
}

// Match is one search answer: where an ME name (or a title) leads.
type Match struct {
	// Name is the ManageEngine name that matched ("" when the report title or ID matched).
	Name   string
	Report report.DefinitionID
	Title  string
	// Preset is the preset to open ("" opens the report's default preset). Empty when Available is false.
	Preset string
	// Available is false when the report, or the preset, is not shipped yet.
	Available bool
	// Pending says what an unavailable answer waits for ("" when it is not pending).
	Pending string
	// AlsoKnownAs are the ME names of the matched preset, for the "Also known as" line (FR-02).
	AlsoKnownAs []string
	Score       int
}

// Resolve returns where an exact ManageEngine name leads (spelling, case and hyphenation do not matter).
func (l *Library) Resolve(name string) (Match, bool) {
	key := normalize(name)
	for _, r := range l.cross {
		if normalize(r.Name) == key {
			return l.match(r, 100), true
		}
	}
	return Match{}, false
}

func (l *Library) match(r crossRow, score int) Match {
	m := Match{Name: r.Name, Report: report.DefinitionID(r.Report), Title: r.Title, Pending: r.Pending, Score: score}
	es := l.byID[m.Report]
	if len(es) == 0 || r.Pending != "" {
		return m
	}
	m.Available, m.Preset = true, r.Preset
	if p, ok := es[len(es)-1].def.Preset(r.Preset); ok {
		m.AlsoKnownAs = slices.Clone(p.Names)
	}
	return m
}

// Search finds reports by ManageEngine name, report title or report ID. An exact ME name ranks first, then
// a name that starts with the query, then names or titles that hold every word of it. Order is by score,
// then report ID, then name, so the result is stable. limit <= 0 means 20.
func (l *Library) Search(query string, limit int) []Match {
	if limit <= 0 {
		limit = 20
	}
	q := normalize(query)
	if q == "" {
		return nil
	}
	words := strings.Fields(q)
	hasAll := func(s string) bool {
		for _, w := range words {
			if !strings.Contains(s, w) {
				return false
			}
		}
		return true
	}
	var out []Match
	reportHit := map[string]bool{}
	for _, r := range l.cross {
		name := normalize(r.Name)
		switch {
		case name == q:
			out = append(out, l.match(r, 100))
		case strings.HasPrefix(name, q):
			out = append(out, l.match(r, 80))
		case hasAll(name):
			out = append(out, l.match(r, 60))
		case !reportHit[r.Report] && (hasAll(normalize(r.Title)) || normalize(r.Report) == q):
			reportHit[r.Report] = true
			m := l.match(r, 40)
			m.Name, m.Preset, m.AlsoKnownAs = "", "", nil
			if es := l.byID[m.Report]; len(es) > 0 {
				d := es[len(es)-1].def
				m.Available, m.Pending, m.Preset = true, "", d.Presets[0].ID
				m.AlsoKnownAs = slices.Clone(d.Presets[0].Names)
			}
			out = append(out, m)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Report != b.Report {
			return a.Report < b.Report
		}
		return a.Name < b.Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Names returns every ManageEngine name in the crosswalk, in file order.
func (l *Library) Names() []string {
	out := make([]string, len(l.cross))
	for i, r := range l.cross {
		out[i] = r.Name
	}
	return out
}
