package main

import (
	"fmt"
	"path/filepath"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
)

// Case is one record whose output an oracle checks: what the implementation (or, before one exists,
// the corpus's own golden value) produced for an input.
type Case struct {
	Record corpus.Record
	Input  corpus.Input // the record's primary input (arg "value" unless an oracle says otherwise)
	Output string       // the rendered text
	HexOut string       // bytes_hex, for the codecs
	Source string       // "report <impl>" or "golden"
}

// loadCases returns every record of unit that has the wanted expectation key, with its output taken
// from the implementation reports in reportsDir (source "report") or from the corpus itself
// (source "golden"). Records that expect an error produce no output and are not oracle cases: a
// rejection is checked by the corpus run, not by an independent parser.
func loadCases(root, unit, source, reportsDir string) ([]Case, *corpus.File, error) {
	f, err := corpus.Load(filepath.Join(root, filepath.FromSlash(corpus.Dir)), unit)
	if err != nil {
		return nil, nil, err
	}
	var actual map[string]corpus.Ran
	label := "golden"
	if source == "auto" { // an implementation's reports when there are any for this unit, else the corpus's own values
		source = "golden"
		if reps, err := corpus.ReadReports(reportsDir); err == nil {
			for _, r := range reps {
				if r.Unit == unit {
					source = "report"
				}
			}
		}
	}
	switch source {
	case "golden":
	case "report":
		reps, err := corpus.ReadReports(reportsDir)
		if err != nil {
			return nil, nil, err
		}
		found := false
		for _, r := range reps {
			if r.Unit != unit {
				continue
			}
			if r.CorpusSHA != f.SHA256 {
				return nil, nil, fmt.Errorf("the %s report of %s was produced against a different corpus file", unit, r.Impl)
			}
			found = true
			label = "report " + r.Impl
			actual = map[string]corpus.Ran{}
			for _, ran := range r.Ran {
				actual[ran.ID] = ran
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("no corpus report for unit %s in %s: run the implementation's corpus test first (make fitness-corpus keeps reports with -report-dir)", unit, reportsDir)
		}
	default:
		return nil, nil, fmt.Errorf("unknown -source %q (golden, report or auto)", source)
	}
	var out []Case
	for _, r := range f.Records {
		if !r.Runtime() {
			continue
		}
		c := Case{Record: r, Source: label}
		if in, err := r.Arg("value"); err == nil {
			c.Input = in
		}
		if actual != nil {
			ran, ok := actual[r.ID]
			if !ok {
				return nil, nil, fmt.Errorf("record %s has no entry in the %s report", r.ID, unit)
			}
			if ran.Actual.Render != nil {
				c.Output = *ran.Actual.Render
			}
			if ran.Actual.BytesHex != nil {
				c.HexOut = *ran.Actual.BytesHex
			}
			if ran.Actual.Render == nil && ran.Actual.BytesHex == nil {
				continue
			}
		} else {
			if v, ok := r.Expect["render"]; ok {
				c.Output = unquote(v)
			} else if v, ok := r.Expect["bytes_hex"]; ok {
				c.HexOut = unquote(v)
			} else {
				continue
			}
		}
		out = append(out, c)
	}
	return out, f, nil
}
