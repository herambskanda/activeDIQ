// Package main is `make vuln-scan` (T-0010): govulncheck over the product module, a fail-closed
// verdict, and an expiring allow list (tools/ci/vuln-allow.json).
//
// govulncheck itself is pinned in tools/vulntools (a tools module, never the product go.mod). Its
// JSON stream is read here because the text mode cannot be combined with an allow list, and
// because every way govulncheck can fail to answer (database unreachable, build error, crash)
// must be a non-zero exit with a named cause: a scan that did not run is not a scan that passed.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Entry is one allowed finding. All four fields are required.
type Entry struct {
	OSV     string `json:"osv"`
	Reason  string `json:"reason"`
	Ticket  string `json:"ticket"`
	Expires string `json:"expires"`
}

// AllowFile is the shape of tools/ci/vuln-allow.json.
type AllowFile struct {
	Entries []Entry `json:"entries"`
}

var (
	osvRe    = regexp.MustCompile(`^(GO|GHSA|CVE|PYSEC|OSV)-[A-Za-z0-9-]+$`)
	ticketRe = regexp.MustCompile(`^T-\d{4,}$`)
)

// ParseAllow reads the allow list. Unknown fields, a malformed id, a missing reason, a ticket that
// is not T-NNNN, a bad date and a duplicate id are all errors.
func ParseAllow(data []byte) (AllowFile, error) {
	var f AllowFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, fmt.Errorf("allow list is not valid: %w", err)
	}
	seen := map[string]bool{}
	for i, e := range f.Entries {
		at := fmt.Sprintf("entry %d (%q)", i+1, e.OSV)
		switch {
		case !osvRe.MatchString(e.OSV):
			return f, fmt.Errorf("%s: osv must be an OSV id such as GO-2026-0001", at)
		case seen[e.OSV]:
			return f, fmt.Errorf("%s: duplicate osv", at)
		case strings.TrimSpace(e.Reason) == "":
			return f, fmt.Errorf("%s: reason is required", at)
		case !ticketRe.MatchString(e.Ticket):
			return f, fmt.Errorf("%s: ticket must look like T-0123", at)
		}
		if _, err := time.Parse(time.DateOnly, e.Expires); err != nil {
			return f, fmt.Errorf("%s: expires must be a YYYY-MM-DD date", at)
		}
		seen[e.OSV] = true
	}
	return f, nil
}

// Finding is a vulnerability the code calls.
type Finding struct {
	OSV      string
	Module   string
	Version  string
	Fixed    string
	Function string // package.Function of the vulnerable symbol that is reached
	Summary  string
}

type message struct {
	OSV *struct {
		ID      string `json:"id"`
		Summary string `json:"summary"`
	} `json:"osv"`
	Finding *struct {
		OSV          string `json:"osv"`
		FixedVersion string `json:"fixed_version"`
		Trace        []struct {
			Module   string `json:"module"`
			Version  string `json:"version"`
			Package  string `json:"package"`
			Function string `json:"function"`
		} `json:"trace"`
	} `json:"finding"`
}

// ParseStream reads govulncheck's -format json stream and returns the called vulnerabilities, one
// per OSV id and module (the first reached symbol is kept), sorted. Findings that are only imported
// or only required are not returned: govulncheck's own default fails on called vulnerabilities and
// reports the rest as information, and so do we.
func ParseStream(r io.Reader) ([]Finding, error) {
	dec := json.NewDecoder(r)
	summaries := map[string]string{}
	var called []Finding
	seen := map[string]bool{}
	for {
		var m message
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("govulncheck output is not valid JSON: %w", err)
		}
		if m.OSV != nil {
			summaries[m.OSV.ID] = m.OSV.Summary
		}
		if m.Finding == nil || len(m.Finding.Trace) == 0 {
			continue
		}
		t := m.Finding.Trace[0]
		if t.Function == "" {
			continue
		}
		key := m.Finding.OSV + "\x00" + t.Module
		if seen[key] {
			continue
		}
		seen[key] = true
		called = append(called, Finding{OSV: m.Finding.OSV, Module: t.Module, Version: t.Version,
			Fixed: m.Finding.FixedVersion, Function: t.Package + "." + t.Function})
	}
	for i := range called {
		called[i].Summary = summaries[called[i].OSV]
	}
	sort.Slice(called, func(i, j int) bool {
		if called[i].OSV != called[j].OSV {
			return called[i].OSV < called[j].OSV
		}
		return called[i].Module < called[j].Module
	})
	return called, nil
}

// Verdict applies the allow list to the findings as of today and returns one message per problem.
// A finding fails unless an unexpired entry names its OSV id; an expired entry fails whether or not
// the finding is still there; an entry that matches no finding fails (delete it, the fix landed).
func Verdict(findings []Finding, allow AllowFile, today time.Time) []string {
	day := today.Format(time.DateOnly)
	listed := map[string]bool{}
	for _, e := range allow.Entries {
		listed[e.OSV] = true
	}
	hit := map[string]bool{}
	var problems []string
	for _, f := range findings {
		hit[f.OSV] = true
		if listed[f.OSV] { // covered; an expired entry is reported once, below
			continue
		}
		fix := "no fix released"
		if f.Fixed != "" {
			fix = "fixed in " + f.Fixed
		}
		problems = append(problems, fmt.Sprintf("%s: called through %s in %s %s (%s). %s. Upgrade, or add an entry to tools/ci/vuln-allow.json with a reason, a ticket and an expiry",
			f.OSV, f.Function, f.Module, f.Version, fix, f.Summary))
	}
	for _, e := range allow.Entries {
		switch {
		case e.Expires < day:
			problems = append(problems, fmt.Sprintf("%s: allow entry expired on %s (ticket %s). Fix the finding or renew the entry with a new reason and date", e.OSV, e.Expires, e.Ticket))
		case !hit[e.OSV]:
			problems = append(problems, fmt.Sprintf("%s: allow entry (ticket %s) matches no finding any more. Delete it", e.OSV, e.Ticket))
		}
	}
	sort.Strings(problems)
	return problems
}

// ErrScan marks a failure to obtain an answer from govulncheck at all.
var ErrScan = errors.New("govulncheck did not complete")
