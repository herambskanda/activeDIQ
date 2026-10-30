package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Published advisories are kept in the repository as the audit copy of what went out:
// security/advisories/<CVE-ID>/advisory.md (the text published as the GitHub security advisory)
// and record.json (the CVE JSON 5 record submitted to the CVE List). The check makes D-0004 (a)
// mechanical: one CVE ID and one CVSS v3.1 score in both, published the day the fix shipped.
const (
	advisoriesDir = "security/advisories"
	templateDir   = "TEMPLATE"
	advisoryFile  = "advisory.md"
	recordFile    = "record.json"
)

var (
	cveIDRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	cweRe   = regexp.MustCompile(`^CWE-[0-9]+$`)
	dateRe  = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
)

// advisoryMeta is the front matter of advisory.md.
type advisoryMeta struct {
	CVE         string   `yaml:"cve"`
	GHSA        string   `yaml:"ghsa"`
	AdvisoryURL string   `yaml:"advisory_url"`
	Title       string   `yaml:"title"`
	Severity    string   `yaml:"severity"`
	CVSSVector  string   `yaml:"cvss_vector"`
	CVSSScore   *float64 `yaml:"cvss_score"`
	CWE         string   `yaml:"cwe"`
	Reported    string   `yaml:"reported"`
	Triaged     string   `yaml:"triaged"`
	FixShipped  string   `yaml:"fix_shipped"`
	Published   string   `yaml:"published"`
	FixedIn     []string `yaml:"fixed_in"`
	TargetMet   *bool    `yaml:"target_met"`
	Credit      []string `yaml:"credit"`
}

// cveRecord is the subset of the CVE JSON 5 record format we check
// (https://github.com/CVEProject/cve-schema).
type cveRecord struct {
	DataType    string `json:"dataType"`
	CVEMetadata struct {
		CVEID         string `json:"cveId"`
		State         string `json:"state"`
		DatePublished string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Affected []struct {
				Vendor   string `json:"vendor"`
				Product  string `json:"product"`
				Versions []struct {
					Status string `json:"status"`
				} `json:"versions"`
				DefaultStatus string `json:"defaultStatus"`
			} `json:"affected"`
			ProblemTypes []struct {
				Descriptions []struct {
					CWEID string `json:"cweId"`
				} `json:"descriptions"`
			} `json:"problemTypes"`
			Metrics    []map[string]json.RawMessage `json:"metrics"`
			References []struct {
				URL  string   `json:"url"`
				Tags []string `json:"tags"`
			} `json:"references"`
		} `json:"cna"`
	} `json:"containers"`
}

type cvss31Block struct {
	Version      string   `json:"version"`
	VectorString string   `json:"vectorString"`
	BaseScore    *float64 `json:"baseScore"`
	BaseSeverity string   `json:"baseSeverity"`
}

// splitFrontMatter returns the YAML between a leading "---" line and the next "---" line, and the body.
func splitFrontMatter(b []byte) ([]byte, []byte, bool) {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	if !bytes.HasPrefix(b, []byte("---\n")) {
		return nil, nil, false
	}
	fm, body, ok := bytes.Cut(b[4:], []byte("\n---\n"))
	return fm, body, ok
}

func day(s string) (time.Time, error) {
	if !dateRe.MatchString(s) {
		return time.Time{}, fmt.Errorf("%q is not YYYY-MM-DD", s)
	}
	return time.Parse("2006-01-02", s)
}

// checkAdvisory validates one advisory directory whose name must be its CVE ID. testIDs allows the
// CVE-1900- example prefix (CNA Rules 5.4), which only fixtures use.
func checkAdvisory(dir, name string, testIDs bool) []string {
	var v []string
	bad := func(f, format string, a ...any) {
		v = append(v, fmt.Sprintf("%s: %s", filepath.ToSlash(filepath.Join(dir, f)), fmt.Sprintf(format, a...)))
	}
	mdb, err := os.ReadFile(filepath.Join(dir, advisoryFile))
	if err != nil {
		bad(advisoryFile, "missing: %v", err)
		return v
	}
	recb, err := os.ReadFile(filepath.Join(dir, recordFile))
	if err != nil {
		bad(recordFile, "missing (every advisory ships with its CVE record): %v", err)
		return v
	}
	for _, f := range []struct {
		name string
		b    []byte
	}{{advisoryFile, mdb}, {recordFile, recb}} {
		if bytes.Contains(f.b, []byte("{{")) {
			bad(f.name, "unfilled {{PLACEHOLDER}} from the template")
		}
	}
	fm, body, ok := splitFrontMatter(mdb)
	if !ok {
		bad(advisoryFile, "no YAML front matter between --- lines")
		return v
	}
	var a advisoryMeta
	dec := yaml.NewDecoder(bytes.NewReader(fm))
	dec.KnownFields(true)
	if err := dec.Decode(&a); err != nil {
		bad(advisoryFile, "front matter: %v", err)
		return v
	}

	// --- the advisory on its own ---
	if !cveIDRe.MatchString(a.CVE) {
		bad(advisoryFile, "cve %q is not a CVE ID", a.CVE)
	} else if a.CVE != name {
		bad(advisoryFile, "cve %s does not match its directory %s", a.CVE, name)
	}
	if !testIDs && strings.HasPrefix(a.CVE, "CVE-1900-") {
		bad(advisoryFile, "%s uses the CVE-1900- test prefix (CNA Rules 5.4); never publish it", a.CVE)
	}
	if u, err := url.Parse(a.AdvisoryURL); err != nil || u.Scheme != "https" || u.Host == "" {
		bad(advisoryFile, "advisory_url %q is not an https URL (the public reference, CNA Rules 5.3)", a.AdvisoryURL)
	}
	if strings.TrimSpace(a.Title) == "" {
		bad(advisoryFile, "title is empty")
	}
	if !cweRe.MatchString(a.CWE) {
		bad(advisoryFile, "cwe %q is not CWE-<n> (CNA Rules 5.1.7)", a.CWE)
	}
	if len(a.FixedIn) == 0 {
		bad(advisoryFile, "fixed_in is empty: an advisory is published with the fix, so it names the fixed version")
	}
	score, serr := cvss31Base(a.CVSSVector)
	switch {
	case serr != nil:
		bad(advisoryFile, "cvss_vector: %v", serr)
	case a.CVSSScore == nil:
		bad(advisoryFile, "cvss_score missing")
	case *a.CVSSScore != score:
		bad(advisoryFile, "cvss_score %.1f does not match %s, which scores %.1f", *a.CVSSScore, a.CVSSVector, score)
	}
	if serr == nil && a.Severity != cvssSeverity(score) {
		bad(advisoryFile, "severity %q is not the CVSS v3.1 rating of %.1f (%q); we publish no other label", a.Severity, score, cvssSeverity(score))
	}
	dates := map[string]time.Time{}
	for _, d := range []struct{ k, s string }{{"reported", a.Reported}, {"triaged", a.Triaged}, {"fix_shipped", a.FixShipped}, {"published", a.Published}} {
		t, err := day(d.s)
		if err != nil {
			bad(advisoryFile, "%s: %v", d.k, err)
			continue
		}
		dates[d.k] = t
	}
	if len(dates) == 4 {
		if dates["triaged"].Before(dates["reported"]) || dates["fix_shipped"].Before(dates["triaged"]) {
			bad(advisoryFile, "dates out of order: reported <= triaged <= fix_shipped")
		}
		if !dates["published"].Equal(dates["fix_shipped"]) {
			bad(advisoryFile, "published %s is not the fix day %s: the advisory ships the same day as the fix (D-0004 a)", a.Published, a.FixShipped)
		}
		if days, ok := fixTargetDays[a.Severity]; ok {
			met := dates["fix_shipped"].Sub(dates["triaged"]) <= time.Duration(days)*24*time.Hour
			if a.TargetMet == nil {
				bad(advisoryFile, "target_met missing")
			} else if *a.TargetMet != met {
				bad(advisoryFile, "target_met: %v but %s target is %d days from triage and the fix took %d; state it honestly",
					*a.TargetMet, a.Severity, days, int(dates["fix_shipped"].Sub(dates["triaged"]).Hours()/24))
			}
		}
	}
	text := string(body)
	for _, want := range []string{a.CVE, a.CVSSVector} {
		if want != "" && !strings.Contains(text, want) {
			bad(advisoryFile, "the advisory text does not show %q; readers must see the same ID and vector as the record", want)
		}
	}
	if a.CVSSScore != nil && !strings.Contains(text, fmt.Sprintf("%.1f", *a.CVSSScore)) {
		bad(advisoryFile, "the advisory text does not show the score %.1f", *a.CVSSScore)
	}

	// --- the CVE record, against the advisory ---
	var r cveRecord
	if err := json.Unmarshal(recb, &r); err != nil {
		bad(recordFile, "not JSON: %v", err)
		return v
	}
	c := r.Containers.CNA
	if r.DataType != "CVE_RECORD" {
		bad(recordFile, "dataType %q is not CVE_RECORD", r.DataType)
	}
	if r.CVEMetadata.CVEID != a.CVE {
		bad(recordFile, "cveId %q differs from the advisory's %q", r.CVEMetadata.CVEID, a.CVE)
	}
	if r.CVEMetadata.State != "PUBLISHED" {
		bad(recordFile, "state %q: the repository keeps the record as published", r.CVEMetadata.State)
	}
	if pt, err := time.Parse(time.RFC3339, r.CVEMetadata.DatePublished); err != nil {
		bad(recordFile, "datePublished %q is not RFC 3339", r.CVEMetadata.DatePublished)
	} else if pt.UTC().Format("2006-01-02") != a.Published {
		bad(recordFile, "datePublished %s is not the advisory day %s: record and advisory go out the same day", pt.UTC().Format("2006-01-02"), a.Published)
	}
	var cvss []cvss31Block
	for _, m := range c.Metrics {
		for k, raw := range m {
			if !strings.HasPrefix(k, "cvss") {
				continue
			}
			if k != "cvssV3_1" {
				bad(recordFile, "metrics carries %s: we publish one CVSS, v3.1, and nothing else", k)
				continue
			}
			var b cvss31Block
			if err := json.Unmarshal(raw, &b); err != nil {
				bad(recordFile, "cvssV3_1: %v", err)
				continue
			}
			cvss = append(cvss, b)
		}
	}
	if len(cvss) != 1 {
		bad(recordFile, "has %d cvssV3_1 metrics; exactly one score goes in the record", len(cvss))
	} else {
		b := cvss[0]
		if b.VectorString != a.CVSSVector {
			bad(recordFile, "vectorString %q differs from the advisory's %q", b.VectorString, a.CVSSVector)
		}
		if b.BaseScore == nil || (a.CVSSScore != nil && *b.BaseScore != *a.CVSSScore) {
			bad(recordFile, "baseScore differs from the advisory's cvss_score")
		}
		if b.BaseSeverity != strings.ToUpper(a.Severity) {
			bad(recordFile, "baseSeverity %q differs from the advisory's %q", b.BaseSeverity, a.Severity)
		}
		if b.Version != "3.1" {
			bad(recordFile, "cvssV3_1.version %q is not 3.1", b.Version)
		}
	}
	en := false
	for _, d := range c.Descriptions {
		if (d.Lang == "en" || strings.HasPrefix(d.Lang, "en-")) && strings.TrimSpace(d.Value) != "" {
			en = true
			for _, who := range a.Credit {
				if who != "" && strings.Contains(d.Value, who) {
					bad(recordFile, "description credits %q; credits go in the advisory or the credits element (CNA Rules 5.2.4)", who)
				}
			}
		}
	}
	if !en {
		bad(recordFile, "no English description (CNA Rules 5.1.9, 5.2.5)")
	}
	affected := false
	for _, p := range c.Affected {
		if p.Vendor == "" || p.Product == "" {
			bad(recordFile, "affected entry without vendor and product (CNA Rules 5.1.3)")
		}
		for _, ver := range p.Versions {
			affected = affected || ver.Status == "affected"
		}
		affected = affected || p.DefaultStatus == "affected"
	}
	if !affected {
		bad(recordFile, "no product version with status affected (CNA Rules 5.1.4, 5.1.8)")
	}
	cweFound := false
	for _, pt := range c.ProblemTypes {
		for _, d := range pt.Descriptions {
			cweFound = cweFound || d.CWEID == a.CWE
		}
	}
	if !cweFound {
		bad(recordFile, "problemTypes does not carry the advisory's %s", a.CWE)
	}
	refFound := false
	for _, ref := range c.References {
		if ref.URL == a.AdvisoryURL {
			refFound = true
		}
		if strings.Contains(ref.URL, "cve.org/CVERecord?id="+a.CVE) {
			bad(recordFile, "references the CVE record itself (CNA Rules 5.1.10)")
		}
	}
	if !refFound {
		bad(recordFile, "references do not include the advisory %s (the public reference, CNA Rules 5.3.1)", a.AdvisoryURL)
	}
	return v
}

// CheckAdvisories validates the template's presence and every published advisory under root.
func CheckAdvisories(root string) []string {
	var v []string
	base := filepath.Join(root, advisoriesDir)
	for _, f := range []string{advisoryFile, recordFile} {
		if _, err := os.Stat(filepath.Join(base, templateDir, f)); err != nil {
			v = append(v, fmt.Sprintf("%s/%s/%s: advisory template missing: %v", advisoriesDir, templateDir, f, err))
		}
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return v
	}
	var names []string
	for _, e := range entries {
		switch {
		case e.Name() == templateDir || e.Name() == "README.md":
		case !e.IsDir():
			v = append(v, fmt.Sprintf("%s/%s: only <CVE-ID>/ directories, %s/ and README.md belong here", advisoriesDir, e.Name(), templateDir))
		default:
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		v = append(v, checkAdvisory(filepath.Join(base, n), n, false)...)
	}
	return v
}
