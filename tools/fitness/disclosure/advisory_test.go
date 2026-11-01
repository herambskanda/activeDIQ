package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const repoTemplate = "../../../" + advisoriesDir + "/" + templateDir

// Reference scores from the FIRST CVSS v3.1 calculator (https://www.first.org/cvss/calculator/3.1).
func TestCVSS31Base(t *testing.T) {
	for vec, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H": 9.1,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	} {
		got, err := cvss31Base(vec)
		if err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", vec, got, err, want)
		}
	}
	for _, bad := range []string{
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // wrong version
		"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",              // no prefix
		"CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",     // out of order
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",         // missing metric
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P", // temporal metric
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     // bad value
	} {
		if _, err := cvss31Base(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	for s, want := range map[float64]string{0: "none", 0.1: "low", 3.9: "low", 4.0: "medium", 6.9: "medium", 7.0: "high", 8.9: "high", 9.0: "critical", 10: "critical"} {
		if got := cvssSeverity(s); got != want {
			t.Errorf("severity(%v) = %s, want %s", s, got, want)
		}
	}
}

// example fills the repository template the way the runbook says to (worked example, CNA Rules
// 5.4 test prefix). It proves the template and the gate agree.
var example = map[string]string{
	"CVE_ID": "CVE-1900-0001", "GHSA_ID": "GHSA-xxxx-xxxx-xxxx", "TITLE": "LDAP filter injection in user search",
	"SEVERITY": "critical", "SEVERITY_UPPER": "CRITICAL", "CVSS_VECTOR": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	"CVSS_SCORE": "9.8", "CWE_ID": "CWE-90", "CWE_NAME": "Improper Neutralization of Special Elements used in an LDAP Query",
	"REPORTED": "2026-11-02", "TRIAGED": "2026-11-04", "FIX_DAY": "2026-11-12", "PUBLISH_TIME": "15:00:00",
	"FIXED_IN": "1.0.1", "FIRST_AFFECTED": "1.0.0", "AFFECTED": "1.0.0", "TARGET_MET": "true",
	"CREDIT": "Example Researcher", "CREDIT_LINE": "Reported by Example Researcher.", "ASSIGNER": "skenzeriq",
	"CVE_DESCRIPTION": "LDAP filter injection in the user search of activeDIQ 1.0.0 lets an unauthenticated attacker read directory objects.",
	"EXPLOITED":       "Not known", "WHO_IS_AFFECTED": "All installations of 1.0.0.", "IMPACT": "Directory read.",
	"UPDATE_NOTE": "Automatic updates apply it.", "WORKAROUND": "No workaround; update.", "DETECTION": "Review search audit events.",
	"TARGET_STATEMENT": "Fixed within our critical target of 14 days from triage.", "DISCOVERY": "EXTERNAL",
	"FIX_COMMIT_URL": "https://github.com/herambskanda/activeDIQ/commit/0000000",
}

func fill(t *testing.T, s string) string {
	t.Helper()
	for k, v := range example {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	// The instruction comment names {{PLACEHOLDER}} literally; the runbook says to delete it.
	if i := strings.Index(s, "<!--\nactiveDIQ security advisory template"); i >= 0 {
		j := strings.Index(s[i:], "-->\n")
		s = s[:i] + s[i+j+4:]
	}
	return s
}

func readTemplate(t *testing.T) (md, rec string) {
	t.Helper()
	m, err := os.ReadFile(filepath.Join(repoTemplate, advisoryFile))
	if err != nil {
		t.Fatal(err)
	}
	r, err := os.ReadFile(filepath.Join(repoTemplate, recordFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(m), string(r)
}

func advisoryTree(t *testing.T, name, md, rec string) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	for f, b := range map[string]string{advisoryFile: md, recordFile: rec} {
		if b == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(d, f), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestTemplateProducesAPassingAdvisory(t *testing.T) {
	md, rec := readTemplate(t)
	if v := checkAdvisory(advisoryTree(t, "CVE-1900-0001", fill(t, md), fill(t, rec)), "CVE-1900-0001", true); len(v) > 0 {
		t.Fatalf("filled template fails the gate: %v", v)
	}
}

func TestAdvisoryViolations(t *testing.T) {
	md0, rec0 := readTemplate(t)
	md0, rec0 = fill(t, md0), fill(t, rec0)
	r := func(s, old, nw string) string {
		if !strings.Contains(s, old) {
			t.Fatalf("mutation target %q not in fixture", old)
		}
		return strings.Replace(s, old, nw, 1)
	}
	vec := example["CVSS_VECTOR"]
	cases := []struct {
		name, dir, md, rec, want string
		testIDs                  bool
	}{
		{name: "record vector differs (two scores)", md: md0, rec: r(rec0, `"vectorString": "`+vec, `"vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`), want: "vectorString"},
		{name: "record CVE differs", md: md0, rec: r(rec0, `"cveId": "CVE-1900-0001"`, `"cveId": "CVE-1900-0002"`), want: "cveId"},
		{name: "record score differs", md: md0, rec: r(rec0, `"baseScore": 9.8`, `"baseScore": 8.1`), want: "baseScore differs"},
		{name: "record severity differs", md: md0, rec: r(rec0, `"baseSeverity": "CRITICAL"`, `"baseSeverity": "HIGH"`), want: "baseSeverity"},
		{name: "second CVSS version in record", md: md0, rec: r(rec0, `"cvssV3_1": {`, `"cvssV4_0": {"baseScore": 7.0}, "cvssV3_1": {`), want: "cvssV4_0"},
		{name: "vendor label below the CVSS rating", md: r(md0, `severity: "critical"`, `severity: "high"`), rec: rec0, want: "is not the CVSS v3.1 rating"},
		{name: "score does not match vector", md: r(md0, "cvss_score: 9.8", "cvss_score: 7.5"), rec: rec0, want: "does not match"},
		{name: "advisory a day after the fix", md: r(md0, `published: "2026-11-12"`, `published: "2026-11-13"`), rec: rec0, want: "is not the fix day"},
		{name: "record a day after the advisory", md: md0, rec: r(rec0, `"datePublished": "2026-11-12`, `"datePublished": "2026-11-13`), want: "datePublished 2026-11-13"},
		{name: "target_met not honest", md: r(md0, `triaged: "2026-11-04"`, `triaged: "2026-10-20"`), rec: rec0, want: "target_met: true but critical target is 14 days"},
		{name: "test prefix in production", md: md0, rec: rec0, want: "CVE-1900- test prefix"},
		{name: "directory not the CVE", dir: "CVE-1900-0009", md: md0, rec: rec0, testIDs: true, want: "does not match its directory"},
		{name: "unfilled placeholder", md: r(md0, "Directory read.", "{{IMPACT}}"), rec: rec0, testIDs: true, want: "unfilled"},
		{name: "advisory text hides the vector", md: r(md0, "`"+vec+"`", "see record"), rec: rec0, testIDs: true, want: "does not show"},
		{name: "credit in the CVE description", md: md0, rec: r(rec0, "read directory objects.", "read directory objects. Found by Example Researcher."), testIDs: true, want: "5.2.4"},
		{name: "record references itself", md: md0, rec: r(rec0, `"url": "https://github.com/herambskanda/activeDIQ/commit/0000000"`, `"url": "https://www.cve.org/CVERecord?id=CVE-1900-0001"`), testIDs: true, want: "5.1.10"},
		{name: "advisory not referenced", md: md0, rec: r(rec0, `"url": "https://github.com/herambskanda/activeDIQ/security/advisories/GHSA-xxxx-xxxx-xxxx"`, `"url": "https://example.com/x"`), testIDs: true, want: "5.3.1"},
		{name: "nothing affected", md: md0, rec: r(rec0, `"status": "affected"`, `"status": "unaffected"`), testIDs: true, want: "5.1.4"},
		{name: "no CWE", md: r(md0, `cwe: "CWE-90"`, `cwe: "CWE-79"`), rec: rec0, testIDs: true, want: "problemTypes"},
		{name: "no fixed version", md: r(md0, `fixed_in: ["1.0.1"]`, `fixed_in: []`), rec: rec0, testIDs: true, want: "fixed_in is empty"},
		{name: "unknown front matter field", md: r(md0, "credit:", "internal_notes: x\ncredit:"), rec: rec0, testIDs: true, want: "internal_notes"},
		{name: "record missing", md: md0, testIDs: true, want: "record.json: missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := c.dir
			if dir == "" {
				dir = "CVE-1900-0001"
			}
			v := checkAdvisory(advisoryTree(t, dir, c.md, c.rec), dir, c.testIDs)
			if !strings.Contains(strings.Join(v, "\n"), c.want) {
				t.Fatalf("want a violation containing %q, got %v", c.want, v)
			}
		})
	}
}

func TestCheckAdvisoriesLayout(t *testing.T) {
	root := t.TempDir()
	if v := CheckAdvisories(root); !strings.Contains(strings.Join(v, "\n"), "advisory template missing") {
		t.Fatalf("missing template not reported: %v", v)
	}
	md, rec := readTemplate(t)
	base := filepath.Join(root, advisoriesDir)
	for dir, files := range map[string][2]string{templateDir: {md, rec}, "CVE-2026-0001": {strings.ReplaceAll(fill(t, md), "CVE-1900-0001", "CVE-2026-0001"), strings.ReplaceAll(fill(t, rec), "CVE-1900-0001", "CVE-2026-0001")}} {
		if err := os.MkdirAll(filepath.Join(base, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(base, dir, advisoryFile), []byte(files[0]), 0o644)
		_ = os.WriteFile(filepath.Join(base, dir, recordFile), []byte(files[1]), 0o644)
	}
	if v := CheckAdvisories(root); len(v) > 0 {
		t.Fatalf("clean advisories tree rejected: %v", v)
	}
	_ = os.WriteFile(filepath.Join(base, "draft.md"), []byte("x"), 0o644)
	if v := CheckAdvisories(root); !strings.Contains(strings.Join(v, "\n"), "draft.md") {
		t.Fatalf("stray file not reported: %v", v)
	}
}

// The worked example in testdata is the template filled with example; tools/ci/proof.sh uses it.
// Regenerate with: UPDATE_FIXTURE=1 go test ./tools/fitness/disclosure -run TestWorkedExample
func TestWorkedExampleMatchesTemplate(t *testing.T) {
	md, rec := readTemplate(t)
	dir := filepath.Join("testdata", "CVE-1900-0001")
	for f, want := range map[string]string{advisoryFile: fill(t, md), recordFile: fill(t, rec)} {
		p := filepath.Join(dir, f)
		if os.Getenv("UPDATE_FIXTURE") == "1" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		got, err := os.ReadFile(p)
		if err != nil || string(got) != want {
			t.Fatalf("%s is stale against the template (err %v); regenerate it (see comment)", p, err)
		}
	}
	if v := checkAdvisory(dir, "CVE-1900-0001", true); len(v) > 0 {
		t.Fatalf("worked example fails: %v", v)
	}
}
