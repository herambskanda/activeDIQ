package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

const (
	contact = "https://github.com/example/repo/security/advisories/new"
	goodMd  = "Report at <" + contact + ">.\n"
	goodTxt = "# comment\nContact: " + contact + "\nExpires: 2027-07-23T00:00:00Z\nPolicy: https://github.com/example/repo/blob/main/SECURITY.md\n"
)

func tree(t *testing.T, txt, md string) string {
	t.Helper()
	d := t.TempDir()
	if txt != "" {
		if err := os.MkdirAll(filepath.Join(d, ".well-known"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, securityTxtPath), []byte(txt), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if md != "" {
		if err := os.WriteFile(filepath.Join(d, securityMdPath), []byte(md), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The advisory template is part of the intake set (advisory_test.go covers its absence).
	tpl := filepath.Join(d, advisoriesDir, templateDir)
	if err := os.MkdirAll(tpl, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{advisoryFile, recordFile} {
		b, err := os.ReadFile(filepath.Join(repoTemplate, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tpl, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestRepositoryFilesPass(t *testing.T) {
	if v := Check("../../..", time.Now().UTC()); len(v) > 0 {
		t.Fatalf("repository intake files fail: %v", v)
	}
}

func TestClean(t *testing.T) {
	if v := Check(tree(t, goodTxt, goodMd), now); len(v) > 0 {
		t.Fatalf("clean input rejected: %v", v)
	}
	// CRLF and case-insensitive field names are valid RFC 9116.
	crlf := strings.ReplaceAll(strings.ReplaceAll(goodTxt, "\n", "\r\n"), "Contact:", "contact:")
	if v := Check(tree(t, crlf, goodMd), now); len(v) > 0 {
		t.Fatalf("CRLF/lowercase rejected: %v", v)
	}
}

func TestViolations(t *testing.T) {
	cases := []struct{ name, txt, md, want string }{
		{"no security.txt", "", goodMd, "missing (RFC 9116"},
		{"no SECURITY.md", goodTxt, "", "SECURITY.md: missing"},
		{"no contact", strings.Replace(goodTxt, "Contact: "+contact+"\n", "", 1), goodMd, "no Contact"},
		{"http contact", strings.Replace(goodTxt, "https://github.com/example/repo/security", "http://github.com/example/repo/security", 1), goodMd, "not an https:"},
		{"contact not in policy", goodTxt, "Email us.\n", "not named in SECURITY.md"},
		{"no expires", strings.Replace(goodTxt, "Expires: 2027-07-23T00:00:00Z\n", "", 1), goodMd, "no Expires"},
		{"two expires", goodTxt + "Expires: 2027-07-24T00:00:00Z\n", goodMd, "appears 2 times"},
		{"bad date", strings.Replace(goodTxt, "2027-07-23T00:00:00Z", "July 2027", 1), goodMd, "not an RFC 3339"},
		{"expired", strings.Replace(goodTxt, "2027-07-23", "2026-10-01", 1), goodMd, "has passed"},
		{"renewal due", strings.Replace(goodTxt, "2027-07-23", "2026-11-10", 1), goodMd, "less than 30 days"},
		{"too far", strings.Replace(goodTxt, "2027-07-23", "2028-01-01", 1), goodMd, "more than a year"},
		{"no policy", strings.Replace(goodTxt, "Policy: https://github.com/example/repo/blob/main/SECURITY.md\n", "", 1), goodMd, "no Policy"},
		{"wrong policy", strings.Replace(goodTxt, "SECURITY.md", "README.md", 1), goodMd, "does not point at"},
		{"garbage line", goodTxt + "this is not a field\n", goodMd, "not a \"Field: value\""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := Check(tree(t, c.txt, c.md), now)
			if !strings.Contains(strings.Join(v, "\n"), c.want) {
				t.Fatalf("want a violation containing %q, got %v", c.want, v)
			}
		})
	}
}
