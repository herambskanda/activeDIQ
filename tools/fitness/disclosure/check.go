package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Paths are relative to the repository root.
const (
	securityTxtPath = ".well-known/security.txt"
	securityMdPath  = "SECURITY.md"
	// renewBefore makes CI fail this long before Expires, so the file is renewed while still valid.
	renewBefore = 30 * 24 * time.Hour
	// maxAhead: RFC 9116 §2.5.5 recommends Expires less than a year in the future.
	maxAhead = 366 * 24 * time.Hour
)

// field is one "Name: value" line of security.txt.
type field struct {
	name, value string
	line        int
}

// parse reads security.txt per RFC 9116 §2.2: comment lines start with '#', blank lines are
// ignored, every other line is "Field-Name: value". Field names are case-insensitive.
func parse(b []byte) ([]field, []string) {
	var fs []field
	var errs []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	n := 0
	for sc.Scan() {
		n++
		l := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		name, value, ok := strings.Cut(l, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			errs = append(errs, fmt.Sprintf("%s:%d: not a \"Field: value\" line", securityTxtPath, n))
			continue
		}
		fs = append(fs, field{strings.ToLower(name), strings.TrimSpace(value), n})
	}
	return fs, errs
}

// Check validates security.txt, SECURITY.md and the published advisories under root at time now
// and returns violations.
func Check(root string, now time.Time) []string {
	var v []string
	txt, err := os.ReadFile(filepath.Join(root, securityTxtPath))
	if err != nil {
		return []string{fmt.Sprintf("%s: missing (RFC 9116 vulnerability contact): %v", securityTxtPath, err)}
	}
	md, err := os.ReadFile(filepath.Join(root, securityMdPath))
	if err != nil {
		v = append(v, fmt.Sprintf("%s: missing (vulnerability disclosure policy): %v", securityMdPath, err))
	}
	fs, perrs := parse(txt)
	v = append(v, perrs...)

	var contacts, expires, policies []field
	for _, f := range fs {
		switch f.name {
		case "contact":
			contacts = append(contacts, f)
		case "expires":
			expires = append(expires, f)
		case "policy":
			policies = append(policies, f)
		}
	}

	if len(contacts) == 0 {
		v = append(v, securityTxtPath+": no Contact field (RFC 9116 §2.5.3 requires at least one)")
	}
	for _, c := range contacts {
		u, err := url.Parse(c.value)
		if err != nil || (u.Scheme != "https" && u.Scheme != "mailto" && u.Scheme != "tel") ||
			(u.Scheme == "https" && u.Host == "") {
			v = append(v, fmt.Sprintf("%s:%d: Contact %q is not an https:, mailto: or tel: URI", securityTxtPath, c.line, c.value))
			continue
		}
		if md != nil && !bytes.Contains(md, []byte(c.value)) {
			v = append(v, fmt.Sprintf("%s:%d: Contact %q is not named in %s; the two must point at the same channel", securityTxtPath, c.line, c.value, securityMdPath))
		}
	}

	switch len(expires) {
	case 0:
		v = append(v, securityTxtPath+": no Expires field (RFC 9116 §2.5.5 requires exactly one)")
	case 1:
		e := expires[0]
		t, err := time.Parse(time.RFC3339, e.value)
		switch {
		case err != nil:
			v = append(v, fmt.Sprintf("%s:%d: Expires %q is not an RFC 3339 date-time: %v", securityTxtPath, e.line, e.value, err))
		case !t.After(now):
			v = append(v, fmt.Sprintf("%s:%d: Expires %s has passed; the file is stale (RFC 9116 §2.5.5)", securityTxtPath, e.line, e.value))
		case t.Sub(now) < renewBefore:
			v = append(v, fmt.Sprintf("%s:%d: Expires %s is less than 30 days away; renew it (new Expires under a year ahead)", securityTxtPath, e.line, e.value))
		case t.Sub(now) > maxAhead:
			v = append(v, fmt.Sprintf("%s:%d: Expires %s is more than a year ahead (RFC 9116 §2.5.5 recommends under a year)", securityTxtPath, e.line, e.value))
		}
	default:
		v = append(v, fmt.Sprintf("%s: Expires appears %d times (RFC 9116 §2.5.5: at most once)", securityTxtPath, len(expires)))
	}

	if len(policies) == 0 {
		v = append(v, securityTxtPath+": no Policy field pointing at "+securityMdPath)
	}
	for _, p := range policies {
		if !strings.HasSuffix(p.value, "/"+securityMdPath) {
			v = append(v, fmt.Sprintf("%s:%d: Policy %q does not point at %s", securityTxtPath, p.line, p.value, securityMdPath))
		}
	}
	return append(v, CheckAdvisories(root)...)
}
