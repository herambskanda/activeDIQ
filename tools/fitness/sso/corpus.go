package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/skenzeriq/activediq/tools/fitness/internal/boundtest"
)

// FIT-SSO-2 (console-sso.md §10.1, §13): the TM-F-SSO corpus covers the spec. The check numbers are read
// from the spec's own §4 and §5 tables, so a check added to the spec fails CI until a record cites it; a
// record that cites a number the spec does not have is a typo, and also fails.

const (
	specFile  = "knowledge/development/architecture/console-sso.md"
	corpusDir = "internal/platform/authn/sso/testdata/corpus"
)

type protocol struct {
	Name    string   // directory under corpusDir
	Prefix  string   // check-number prefix in the spec
	Pkg     string   // package whose TestCorpus runs one subtest per record
	Classes []string // every class needs a record
	// PendingBy, when set, lets the protocol's corpus be absent (listed as pending, never silent) until
	// that ticket lands it. It stops applying the moment the corpus directory or a TestCorpus exists.
	PendingBy string
}

// The XML signature-wrapping class exists only where there is a signed XML document; the OIDC cases of
// §10.3 are forged, replayed, misaddressed and malformed.
var protocols = []protocol{
	{Name: "saml", Prefix: "SAML-", Pkg: "./" + samlDir, Classes: []string{"forged", "wrapped", "replayed", "misaddressed", "malformed"}},
	{Name: "oidc", Prefix: "OIDC-", Pkg: "./" + oidcDir, Classes: []string{"forged", "replayed", "misaddressed", "malformed"}, PendingBy: "T-0911"},
}

var (
	checkRow = regexp.MustCompile(`^\|\s*((?:OIDC|SAML)-(\d+))\s*\|`)
	sharedID = regexp.MustCompile(`^SSO-\d+$`)
)

// record is one corpus file (§10.1).
type record struct {
	ID     string   `json:"id"`
	Class  string   `json:"class"`
	Cites  []string `json:"cites"`
	Build  string   `json:"build"`
	Expect string   `json:"expect"`
	Reason string   `json:"reason"`
}

// SpecChecks returns the check numbers of the spec's §4 and §5 tables (from "## 4." up to "## 6."), in
// order.
func SpecChecks(root string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(root, specFile))
	if err != nil {
		return nil, err
	}
	var out []string
	in := false
	for _, l := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(l, "## 4."):
			in = true
		case strings.HasPrefix(l, "## 6."):
			in = false
		case in:
			if m := checkRow.FindStringSubmatch(l); m != nil {
				out = append(out, m[1])
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no OIDC-n or SAML-n check rows between \"## 4.\" and \"## 6.\"; the spec layout changed, update the checker", specFile)
	}
	return out, nil
}

// Result is what CheckCorpus found.
type Result struct {
	Violations []string
	Pending    []string
	Records    map[string][]string // protocol -> record IDs that must each have a passing subtest
}

// CheckCorpus is the static half of FIT-SSO-2: it needs only the spec and the record files.
func CheckCorpus(root string) (*Result, error) {
	checks, err := SpecChecks(root)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, c := range checks {
		known[c] = true
	}
	res := &Result{Records: map[string][]string{}}
	bad := func(format string, a ...any) { res.Violations = append(res.Violations, fmt.Sprintf(format, a...)) }

	for _, p := range protocols {
		dir := filepath.Join(root, corpusDir, p.Name)
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		sort.Strings(files)
		if len(files) == 0 {
			if _, statErr := os.Stat(dir); statErr != nil && p.PendingBy != "" && !declaresTestCorpus(filepath.Join(root, strings.TrimPrefix(p.Pkg, "./"))) {
				res.Pending = append(res.Pending, fmt.Sprintf("%s corpus (%s) has not landed; %s owns it. Until then no %s check is proven by a record; the checker enforces it in full the day %s/%s appears",
					p.Name, filepath.ToSlash(filepath.Join(corpusDir, p.Name)), p.PendingBy, p.Prefix+"n", corpusDir, p.Name))
				continue
			}
			bad("%s: no corpus records in %s (every %s check needs one)", p.Name, filepath.ToSlash(filepath.Join(corpusDir, p.Name)), p.Prefix+"n")
			continue
		}
		cited, classes, ids := map[string]bool{}, map[string]bool{}, map[string]bool{}
		validClass := map[string]bool{}
		for _, c := range p.Classes {
			validClass[c] = true
		}
		for _, f := range files {
			rel := filepath.ToSlash(filepath.Join(corpusDir, p.Name, filepath.Base(f)))
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			var r record
			if err := json.Unmarshal(b, &r); err != nil {
				bad("%s: not a corpus record: %v", rel, err)
				continue
			}
			if stem := strings.TrimSuffix(filepath.Base(f), ".json"); r.ID != stem {
				bad("%s: id %q must equal the file name %q", rel, r.ID, stem)
			}
			if ids[r.ID] {
				bad("%s: duplicate id %q", rel, r.ID)
			}
			ids[r.ID] = true
			if !validClass[r.Class] {
				bad("%s: class %q is not one of %s", rel, r.Class, strings.Join(p.Classes, ", "))
			}
			if r.Expect != "refuse" || r.Reason == "" {
				bad("%s: must expect \"refuse\" with a reason code", rel)
			}
			if len(r.Cites) == 0 {
				bad("%s: cites no check number", rel)
			}
			for _, c := range r.Cites {
				switch {
				case sharedID.MatchString(c): // SSO-n, §6: shared checks live outside the §4/§5 tables
				case strings.HasPrefix(c, p.Prefix) && known[c]:
					cited[c] = true
				default:
					bad("%s: cites %q, which is not a %s check of §4/§5 of the spec", rel, c, strings.TrimSuffix(p.Prefix, "-"))
				}
			}
			classes[r.Class] = true
			res.Records[p.Name] = append(res.Records[p.Name], r.ID)
		}
		for _, c := range checks {
			if strings.HasPrefix(c, p.Prefix) && !cited[c] {
				bad("%s: %s is cited by no corpus record", p.Name, c)
			}
		}
		for _, c := range p.Classes {
			if !classes[c] {
				bad("%s: no %q record", p.Name, c)
			}
		}
	}
	sort.Slice(res.Violations, func(i, j int) bool { return naturalLess(res.Violations[i], res.Violations[j]) })
	return res, nil
}

// declaresTestCorpus reports whether a _test.go file of the package declares TestCorpus: a package that
// claims a corpus run cannot be pending.
func declaresTestCorpus(pkgDir string) bool {
	files, _ := filepath.Glob(filepath.Join(pkgDir, "*_test.go"))
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil && bytes.Contains(b, []byte("func TestCorpus(")) {
			return true
		}
	}
	return false
}

// CheckSubtests is the bound half: TestCorpus of each protocol's package must run and pass one subtest
// per record (a missing, failed or skipped subtest, or a missing TestCorpus, is a violation).
func CheckSubtests(ctx context.Context, root string, res *Result, run boundtest.Runner) ([]string, error) {
	var tests []boundtest.Test
	for _, p := range protocols {
		ids := res.Records[p.Name]
		if len(ids) == 0 {
			continue
		}
		sort.Strings(ids)
		tests = append(tests, boundtest.Test{
			Check:    "FIT-SSO-2",
			What:     "Every " + p.Name + " corpus record runs as its own subtest of TestCorpus (console-sso.md §10.1).",
			Pkgs:     []string{p.Pkg},
			Name:     "TestCorpus",
			Subtests: ids,
		})
	}
	if len(tests) == 0 {
		return nil, nil
	}
	fails, err := boundtest.Run(ctx, root, tests, run)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range fails {
		out = append(out, f.String())
	}
	return out, nil
}

// naturalLess orders "…OIDC-2" before "…OIDC-10" so the report reads in spec order.
var digits = regexp.MustCompile(`\d+`)

func naturalLess(a, b string) bool {
	pa, pb := digits.FindAllString(a, -1), digits.FindAllString(b, -1)
	sa, sb := digits.ReplaceAllString(a, "#"), digits.ReplaceAllString(b, "#")
	if sa != sb {
		return a < b
	}
	for i := range pa {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}
