package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/corpus"
)

// MinNightlyFuzz is the FF-SP5 floor for a counted nightly run of one target.
const MinNightlyFuzz = 10 * time.Minute

// requiredProps are the properties each unit's fuzz target must claim (safe-primitives §8 FF-SP5):
// the P1–P4 text primitives check that parse(render(x)) == x and that rendering never emits an
// unescaped special; the P7 encoders check their own output properties. Units not listed need at
// least one property of the target's choosing.
var requiredProps = map[string][]string{
	"ldapfilter":      {"roundtrip", "noUnescapedSpecial"},
	"dn":              {"roundtrip", "noUnescapedSpecial"},
	"attr.guid":       {"roundtrip", "noUnescapedSpecial"},
	"attr.sid":        {"roundtrip", "noUnescapedSpecial"},
	"attr.filetime":   {"roundtrip", "noUnescapedSpecial"},
	"attr.gentime":    {"roundtrip", "noUnescapedSpecial"},
	"attr.flags":      {"roundtrip", "noUnescapedSpecial"},
	"attr.unicodepwd": {"roundtrip", "noUnescapedSpecial"},
	"pslit":           {"roundtrip", "noUnescapedSpecial"},
	"cellsafe":        {"noFormulaLead"},
	"csv":             {"roundtrip", "noFormulaLead"},
	"xlsx":            {"independentParse"},
	"html":            {"independentParse"},
	"mail":            {"independentParse"},
	"pdf":             {"independentParse"},
}

// checkFuzzDeclared is the static half of FF-SP5: every declared (implementation, unit) pair has a
// corpus-seeded fuzz target that exists, takes its seeds from the corpus and claims the required
// properties, or a stated reason for having none.
func checkFuzzDeclared(root string, m *Manifest) []Finding {
	var fs []Finding
	at := corpus.Dir + "/" + ManifestFile
	exempt := map[string]FuzzExempt{}
	for _, e := range m.FuzzExempt {
		if strings.TrimSpace(e.Reason) == "" {
			fs = append(fs, Finding{"FF-SP5", "fuzz-exempt", at, fmt.Sprintf("fuzzExempt %s/%s needs a reason", e.Implementation, e.Unit)})
		}
		exempt[e.Implementation+"\x00"+e.Unit] = e
	}
	have := map[string][]FuzzTarget{}
	for _, t := range m.Fuzz {
		im := m.implementation(t.Implementation)
		if im == nil || !im.hasUnit(t.Unit) {
			fs = append(fs, Finding{"FF-SP5", "fuzz-target", at, fmt.Sprintf("fuzz target %s names %s/%s, which no implementation declares", t.Target, t.Implementation, t.Unit)})
			continue
		}
		have[t.Implementation+"\x00"+t.Unit] = append(have[t.Implementation+"\x00"+t.Unit], t)
		fs = append(fs, checkTarget(root, im, t)...)
	}
	for _, im := range m.Implementations {
		for _, u := range im.Units {
			k := im.Name + "\x00" + u
			if len(have[k]) == 0 {
				if e, ok := exempt[k]; ok && strings.TrimSpace(e.Reason) != "" {
					fmt.Fprintf(os.Stderr, "fitness-corpus: note: %s/%s has no fuzz target: %s\n", im.Name, u, e.Reason)
					continue
				} else if ok {
					continue // the empty reason is already a finding
				}
				fs = append(fs, Finding{"FF-SP5", "no-fuzz-target", at, fmt.Sprintf("unit %s of implementation %s has no corpus-seeded fuzz target; add one that starts with corpustest.Seed(f, %q) and declare it under \"fuzz\" (or give a reason under \"fuzzExempt\")", u, im.Name, u)})
				continue
			}
			props := map[string]bool{}
			for _, t := range have[k] {
				for _, p := range t.Properties {
					props[p] = true
				}
			}
			need := requiredProps[u]
			if len(need) == 0 && len(props) == 0 {
				need = []string{"<any property>"}
			}
			for _, p := range need {
				if p == "<any property>" {
					fs = append(fs, Finding{"FF-SP5", "fuzz-properties", at, fmt.Sprintf("the fuzz targets of %s/%s claim no property", im.Name, u)})
				} else if !props[p] {
					fs = append(fs, Finding{"FF-SP5", "fuzz-properties", at, fmt.Sprintf("the fuzz targets of %s/%s must check %q (safe-primitives §8 FF-SP5); claimed: %v", im.Name, u, p, keys(props))})
				}
			}
		}
	}
	return fs
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// checkTarget reads a Go fuzz target's source: it must exist as func FuzzX(f *testing.F) in a _test.go
// file and call corpustest.Seed with the unit's name. A non-Go target is checked by being run.
func checkTarget(root string, im *Implementation, t FuzzTarget) []Finding {
	if len(t.Command) > 0 || im.Language != "go" {
		if len(t.Command) == 0 {
			return []Finding{{"FF-SP5", "fuzz-target", corpus.Dir + "/" + ManifestFile, fmt.Sprintf("fuzz target %s of %s needs a command", t.Target, im.Name)}}
		}
		return nil
	}
	pkg := t.Package
	if pkg == "" {
		pkg = im.Package
	}
	dir := filepath.Join(root, filepath.FromSlash(pkg))
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { return strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		return []Finding{{"FF-SP5", "fuzz-target", pkg, fmt.Sprintf("cannot read %s: %v", pkg, err)}}
	}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || fn.Name.Name != t.Target || fn.Body == nil {
					continue
				}
				if seeded(fn, t.Unit) {
					return nil
				}
				pos := fset.Position(fn.Pos())
				return []Finding{{"FF-SP5", "fuzz-not-seeded", rel(root, pos.Filename) + ":" + strconv.Itoa(pos.Line), fmt.Sprintf("fuzz target %s does not start from the corpus: call corpustest.Seed(f, %q) in its body", t.Target, t.Unit)}}
			}
		}
	}
	return []Finding{{"FF-SP5", "fuzz-target", pkg, fmt.Sprintf("fuzz target %s is declared for %s/%s but no func %s exists in a _test.go file of %s", t.Target, im.Name, t.Unit, t.Target, pkg)}}
}

func seeded(fn *ast.FuncDecl, unit string) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Seed" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "corpustest" {
			return true
		}
		if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, err := strconv.Unquote(lit.Value); err == nil && v == unit {
				found = true
			}
		}
		return true
	})
	return found
}

// FuzzResult is one target's run.
type FuzzResult struct {
	Target   FuzzTarget
	Duration time.Duration
	Output   string
	Err      error
}

var elapsedRE = regexp.MustCompile(`fuzz: elapsed: `)

// RunFuzz runs every declared fuzz target for d each, parallel at a time, and returns a Finding
// for any target that failed, found a crasher or did not actually fuzz. The returned log lists
// every target. A run shorter than MinNightlyFuzz is refused when nightly is true.
func RunFuzz(root string, m *Manifest, d time.Duration, nightly bool, parallel int, run Runner, logf func(string)) []Finding {
	if nightly && d < MinNightlyFuzz {
		return []Finding{{"FF-SP5", "fuzz-time", "-fuzztime", fmt.Sprintf("a nightly FF-SP5 run counts only with at least %s per target, not %s", MinNightlyFuzz, d)}}
	}
	if parallel < 1 {
		parallel = 1
	}
	var mu sync.Mutex
	var fs []Finding
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for _, t := range m.Fuzz {
		t := t
		im := m.implementation(t.Implementation)
		if im == nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var argv []string
			if len(t.Command) > 0 {
				for _, a := range t.Command {
					argv = append(argv, strings.ReplaceAll(a, "{fuzztime}", d.String()))
				}
			} else {
				pkg := t.Package
				if pkg == "" {
					pkg = im.Package
				}
				argv = []string{"go", "test", "-run", "^$", "-fuzz", "^" + t.Target + "$", "-fuzztime", d.String(), "./" + pkg}
			}
			start := time.Now()
			out, err := run(root, nil, argv)
			took := time.Since(start)
			line := fmt.Sprintf("FUZZ %-24s %-16s %-28s %8s", t.Implementation, t.Unit, t.Target, took.Round(time.Second))
			var f *Finding
			switch {
			case err != nil:
				f = &Finding{"FF-SP5", "fuzz-failed", t.Implementation + "/" + t.Target, fmt.Sprintf("fuzz target %s (unit %s) failed or found an input that breaks a property (Go keeps it under testdata/fuzz/%s of the package: commit it as a regression seed):\n    %s", t.Target, t.Unit, t.Target, tail(out, 30))}
				line += " FAIL"
			case len(t.Command) == 0 && !elapsedRE.MatchString(out):
				f = &Finding{"FF-SP5", "fuzz-not-run", t.Implementation + "/" + t.Target, fmt.Sprintf("`go test -fuzz` for %s ended without fuzzing (is the target a Fuzz function of that package?):\n    %s", t.Target, tail(out, 10))}
				line += " NOT-RUN"
			case took < d:
				f = &Finding{"FF-SP5", "fuzz-time", t.Implementation + "/" + t.Target, fmt.Sprintf("fuzz target %s ended after %s, before the requested %s", t.Target, took.Round(time.Second), d)}
				line += " SHORT"
			default:
				line += " ok"
			}
			mu.Lock()
			if f != nil {
				fs = append(fs, *f)
			}
			if logf != nil {
				logf(line)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return fs
}
