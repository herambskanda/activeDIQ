package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var goosList = setOf("aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios", "js",
	"linux", "nacl", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows", "zos",
	"unix") // unix names a set of GOOS values, so it counts as a GOOS (director, T-0022)
var goarchList = setOf("386", "amd64", "amd64p32", "arm", "armbe", "arm64", "arm64be", "loong64", "mips",
	"mipsle", "mips64", "mips64le", "mips64p32", "mips64p32le", "ppc", "ppc64", "ppc64le", "riscv",
	"riscv64", "s390", "s390x", "sparc", "sparc64", "wasm")

func setOf(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// verbose prints each passing cross-build target (the -v flag), as evidence in the make output.
var verbose bool

var goVersionTag = regexp.MustCompile(`^go1\.\d+$`)

// buildModeRE matches the build modes that produce a shared object or a plug-in. The class [= ]
// keeps this source line from matching its own pattern.
var buildModeRE = regexp.MustCompile(`-buildmode[= ](c-shared|c-archive|plugin|shared)\b`)

// textScanSkip are the files the build-mode text scan does not read: prose and lockfiles.
var textScanSkip = []string{".md", ".lock", ".sum", ".svg", ".png", ".jpg", ".ico", ".woff", ".woff2", ".zip", ".gz"}

// checkGoSource is F2 (ADR-0001 rule 2) minus the cross-build: source-level bans.
func (c *Ctx) checkGoSource() []Violation {
	var vs []Violation
	add := func(f, msg string) { vs = append(vs, Violation{"F2", f, msg}) }
	m := c.M
	adapters := exceptionPaths(m.Exceptions.PlatformAdapters)
	testTags := setOf(m.TestTags...)
	toolTags := setOf(m.ToolchainTags...)

	for _, f := range c.Files {
		if strings.HasSuffix(f, ".go") {
			vs = append(vs, c.scanGoFile(f, adapters, testTags, toolTags)...)
		}
		if !scanForBuildMode(f) {
			continue
		}
		b, err := c.read(f)
		if err != nil || bytes.IndexByte(b, 0) >= 0 || len(b) > 2<<20 {
			continue
		}
		if loc := buildModeRE.FindIndex(b); loc != nil {
			line := 1 + bytes.Count(b[:loc[0]], []byte{'\n'})
			add(f+":"+strconv.Itoa(line), fmt.Sprintf("build flag %q builds a shared object or plug-in; Go in this product is a static, cgo-free binary", string(b[loc[0]:loc[1]])))
		}
	}

	// consistent toolchain directives
	var first, firstFile string
	for _, dir := range c.goModules() {
		f := path.Join(dir, "go.mod")
		if !c.hasFile(f) {
			continue
		}
		tc, err := c.effectiveToolchain(dir)
		if err != nil {
			add(f, err.Error())
			continue
		}
		if first == "" {
			first, firstFile = tc, f
		} else if tc != first {
			add(f, fmt.Sprintf("toolchain %s differs from %s in %s; every go.mod pins the same toolchain", tc, first, firstFile))
		}
	}

	// rust-toolchain.toml when native/ exists
	for _, root := range m.LanguageZones["rust"].Allow {
		exists := false
		for _, f := range c.Files {
			if underAny(f, []string{root}) {
				exists = true
				break
			}
		}
		if exists && !c.hasFile("rust-toolchain.toml") && !c.hasFile(path.Join(root, "rust-toolchain.toml")) {
			add(root, "rust-toolchain.toml is missing; the Rust toolchain is pinned in the repository root")
		}
	}
	return vs
}

func scanForBuildMode(f string) bool {
	for _, s := range textScanSkip {
		if strings.HasSuffix(f, s) {
			return false
		}
	}
	return !strings.HasSuffix(f, "package-lock.json")
}

func (c *Ctx) scanGoFile(f string, adapters []string, testTags, toolTags map[string]bool) []Violation {
	var vs []Violation
	add := func(msg string) { vs = append(vs, Violation{"F2", f, msg}) }
	src, err := c.read(f)
	if err != nil {
		return nil
	}
	fset := token.NewFileSet()
	af, err := parser.ParseFile(fset, f, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		add("cannot be parsed, so it cannot be scanned for cgo, plug-ins and build tags: " + firstLine(err.Error()))
		return vs
	}
	inAdapter := underAny(path.Dir(f), adapters)
	isTest := strings.HasSuffix(f, "_test.go")

	for _, imp := range af.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		switch p {
		case "C":
			add(fmt.Sprintf("line %d: import \"C\" (cgo) is banned whatever the file's build tags say", fset.Position(imp.Pos()).Line))
		case "plugin":
			add(fmt.Sprintf("line %d: the plugin package (Go plug-ins) is banned", fset.Position(imp.Pos()).Line))
		}
	}
	for _, cg := range af.Comments {
		for _, cm := range cg.List {
			if strings.HasPrefix(cm.Text, "//export ") || cm.Text == "//export" {
				add(fmt.Sprintf("line %d: //export (a cgo export) is banned", fset.Position(cm.Pos()).Line))
			}
		}
	}

	// filename suffix naming a GOOS/GOARCH
	if !inAdapter {
		if s := platformSuffix(f); s != "" {
			add(fmt.Sprintf("filename suffix %q names a GOOS or GOARCH outside a declared platform-adapter package; OS-specific Go belongs in a package listed in manifest exceptions.platformAdapters", s))
		}
	}

	// build constraints in the header comments
	for _, cg := range af.Comments {
		if cg.Pos() > af.Package {
			break
		}
		for _, cm := range cg.List {
			if !constraint.IsGoBuild(cm.Text) && !constraint.IsPlusBuild(cm.Text) {
				continue
			}
			expr, err := constraint.Parse(cm.Text)
			if err != nil {
				add(fmt.Sprintf("line %d: unparseable build constraint: %v", fset.Position(cm.Pos()).Line, err))
				continue
			}
			for _, tag := range exprTags(expr) {
				switch {
				case goosList[tag] || goarchList[tag]:
					if !inAdapter {
						add(fmt.Sprintf("line %d: build constraint names GOOS/GOARCH %q outside a declared platform-adapter package (manifest exceptions.platformAdapters)", fset.Position(cm.Pos()).Line, tag))
					}
				case testTags[tag]:
					if !isTest {
						add(fmt.Sprintf("line %d: test tag %q is only allowed in _test.go files", fset.Position(cm.Pos()).Line, tag))
					}
				case toolTags[tag] || goVersionTag.MatchString(tag):
				default:
					add(fmt.Sprintf("line %d: build tag %q is not allowed; custom tags are for tests only and must be in the manifest testTags list (code generators are ordinary main packages under tools/, not //go:build ignore files)", fset.Position(cm.Pos()).Line, tag))
				}
			}
		}
	}
	return vs
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// platformSuffix returns the _GOOS, _GOARCH or _GOOS_GOARCH suffix of a Go file name, if any.
func platformSuffix(f string) string {
	name := strings.TrimSuffix(path.Base(f), ".go")
	name = strings.TrimSuffix(name, "_test")
	parts := strings.Split(name, "_")
	n := len(parts)
	if n >= 3 && goosList[parts[n-2]] && parts[n-2] != "unix" && goarchList[parts[n-1]] {
		return "_" + parts[n-2] + "_" + parts[n-1]
	}
	if n >= 2 {
		last := parts[n-1]
		if (goosList[last] && last != "unix") || goarchList[last] {
			return "_" + last
		}
	}
	return ""
}

func exprTags(e constraint.Expr) []string {
	switch x := e.(type) {
	case *constraint.TagExpr:
		return []string{x.Tag}
	case *constraint.NotExpr:
		return exprTags(x.X)
	case *constraint.AndExpr:
		return append(exprTags(x.X), exprTags(x.Y)...)
	case *constraint.OrExpr:
		return append(exprTags(x.X), exprTags(x.Y)...)
	}
	return nil
}

// effectiveToolchain is the toolchain a module resolves to: its toolchain directive, else its go line.
func (c *Ctx) effectiveToolchain(dir string) (string, error) {
	var out struct {
		Go        string
		Toolchain string
	}
	if err := c.goModEdit(dir, &out); err != nil {
		return "", err
	}
	if out.Toolchain != "" {
		return out.Toolchain, nil
	}
	return "go" + out.Go, nil
}

func (c *Ctx) goModEdit(dir string, v any) error {
	cmd := exec.Command("go", "mod", "edit", "-json")
	cmd.Dir = c.abs(dir)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local") // reading a go.mod must never download a toolchain
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("go mod edit -json failed in %s: %s", dir, strings.TrimSpace(stderr.String()))
	}
	return json.Unmarshal(b, v)
}

// checkCrossBuild is the other half of F2: CGO_ENABLED=0 go build ./... for each target in the matrix.
func (c *Ctx) checkCrossBuild() []Violation {
	var vs []Violation
	for _, dir := range c.goModules() {
		gomod := path.Join(dir, "go.mod")
		if !c.hasFile(gomod) {
			continue
		}
		for _, t := range c.M.BuildMatrix {
			goos, goarch, ok := strings.Cut(t, "/")
			if !ok {
				vs = append(vs, Violation{"F2", c.ManifestPath, fmt.Sprintf("buildMatrix entry %q is not GOOS/GOARCH", t)})
				continue
			}
			cmd := exec.Command("go", "build", "./...")
			cmd.Dir = c.abs(dir)
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
			if out, err := cmd.CombinedOutput(); err != nil {
				vs = append(vs, Violation{"F2", gomod, fmt.Sprintf("CGO_ENABLED=0 go build ./... fails for %s: %s", t, trimOutput(out))})
			} else if verbose {
				fmt.Printf("fitness-stack: F2 CGO_ENABLED=0 go build ./... ok for %s (%s)\n", t, dir)
			}
		}
	}
	return vs
}

func trimOutput(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > 12 {
		lines = append(lines[:12], fmt.Sprintf("… (%d more lines)", len(lines)-12))
	}
	return "\n    " + strings.Join(lines, "\n    ")
}
