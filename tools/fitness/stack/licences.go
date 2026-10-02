package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// register maps a package path to the statuses of the register rows whose Project cell carries it
// in backticks. The register's own "Machine matching" note states this contract.
type register map[string][]string

var backticked = regexp.MustCompile("`([^`]+)`")

func loadRegister(file string) (register, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	reg := register{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 2 {
			continue
		}
		status := strings.ToLower(strings.TrimLeft(strings.TrimSpace(cells[len(cells)-1]), "*_ "))
		for _, m := range backticked.FindAllStringSubmatch(cells[0], -1) {
			reg[m[1]] = append(reg[m[1]], status)
		}
	}
	return reg, nil
}

// problem returns why a dependency may not be adopted: "" when it has a row and no row is Rejected.
func (r register) problem(pkg string) string {
	st, ok := r[pkg]
	if !ok {
		return "has no licence-register row whose Project cell carries its exact path in backticks"
	}
	for _, s := range st {
		if strings.HasPrefix(s, "rejected") {
			return "has a licence-register row marked Rejected"
		}
	}
	return ""
}

// checkLicences is F4 (ADR-0001 rule 6).
func (c *Ctx) checkLicences() []Violation {
	var vs []Violation
	reg, err := loadRegister(c.abs(c.M.LicenceReg))
	if err != nil {
		return []Violation{{"F4", c.M.LicenceReg, "cannot read the licence register: " + err.Error()}}
	}
	regFile := c.M.LicenceReg
	fail := func(f, msg string) { vs = append(vs, Violation{"F4", f, msg + " (register: " + regFile + ")"}) }

	// Direct Go dependencies.
	for _, dir := range c.goModules() {
		gomod := path.Join(dir, "go.mod")
		if !c.hasFile(gomod) {
			continue
		}
		var mod struct {
			Require []struct {
				Path     string
				Indirect bool
			}
		}
		if err := c.goModEdit(dir, &mod); err != nil {
			fail(gomod, err.Error())
			continue
		}
		for _, r := range mod.Require {
			if r.Indirect {
				continue
			}
			if p := reg.problem(r.Path); p != "" {
				fail(gomod, fmt.Sprintf("direct dependency %s %s", r.Path, p))
			}
		}
	}

	// Direct web, Rust and .NET dependencies.
	for _, f := range c.Files {
		var deps []string
		switch path.Base(f) {
		case "package.json":
			deps = c.npmDirect(f)
		case "Cargo.toml":
			deps = c.cargoDirect(f)
		default:
			if strings.HasSuffix(f, ".csproj") {
				deps = c.nugetDirect(f)
			}
		}
		for _, d := range deps {
			if p := reg.problem(d); p != "" {
				fail(f, fmt.Sprintf("direct dependency %s %s", d, p))
			}
		}
	}

	// third_party/<name>/ directories: a register row and a LICENSE file each.
	seen := map[string]bool{}
	for _, f := range c.Files {
		parts := strings.Split(f, "/")
		if len(parts) < 3 || parts[0] != "third_party" {
			continue
		}
		dir := parts[0] + "/" + parts[1]
		if seen[dir] {
			continue
		}
		seen[dir] = true
		if p := reg.problem(dir); p != "" {
			fail(dir, fmt.Sprintf("copied code %s %s", dir, p))
		}
		if !hasLicenceFile(c.abs(dir)) {
			fail(dir, "copied code carries no LICENSE file")
		}
	}

	vs = append(vs, c.scanTransitive()...)
	return vs
}

func (c *Ctx) npmDirect(f string) []string {
	b, err := c.read(f)
	if err != nil {
		return nil
	}
	var pj struct {
		Dependencies, DevDependencies, OptionalDependencies, PeerDependencies map[string]string
	}
	if json.Unmarshal(b, &pj) != nil {
		return nil
	}
	var out []string
	for _, m := range []map[string]string{pj.Dependencies, pj.DevDependencies, pj.OptionalDependencies, pj.PeerDependencies} {
		for k := range m {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

var (
	cargoDepSection = regexp.MustCompile(`^(?:workspace\.|target\..+\.)?(?:dev-|build-)?dependencies$`)
	cargoDepTable   = regexp.MustCompile(`^(?:workspace\.|target\..+\.)?(?:dev-|build-)?dependencies\.([A-Za-z0-9_-]+)$`)
	cargoKey        = regexp.MustCompile(`^([A-Za-z0-9_-]+)(\.[A-Za-z0-9_-]+)?\s*=\s*(.*)$`)
	cargoPackage    = regexp.MustCompile(`package\s*=\s*"([^"]+)"`)
	cargoOwn        = regexp.MustCompile(`\b(path|workspace)\s*=`)
)

// cargoDirect lists the registry dependencies of a Cargo.toml. It reads the dependency tables line
// by line, which covers the forms Cargo.toml uses for them. Path dependencies are our own crates
// and workspace-inherited ones are declared in the workspace table, so both are skipped.
func (c *Ctx) cargoDirect(f string) []string {
	b, err := c.read(f)
	if err != nil {
		return nil
	}
	var out []string
	section, tableName, tableOwn := "", "", false
	flush := func() {
		if tableName != "" && !tableOwn {
			out = append(out, tableName)
		}
		tableName, tableOwn = "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.HasPrefix(line, "["):
			flush()
			section = strings.Trim(line, "[] ")
			if m := cargoDepTable.FindStringSubmatch(section); m != nil {
				tableName = m[1]
			}
		case tableName != "":
			if cargoOwn.MatchString(line) {
				tableOwn = true
			}
			if m := cargoPackage.FindStringSubmatch(line); m != nil {
				tableName = m[1]
			}
		case cargoDepSection.MatchString(section):
			m := cargoKey.FindStringSubmatch(line)
			if m == nil || m[2] != "" || cargoOwn.MatchString(m[3]) {
				continue // not a dependency line, name.workspace = true, a path or workspace-inherited dependency
			}
			name := m[1]
			if pm := cargoPackage.FindStringSubmatch(m[3]); pm != nil {
				name = pm[1]
			}
			out = append(out, name)
		}
	}
	flush()
	return out
}

var nugetRef = regexp.MustCompile(`<PackageReference\s[^>]*Include="([^"]+)"`)

func (c *Ctx) nugetDirect(f string) []string {
	b, err := c.read(f)
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range nugetRef.FindAllStringSubmatch(string(b), -1) {
		out = append(out, m[1])
	}
	return out
}

func hasLicenceFile(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if !e.IsDir() && licenceFileName.MatchString(e.Name()) {
			return true
		}
	}
	return false
}

var licenceFileName = regexp.MustCompile(`(?i)^(licen[sc]e|copying|unlicen[sc]e)([-_.].*)?$`)

// ---- transitive scan -----------------------------------------------------------------------

// strongCopyleft names the licence families ADR-0001 rule 6 bans from shipped artefacts.
func classifyLicenceText(text string) string {
	t := strings.Join(strings.Fields(strings.ToLower(text)), " ")
	head := func(n int) string {
		if len(t) > n {
			return t[:n]
		}
		return t
	}
	switch {
	case titledBefore(t, "gnu affero general public license", 1500):
		return "AGPL"
	case strings.Contains(head(300), "gnu lesser general public license"), strings.Contains(head(300), "gnu library general public license"):
		return "" // LGPL is not on the banned list
	case titledBefore(t, "gnu general public license", 400):
		return "GPL"
	case strings.Contains(head(1500), "server side public license"):
		return "SSPL"
	case strings.Contains(head(1500), "elastic license"):
		return "Elastic"
	case strings.Contains(head(1500), "business source license"):
		return "BUSL"
	}
	for _, m := range spdxLine.FindAllStringSubmatch(text, -1) {
		if spdxBlocked(m[1]) {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}

// permissiveOpening are phrases that open a permissive licence text. A text that names the GPL only
// after one of them is a permissive licence mentioning the GPL, not the GPL.
var permissiveOpening = []string{"permission is hereby granted", "redistribution and use in source and binary", "apache license", "licensed under the apache"}

// titledBefore reports whether title appears in the first n bytes of the normalised text and ahead
// of every permissive opening phrase.
func titledBefore(t, title string, n int) bool {
	i := strings.Index(t, title)
	if i < 0 || i >= n {
		return false
	}
	for _, p := range permissiveOpening {
		if j := strings.Index(t, p); j >= 0 && j < i {
			return false
		}
	}
	return true
}

var spdxLine = regexp.MustCompile(`(?im)spdx-license-identifier:\s*(.+)$`)

// spdxBlocked reports whether an SPDX expression leaves no way to comply: every OR alternative
// names a banned family. "MIT OR GPL-2.0" is acceptable (take MIT); "GPL-3.0-only" is not.
func spdxBlocked(expr string) bool {
	expr = strings.NewReplacer("(", " ", ")", " ").Replace(expr)
	alts := regexp.MustCompile(`(?i)\s+or\s+`).Split(strings.TrimSpace(expr), -1)
	if len(alts) == 0 || strings.TrimSpace(expr) == "" {
		return false
	}
	for _, alt := range alts {
		bad := false
		for _, id := range regexp.MustCompile(`(?i)\s+and\s+`).Split(alt, -1) {
			id = strings.ToUpper(strings.Fields(id + " x")[0])
			for _, p := range []string{"GPL-", "AGPL-", "SSPL-", "ELASTIC-", "BUSL-"} {
				if strings.HasPrefix(id, p) {
					bad = true
				}
			}
		}
		if !bad {
			return false
		}
	}
	return true
}

func (c *Ctx) licenceExempt(module string) bool {
	for _, e := range c.M.LicenceExcepts {
		if e.Module == module {
			return true
		}
	}
	return false
}

func (c *Ctx) scanTransitive() []Violation {
	var vs []Violation
	add := func(f, msg string) { vs = append(vs, Violation{"F4", f, msg}) }

	// Go: the licence files of every module a shipped binary links.
	if len(c.M.Binaries) > 0 {
		d := c.listDeps()
		mods := make([]string, 0, len(d.modules))
		for m := range d.modules {
			mods = append(mods, m)
		}
		sort.Strings(mods)
		for _, m := range mods {
			if c.licenceExempt(m) {
				continue
			}
			info := d.modules[m]
			for _, lf := range licenceFiles(info.Dir) {
				b, err := os.ReadFile(lf)
				if err != nil {
					continue
				}
				if fam := classifyLicenceText(string(b)); fam != "" {
					add(info.gomod, fmt.Sprintf("shipped binary links %s %s whose %s is %s; strong copyleft cannot ship on-prem (a justified exception goes in manifest licenceExceptions with a ratified ADR)", m, info.Version, filepath.Base(lf), fam))
					break
				}
			}
		}
	}

	// Web: the production closure in each lockfile.
	for _, f := range c.Files {
		if path.Base(f) != "package-lock.json" || !underAny(f, c.M.LanguageZones["typescript"].Allow) {
			continue
		}
		b, err := c.read(f)
		if err != nil {
			continue
		}
		var lock struct {
			Packages map[string]struct {
				License string `json:"license"`
				Dev     bool   `json:"dev"`
			}
		}
		if json.Unmarshal(b, &lock) != nil {
			add(f, "package-lock.json cannot be parsed for the transitive licence scan")
			continue
		}
		names := make([]string, 0, len(lock.Packages))
		for n := range lock.Packages {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			p := lock.Packages[n]
			if p.Dev || p.License == "" || n == "" {
				continue
			}
			if spdxBlocked(p.License) {
				name := n[strings.LastIndex(n, "node_modules/")+len("node_modules/"):]
				if c.licenceExempt(name) {
					continue
				}
				add(f, fmt.Sprintf("shipped web closure includes %s under %s; strong copyleft cannot ship on-prem", name, p.License))
			}
		}
	}

	// Rust: cargo metadata reports each crate's licence expression.
	for _, f := range c.Files {
		if path.Base(f) == "Cargo.toml" && underAny(f, c.M.LanguageZones["rust"].Allow) {
			vs = append(vs, c.scanCargo(f)...)
		}
	}
	// .NET: no transitive NuGet scan yet, so a declared sidecar fails closed.
	for _, s := range c.M.Exceptions.Sidecars {
		add(c.ManifestPath, fmt.Sprintf("sidecar %s is declared but the transitive NuGet licence scan is not built; add it before the first sidecar ships", s.Path))
	}
	return vs
}

func licenceFiles(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() && licenceFileName.MatchString(e.Name()) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func (c *Ctx) scanCargo(f string) []Violation {
	cmd := exec.Command("cargo", "metadata", "--format-version", "1", "--manifest-path", c.abs(f))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return []Violation{{"F4", f, "cargo metadata failed, so the transitive Rust licence scan could not run: " + trimOutput(stderr.Bytes())}}
	}
	return cargoLicenceViolations(f, b, c.licenceExempt)
}

// cargoLicenceViolations reads `cargo metadata` JSON. Our own crates (source null) are skipped.
func cargoLicenceViolations(f string, metadata []byte, exempt func(string) bool) []Violation {
	var md struct {
		Packages []struct {
			Name, Version, License string
			Source                 *string
		}
	}
	if err := json.Unmarshal(metadata, &md); err != nil {
		return []Violation{{"F4", f, "cargo metadata output cannot be parsed: " + err.Error()}}
	}
	var vs []Violation
	for _, p := range md.Packages {
		if p.Source == nil || p.License == "" || exempt(p.Name) {
			continue
		}
		if spdxBlocked(p.License) {
			vs = append(vs, Violation{"F4", f, fmt.Sprintf("shipped Rust closure includes %s %s under %s; strong copyleft cannot ship on-prem", p.Name, p.Version, p.License)})
		}
	}
	return vs
}
