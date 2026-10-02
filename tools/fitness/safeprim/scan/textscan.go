package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/skenzeriq/activediq/tools/analyzers/policy"
)

// textRule is a line (or whole-file) rule for the languages that have no Go AST here: C# sidecars,
// the Rust native tier and SQL migrations. The Roslyn BannedApiAnalyzers and clippy configs under
// sidecars/ and native/ enforce the same lists inside their own builds once those projects exist;
// these rules are what `make ci` can enforce today, and they run without a .NET or Rust toolchain.
type textRule struct {
	FF       string
	Rule     string
	Re       *regexp.Regexp
	Home     []string // directories where the construct is allowed
	Combined bool     // the line must also combine the match with data (concatenation, interpolation, formatting)
	Whole    bool     // match across lines
	Msg      string
}

var (
	reCSCombined   = regexp.MustCompile(`\$@?"|[Ss]tring\.Format\s*\(|"\s*\+|\+\s*@?"`)
	reRustCombined = regexp.MustCompile(`format!\s*\(|"\s*\+|\+\s*&?"`)
)

func shapeRules(combined *regexp.Regexp) []textRule {
	var out []textRule
	for _, s := range shapes {
		if s.Rule == "powershell-quote-escaper" {
			out = append(out, textRule{FF: "FF-SP3", Rule: s.Rule, Re: s.Re, Home: s.Home, Msg: s.Msg})
			continue
		}
		if s.Rule == "html-shape" || s.Rule == "mail-header-shape" {
			continue // Go output encoders only: the other tiers produce no human-facing files (§12.1)
		}
		out = append(out, textRule{FF: "FF-SP3", Rule: s.Rule, Re: s.Re, Home: s.Home, Combined: true, Msg: s.Msg})
	}
	return out
}

var csRules = append([]textRule{
	{FF: "FF-SP1", Rule: "powershell-sdk", Re: regexp.MustCompile(`System\.Management\.Automation|Microsoft\.PowerShell\.SDK|PowerShell\.Create\s*\(`), Home: []string{policy.SidecarHost},
		Msg: "the PowerShell SDK is referenced only by sidecars/pshost (" + refP4 + ")"},
	{FF: "FF-SP1", Rule: "process-api-dotnet", Re: regexp.MustCompile(`System\.Diagnostics\.Process\b|\bProcessStartInfo\b|\bProcess\.Start\s*\(`),
		Msg: "process creation is banned in .NET sidecars: Process.Start and ProcessStartInfo (" + refPr + ")"},
	{FF: "FF-SP2", Rule: "powershell-script-text", Re: regexp.MustCompile(`\.AddScript\s*\(|ScriptBlock\s*\.\s*Create|\bExpandString\b|\bInvokeScript\b|\bInvoke-Expression\b`),
		Msg: "PowerShell.AddScript, ScriptBlock.Create, ExpandString and InvokeScript build code from text; use AddCommand and AddParameter (" + refP4 + ")"},
	{FF: "FF-SP2", Rule: "dotnet-ldap-search-string", Re: regexp.MustCompile(`\bDirectorySearcher\b|new\s+SearchRequest\s*\(`),
		Msg: "DirectorySearcher and string SearchRequest constructors are banned in tier X; the filter arrives rendered by ldapfilter (" + refP1 + ")"},
	{FF: "FF-SP2", Rule: "tls-verify-bypass-dotnet", Re: regexp.MustCompile(`ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback|\bVerifyServerCertificate\b|DangerousAcceptAnyServerCertificateValidator`),
		Msg: "certificate validation callbacks accept any certificate (" + refTLS + ")"},
}, shapeRules(reCSCombined)...)

var rustRules = append([]textRule{
	{FF: "FF-SP1", Rule: "process-api-rust", Re: regexp.MustCompile(`\bstd::process\b|\btokio::process\b|\bCommand::new\b`),
		Msg: "process creation is banned in the native tier: nothing in LSASS or LogonUI starts a process (" + refPr + ")"},
	{FF: "FF-SP2", Rule: "tls-verify-bypass-rust", Re: regexp.MustCompile(`danger_accept_invalid_certs|danger_accept_invalid_hostnames`),
		Msg: "certificate and hostname verification bypasses are banned (" + refTLS + ")"},
}, shapeRules(reRustCombined)...)

var sqlRules = []textRule{
	{FF: "FF-SP2", Rule: "plpgsql-execute-concat", Re: regexp.MustCompile(`(?is)\bexecute\b[^;]*\|\|`), Whole: true,
		Msg: "PL/pgSQL EXECUTE with || builds SQL from text; use format('%I'/'%L', …) or USING (" + refP5 + " rule 8)"},
}

func isTestPath(rel string) bool {
	l := strings.ToLower(rel)
	return strings.Contains(l, "/tests/") || strings.Contains(l, "/test/") || strings.Contains(l, "tests.cs") || strings.HasSuffix(l, "_test.rs") || strings.HasPrefix(l, "tests/")
}

func scanText(root, rel string, rules []textRule, checks Checks, out *[]Finding) error {
	if policy.IsToolTier(rel) {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return err
	}
	dir := policy.DirOf(rel)
	text := string(data)
	lines := strings.Split(text, "\n")
	for _, r := range rules {
		if !checks[r.FF] || policy.MatchAny(dir, r.Home) {
			continue
		}
		if r.FF == "FF-SP3" && isTestPath(rel) {
			continue
		}
		if r.Whole {
			for _, m := range r.Re.FindAllStringIndex(text, -1) {
				*out = append(*out, Finding{FF: r.FF, Rule: r.Rule, File: rel, Line: 1 + strings.Count(text[:m[0]], "\n"), Msg: r.Msg})
			}
			continue
		}
		combined := reCSCombined
		if strings.HasSuffix(rel, ".rs") {
			combined = reRustCombined
		}
		for i, ln := range lines {
			t := strings.TrimSpace(ln)
			if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") && strings.HasSuffix(rel, ".rs") && !strings.HasPrefix(t, "#[") {
				continue
			}
			if !r.Re.MatchString(ln) || (r.Combined && !combined.MatchString(ln)) {
				continue
			}
			*out = append(*out, Finding{FF: r.FF, Rule: r.Rule, File: rel, Line: i + 1, Msg: r.Msg})
		}
	}
	return nil
}

// scanGoMod is FF-SP1 on go.mod: headless browsers and HTML-to-PDF engines are not dependencies of
// the product (§12.7 rule 1). Tier L modules (tools/, lab/) are exempt.
func scanGoMod(root, rel string, checks Checks, out *[]Finding) error {
	if !checks["FF-SP1"] || policy.IsToolTier(rel) {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return err
	}
	for i, ln := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ln), "require"))
		for _, banned := range moduleDenylist {
			if strings.HasPrefix(t, banned+" ") || strings.HasPrefix(t, banned+"/") {
				*out = append(*out, Finding{FF: "FF-SP1", Rule: "html-to-pdf-engine", File: rel, Line: i + 1,
					Msg: "requires " + banned + ": a headless browser or HTML-to-PDF engine is banned in product code (" + refP7 + ".7)"})
			}
		}
	}
	return nil
}

// scanWebPackage is FF-SP3 on web/**/package.json: the console never carries a CSV, XLSX, PDF or
// HTML-string library (§12.3, §12.5 W1).
func scanWebPackage(root, rel string, checks Checks, out *[]Finding) error {
	if !checks["FF-SP3"] {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return err
	}
	var pkg map[string]json.RawMessage
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		raw, ok := pkg[section]
		if !ok {
			continue
		}
		var deps map[string]string
		if json.Unmarshal(raw, &deps) != nil {
			continue
		}
		for name := range deps {
			why, banned := webPackageDenylist[name]
			if !banned {
				continue
			}
			line := 1
			for i, ln := range lines {
				if strings.Contains(ln, `"`+name+`"`) {
					line = i + 1
					break
				}
			}
			*out = append(*out, Finding{FF: "FF-SP3", Rule: "web-banned-package", File: rel, Line: line,
				Msg: "depends on " + name + ", " + why})
		}
	}
	return nil
}

var serviceExts = map[string]bool{".yml": true, ".yaml": true, ".service": true, ".wxs": true, ".wxi": true, ".sh": true, ".ps1": true, ".toml": true, ".mk": true, ".conf": true, ".ini": true, ".cfg": true, ".plist": true, ".env": false, ".tmpl": true, ".json": true, ".xml": true, ".props": true}

// scanServiceDefinition is FF-SP2's GOTRACEBACK rule on everything that can define a service's
// environment: unit files, compose files, Dockerfiles, MSI sources, scripts.
func scanServiceDefinition(root, rel, ext, base string, checks Checks, out *[]Finding) error {
	if !checks["FF-SP2"] {
		return nil
	}
	isDocker := strings.HasPrefix(base, "Dockerfile") || strings.HasPrefix(base, "Containerfile") || base == "Makefile"
	if !serviceExts[ext] && !isDocker {
		return nil
	}
	if base == "package-lock.json" {
		return nil
	}
	if st, err := os.Stat(filepath.Join(root, rel)); err != nil || st.Size() > 2<<20 {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return err
	}
	for i, ln := range strings.Split(string(data), "\n") {
		if reGoTraceback.MatchString(ln) {
			*out = append(*out, Finding{FF: "FF-SP2", Rule: "gotraceback-crash", File: rel, Line: i + 1,
				Msg: "a crash-mode GOTRACEBACK writes core dumps that carry secrets (" + refTLS + " R7)"})
		}
	}
	return nil
}
