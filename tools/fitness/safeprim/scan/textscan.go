package scan

import (
	"encoding/json"
	"os"
	"path"
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
	// Keep, when set on a Whole rule, decides per match (given the text and the match start) whether it
	// is a violation; it lets a rule see structure a regexp cannot, such as which argument holds a ||.
	Keep func(text string, at int) bool
	Msg  string
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
	{FF: "FF-SP2", Rule: "plpgsql-execute-concat", Re: regexp.MustCompile(`(?i)\bexecute\b`), Whole: true, Keep: executeConcatUnsafe,
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
				if r.Keep != nil && !r.Keep(text, m[0]) {
					continue
				}
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

// isBuildOrEnvFile: files that set build flags or environment without a scannable extension:
// make and just files, and dotenv/direnv/go.env files (GOFLAGS=-ldflags=-checklinkname=0, T-0221).
func isBuildOrEnvFile(base string) bool {
	l := strings.ToLower(base)
	return l == "makefile" || l == "gnumakefile" || l == "justfile" || l == ".justfile" || l == "go.env" ||
		l == ".envrc" || strings.HasPrefix(l, ".envrc.") || l == ".env" || strings.HasPrefix(l, ".env.") || strings.HasSuffix(l, ".env")
}

// scanGoCheckLinkname flags any checklinkname mention in a .go file (a tier L release tool passing
// -ldflags=-checklinkname=0 to exec go build). The safeprim scanner's own sources name the flag to
// detect it and are exempt (only that directory, not its subdirectories; other .go under
// tools/fitness/safeprim/ are scanned, T-0275, T-0286).
func scanGoCheckLinkname(rel string, src []byte, checks Checks, out *[]Finding) {
	if !checks["FF-SP2"] || path.Dir(rel) == "tools/fitness/safeprim/scan" {
		return
	}
	for i, ln := range strings.Split(string(src), "\n") {
		if reCheckLinkname.MatchString(ln) {
			*out = append(*out, Finding{FF: "FF-SP2", Rule: "checklinkname-off", File: rel, Line: i + 1,
				Msg: "any -checklinkname flag disables the linker's block on pull-linkname into the standard library; no Go source (tools included) may pass it (T-0221)"})
		}
	}
}

var reCheckLinkname = regexp.MustCompile(`(?i)checklinkname`)

var serviceExts = map[string]bool{".yml": true, ".yaml": true, ".service": true, ".wxs": true, ".wxi": true, ".sh": true, ".ps1": true, ".psm1": true, ".psd1": true, ".bat": true, ".cmd": true, ".py": true, ".bash": true, ".zsh": true, ".toml": true, ".mk": true, ".conf": true, ".ini": true, ".cfg": true, ".plist": true, ".env": false, ".tmpl": true, ".json": true, ".xml": true, ".props": true, ".fish": true, ".vbs": true, ".nu": true, ".pyw": true}

// scanServiceDefinition is FF-SP2's GOTRACEBACK rule on everything that can define a service's
// environment: unit files, compose files, Dockerfiles, MSI sources, scripts.
func scanServiceDefinition(root, rel, ext, base string, checks Checks, out *[]Finding) error {
	if !checks["FF-SP2"] {
		return nil
	}
	isDocker := strings.HasPrefix(base, "Dockerfile") || strings.HasPrefix(base, "Containerfile") || isBuildOrEnvFile(base)
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
		if reCheckLinkname.MatchString(ln) {
			*out = append(*out, Finding{FF: "FF-SP2", Rule: "checklinkname-off", File: rel, Line: i + 1,
				Msg: "any -checklinkname flag (=0, =false, =f ...) disables the linker's block on pull-linkname into the standard library; no build or release script may mention it (T-0186)"})
		}
		if reGoTraceback.MatchString(ln) {
			*out = append(*out, Finding{FF: "FF-SP2", Rule: "gotraceback-crash", File: rel, Line: i + 1,
				Msg: "a crash-mode GOTRACEBACK writes core dumps that carry secrets (" + refTLS + " R7)"})
		}
	}
	return nil
}

// executeConcatUnsafe decides one regexp hit of plpgsql-execute-concat. A || in the arguments after
// the template of EXECUTE format(...) is a value that %I or %L quotes, so it is not building SQL from
// text; a || in the template, after the call, or in any EXECUTE that is not a format() call is. The
// regexp only finds the keyword (a ; inside a quoted template would hide a || from a pattern); this
// scans to the statement end honouring quotes.
func executeConcatUnsafe(text string, at int) bool {
	i := at + len("execute")
	for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r') {
		i++
	}
	depth, arg := 0, 0 // outside a format() call every || is unsafe; inside, only one in the template (argument 0)
	if strings.HasPrefix(strings.ToLower(text[i:min(i+6, len(text))]), "format") {
		j := i + len("format")
		for j < len(text) && (text[j] == ' ' || text[j] == '\t' || text[j] == '\n' || text[j] == '\r') {
			j++
		}
		if j < len(text) && text[j] == '(' {
			i, depth = j+1, 1
		}
	}
	for i < len(text) {
		switch c := text[i]; {
		case c == '\'':
			i++
			for i < len(text) {
				if text[i] == '\'' {
					if i+1 < len(text) && text[i+1] == '\'' {
						i += 2
						continue
					}
					break
				}
				i++
			}
		case c == '$':
			if end := dollarTagEnd(text, i); end > 0 {
				tag := text[i:end]
				if j := strings.Index(text[end:], tag); j >= 0 {
					i = end + j + len(tag) - 1
				}
			}
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 1:
			arg++
		case c == ';' && depth <= 0:
			return false
		case c == '|' && i+1 < len(text) && text[i+1] == '|':
			if depth <= 0 || arg == 0 {
				return true
			}
			i++
		}
		i++
	}
	return false
}

// dollarTagEnd returns the index after a dollar-quote opener ($$ or $tag$) at i, or 0 when there is none.
func dollarTagEnd(text string, i int) int {
	for j := i + 1; j < len(text); j++ {
		c := text[j]
		if c == '$' {
			return j + 1
		}
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return 0
		}
	}
	return 0
}
