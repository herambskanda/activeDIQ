package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const pTestsWhat = "P1-P8 (ADR-0007) and F1 (out-of-bounds policy) tests exist, run and pass"

// Options selects what Run does.
type Options struct {
	SkipTests    bool
	Only         string
	ClosureAllow []string // overrides closure-allow.txt (fixtures); nil uses the reviewed file
}

func closureAllow(o Options) []string {
	if o.ClosureAllow != nil {
		return o.ClosureAllow
	}
	return parseAllow(embeddedClosureAllow)
}

// Result is one check's outcome.
type Result struct {
	ID         string
	What       string
	Inactive   string // non-empty: the missing input; the check did not run
	Violations []string
}

// Line is the one-line status printed for a check, followed by its violations.
func (r Result) Line() string {
	switch {
	case r.Inactive != "":
		return fmt.Sprintf("%-3s %s: inactive (%s)", r.ID, r.What, r.Inactive)
	case len(r.Violations) > 0:
		return fmt.Sprintf("%-3s %s: FAIL\n    %s", r.ID, r.What, strings.Join(r.Violations, "\n    "))
	}
	return fmt.Sprintf("%-3s %s: ok", r.ID, r.What)
}

// Run executes the checks against the tree at root.
func Run(root string, o Options) []Result {
	want := func(id string) bool {
		if o.Only == "" {
			return true
		}
		for _, s := range strings.Split(o.Only, ",") {
			if strings.TrimSpace(s) == id {
				return true
			}
		}
		return false
	}
	var out []Result
	add := func(id string, r Result) {
		if want(id) {
			out = append(out, r)
		}
	}
	add("R1", checkProto(root, "R1", "agent RPC set equals the golden list; no RPC outside it (AG1-AG3: denied verbs, unary)", []string{"AG1", "AG2", "AG3", "AG8"}))
	add("R2", checkProto(root, "R2", "policy messages are typed data: no Any, map, bytes or free string (AG4, AG5)", []string{"AG4", "AG5"}))
	add("R3", checkModuleCapabilities(root))
	add("R4", checkNoListener(root))
	add("R5", checkProto(root, "R5", "no password/credential/hash field or message, no fail-mode field (AG6, AG7)", []string{"AG6", "AG7"}))
	add("A1", checkInstaller(root))
	add("A4", checkAgentImports(root, closureAllow(o)))
	if want("P") || want("F1") {
		if o.SkipTests {
			add("P", Result{ID: "P", What: pTestsWhat, Inactive: "tests skipped by -skip-tests"})
		} else {
			add("P", checkTests(root))
		}
	}
	// An ADR may not be ratified on an inactive check: front-matter `status: accepted` with any check
	// inactive is a failure, not a pass.
	if o.Only == "" {
		var inactive []string
		for _, r := range out {
			if r.Inactive != "" && r.ID != "P" {
				inactive = append(inactive, r.ID)
			}
		}
		if len(inactive) > 0 {
			for _, adr := range acceptedADRs(root) {
				out = append(out, Result{ID: "ADR", What: "ADR-0006/0007 are accepted only when no check is inactive",
					Violations: []string{fmt.Sprintf("%s has status: accepted while %s are inactive", adr, strings.Join(inactive, ", "))}})
			}
		}
	}
	return out
}

// acceptedADRs lists ADR-0006/0007 files whose front-matter status is accepted.
func acceptedADRs(root string) []string {
	var out []string
	for _, pat := range []string{"0006-*.md", "0007-*.md"} {
		m, _ := filepath.Glob(filepath.Join(root, "knowledge/development/decisions", pat))
		for _, f := range m {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			head := string(b)
			if i := strings.Index(head, "\n---"); i > 0 && strings.HasPrefix(head, "---") {
				head = head[:i]
			}
			if regexp.MustCompile(`(?m)^status:\s*accepted\s*$`).MatchString(head) {
				out = append(out, filepath.Base(f))
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// R1, R2, R5: the agent proto lints. They are the AG rules of fitness-proto (tools/fitness/proto),
// run here against the agent protos so a violation fails fitness-agent-host by name.

var agentProtoDirs = []string{"proto/skenzeriq/agent/v1", "proto/activediq/addc/v1"}

var violationRe = regexp.MustCompile(`\b(AG[1-8])\b`)

func checkProto(root, id, what string, rules []string) Result {
	r := Result{ID: id, What: what}
	var missing []string
	for _, d := range agentProtoDirs {
		m, _ := filepath.Glob(filepath.Join(root, d, "*.proto"))
		if len(m) == 0 {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 {
		r.Inactive = "no proto in " + strings.Join(missing, ", ") + " (T-0600)"
		return r
	}
	lines, err := runProtoLint(root)
	if err != nil {
		r.Violations = append(r.Violations, "proto lint could not run: "+err.Error())
		return r
	}
	for _, l := range lines {
		for _, m := range violationRe.FindAllString(l, -1) {
			for _, rule := range rules {
				if m == rule {
					r.Violations = append(r.Violations, l)
				}
			}
		}
	}
	// The proto tool also fails for reasons that are not AG rules (a file that does not compile).
	// Those belong to fitness-proto, but a tree that does not compile has no verified agent contract.
	if len(lines) > 0 && len(r.Violations) == 0 && id == "R1" {
		r.Violations = append(r.Violations, lines...)
	}
	return r
}

// runProtoLint runs `go run ./tools/fitness/proto <root>/proto` from the module containing this tool
// and returns its output lines when it fails.
func runProtoLint(root string) ([]string, error) {
	abs, err := filepath.Abs(filepath.Join(root, "proto"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("go", "run", "github.com/skenzeriq/activediq/tools/fitness/proto", abs)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err = cmd.Run()
	if err == nil {
		return nil, nil
	}
	if _, ok := err.(*exec.ExitError); !ok {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

// ---------------------------------------------------------------------------------------------
// R3, R4: capability scans of agent-owned Go source (imports and calls; type-checking is not needed
// because the banned things are named packages and functions). R3 is an allowlist: a module may import
// only what is named here, so a new escape hatch (x/sys/windows, syscall, cgo) is a failure by default.

// agentModuleDirs hold code that runs inside the agent host with only the dependency struct.
var agentModuleDirs = []string{"internal/agentmodules"}

// agentOwnedDirs are all code only the agent binary runs; R4 also scans every own-module package in the
// agent's import closure (see goClosure), so this list is a floor, not the scope.
var agentOwnedDirs = []string{"cmd/agent", "internal/agentmodules", "internal/compose/agent"}

// r3AllowedStd: the standard-library packages an agent module may import. Pure computation, text,
// encoding, time and synchronisation. "os" is allowed for its read-only and environment helpers; the
// mutating calls are denied below as a second layer. To add one, review what it can reach.
var r3AllowedStd = setOf(
	"bytes", "bufio", "context", "errors", "fmt", "io", "log/slog", "maps", "math", "math/big", "math/bits",
	"os", "path", "path/filepath", "regexp", "slices", "sort", "strconv", "strings", "sync", "sync/atomic",
	"time", "unicode", "unicode/utf16", "unicode/utf8", "encoding/binary", "encoding/hex", "encoding/json",
	"encoding/base64", "crypto/sha256", "crypto/subtle", "hash", "hash/fnv", "iter", "cmp",
)

// r3AllowedOwn: path fragments of our own packages an agent module may import (its siblings and the
// host dependency-struct and policy packages). Matched against the import path.
var r3AllowedOwn = []string{"/internal/agentmodules/", "/internal/platform/agentpolicy", "/internal/agenthost/api"}

// r3Named: the reason given for the imports most likely to be tried, so the message teaches.
var r3Named = map[string]string{
	"os/exec":                               "process execution (C1/C2)",
	"plugin":                                "loading code",
	"syscall":                               "raw system calls: process, file, socket and service APIs",
	"unsafe":                                "memory the type system cannot check",
	"C":                                     "cgo",
	"io/ioutil":                             "file mutation (WriteFile, TempFile, ...)",
	"golang.org/x/sys/windows":              "the full Windows API: CreateProcess, OpenSCManager, registry, tokens (C1-C3)",
	"golang.org/x/sys/windows/registry":     "registry change (C3)",
	"golang.org/x/sys/windows/svc/mgr":      "service configuration change (C3)",
	"golang.org/x/sys/windows/svc/eventlog": "writes the host's log, reserved for the host",
	"golang.org/x/sys/unix":                 "raw system calls",
}

// r3BannedCalls: file mutation by an agent module (C2), the second layer behind the import allowlist.
// Reading is the module's own business through the host's dependency struct; any write goes through the
// host (the data directory only).
var r3BannedCalls = setOf(
	"os.Create", "os.CreateTemp", "os.WriteFile", "os.OpenFile", "os.Remove", "os.RemoveAll",
	"os.Rename", "os.Mkdir", "os.MkdirAll", "os.MkdirTemp", "os.Chmod", "os.Chown", "os.Lchown",
	"os.Truncate", "os.Symlink", "os.Link", "os.Chtimes", "os.NewFile", "os.StartProcess",
	"os.Setenv", "os.Unsetenv", "os.Clearenv", "os.Chdir", "os.Exit",
	"syscall.Exec", "syscall.ForkExec", "syscall.StartProcess",
)

func setOf(s ...string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, x := range s {
		m[x] = true
	}
	return m
}

func checkModuleCapabilities(root string) Result {
	r := Result{ID: "R3", What: "agent modules import only allowlisted packages and call no file-mutating or process API (C2, C3)"}
	files := goFiles(root, agentModuleDirs)
	if len(files) == 0 {
		r.Inactive = "no Go source under internal/agentmodules (T-0600 onward)"
		return r
	}
	for _, f := range files {
		scanGo(root, f, func(rel, imp, name string, line int) {
			if msg := judgeModuleImport(imp, name); msg != "" {
				r.Violations = append(r.Violations, fmt.Sprintf("%s:%d %s", rel, line, msg))
			}
		}, func(rel, call string, line int) {
			if r3BannedCalls[call] || strings.HasPrefix(call, "ioutil.") {
				r.Violations = append(r.Violations, fmt.Sprintf("%s:%d calls %s: an agent module cannot mutate files or start processes (write through the host's data-directory capability)", rel, line, call))
			}
		})
	}
	return r
}

// judgeModuleImport returns "" when an agent module may import imp under the local name, else the reason.
func judgeModuleImport(imp, name string) string {
	switch name {
	case ".":
		return fmt.Sprintf("dot-imports %s: dot and blank imports hide what a module can call", imp)
	case "_":
		return fmt.Sprintf("blank-imports %s: dot and blank imports hide what a module can call", imp)
	}
	if strings.HasPrefix(imp, "unparseable:") {
		return "does not parse: " + imp
	}
	if why, bad := r3Named[imp]; bad {
		return fmt.Sprintf("imports %s: %s", imp, why)
	}
	if r3AllowedStd[imp] {
		return ""
	}
	for _, o := range r3AllowedOwn {
		if strings.Contains(imp, o) {
			return ""
		}
	}
	return fmt.Sprintf("imports %s, which is not on the agent-module allowlist (tools/fitness/agenthost r3AllowedStd/r3AllowedOwn): a module gets only the host's dependency struct", imp)
}

// r4ListenNames are selectors that open or serve a listener, whatever they are called on: method calls on
// a value (lc.Listen) cannot be resolved without type-checking, so the name alone fails in agent code.
var r4ListenNames = setOf(
	"Listen", "ListenPacket", "ListenAndServe", "ListenAndServeTLS", "ListenTCP", "ListenUDP", "ListenIP",
	"ListenUnix", "ListenUnixgram", "ListenMulticastUDP", "ListenConfig", "ListenPipe",
	"Serve", "ServeTLS", "ServeConn", "ServeHTTP", "FileListener", "NewServer", "NewTLSServer",
)

// r4SocketPkgs: packages whose Bind is a server-side socket call.
var r4SocketPkgs = setOf("syscall", "windows", "unix")

func checkNoListener(root string) Result {
	r := Result{ID: "R4", What: "agent code (every own package in the agent closure) opens no listening socket (C5): outbound mTLS and the reverse tunnel on it only"}
	files, err := agentOwnedFiles(root)
	if err != nil {
		r.Violations = append(r.Violations, err.Error())
		return r
	}
	if len(files) == 0 {
		r.Inactive = "no agent-owned Go source"
		return r
	}
	seen := map[string]bool{}
	add := func(v string) {
		if !seen[v] {
			seen[v] = true
			r.Violations = append(r.Violations, v)
		}
	}
	for _, f := range files {
		scanGo(root, f, func(rel, imp, name string, line int) {
			switch {
			case imp == "net/http/httptest":
				add(fmt.Sprintf("%s:%d imports net/http/httptest, a listener in a shipped binary", rel, line))
			case name == ".":
				add(fmt.Sprintf("%s:%d dot-imports %s: dot imports hide the listener calls this check looks for", rel, line, imp))
			}
		}, func(rel, call string, line int) {
			i := strings.LastIndex(call, ".")
			recv, sel := call[:i], call[i+1:]
			if r4ListenNames[sel] || (sel == "Bind" && r4SocketPkgs[recv]) {
				add(fmt.Sprintf("%s:%d calls %s: the agent has no listener (TM-D13)", rel, line, call))
			}
		})
	}
	return r
}

// agentOwnedFiles are the non-test Go files of the agent-owned directories plus every file of every
// package of our own module in the agent's import closure (windows and linux).
func agentOwnedFiles(root string) ([]string, error) {
	set := map[string]bool{}
	for _, f := range goFiles(root, agentOwnedDirs) {
		set[f] = true
	}
	if _, err := os.Stat(filepath.Join(root, "cmd/agent")); err == nil {
		for _, goos := range []string{"windows", "linux"} {
			pkgs, err := goClosure(root, goos)
			if err != nil {
				return nil, fmt.Errorf("go list -deps ./cmd/agent (GOOS=%s): %v", goos, err)
			}
			for _, p := range pkgs {
				if !p.Main {
					continue
				}
				for _, f := range p.Files {
					set[filepath.Join(p.Dir, f)] = true
				}
			}
		}
	}
	var out []string
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}

// goFiles lists non-test .go files under the dirs of root.
func goFiles(root string, dirs []string) []string {
	var out []string
	for _, d := range dirs {
		_ = filepath.WalkDir(filepath.Join(root, d), func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !e.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				out = append(out, p)
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

// importName is the identifier an import binds when it is not renamed: the last path element that is not
// a major-version suffix.
func importName(p string) string {
	parts := strings.Split(p, "/")
	n := parts[len(parts)-1]
	if len(parts) > 1 && regexp.MustCompile(`^v[0-9]+$`).MatchString(n) {
		n = parts[len(parts)-2]
	}
	return n
}

// scanGo reports every import (with its local name: "", ".", "_" or an alias) and every pkg.Func / x.Method
// selector (as written; "?.Name" when the receiver is an expression) of a file.
func scanGo(root, path string, onImport func(rel, imp, name string, line int), onCall func(rel, call string, line int)) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	rel, _ := filepath.Rel(root, path)
	rel = filepath.ToSlash(rel)
	if err != nil {
		onImport(rel, "unparseable:"+err.Error(), "", 0)
		return
	}
	names := map[string]string{} // local name -> import path
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		local := ""
		if im.Name != nil {
			local = im.Name.Name
		}
		onImport(rel, p, local, fset.Position(im.Pos()).Line)
		n := importName(p)
		if local != "" {
			n = local
		}
		names[n] = p
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		line := fset.Position(sel.Pos()).Line
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			onCall(rel, "?."+sel.Sel.Name, line)
			return true
		}
		if p, ok := names[id.Name]; ok {
			onCall(rel, importName(p)+"."+sel.Sel.Name, line)
			if base := filepath.Base(p); base != importName(p) {
				onCall(rel, base+"."+sel.Sel.Name, line)
			}
			return true
		}
		onCall(rel, id.Name+"."+sel.Sel.Name, line)
		return true
	})
}

// pkgInfo is one package of the agent's closure.
type pkgInfo struct {
	Path  string
	Std   bool
	Main  bool // in the main module (our own code)
	Dir   string
	Files []string // GoFiles for this GOOS
}

// goClosure lists `go list -deps ./cmd/agent` for a GOOS (cgo off).
func goClosure(root, goos string) ([]pkgInfo, error) {
	const tpl = "{{.ImportPath}}\t{{.Standard}}\t{{if .Module}}{{.Module.Main}}{{end}}\t{{.Dir}}\t{{join .GoFiles \",\"}}"
	cmd := exec.Command("go", "list", "-deps", "-f", tpl, "./cmd/agent")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	var pkgs []pkgInfo
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(l, "\t")
		if len(f) != 5 {
			continue
		}
		p := pkgInfo{Path: f[0], Std: f[1] == "true", Main: f[2] == "true", Dir: f[3]}
		if f[4] != "" {
			p.Files = strings.Split(f[4], ",")
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------------------------
// A1: the agent installer source.

// Pinned by ADR-0006 rule 1 and 3.
const (
	pinnedAccount = `NT SERVICE\activeDIQAgent`
	pinnedSidType = "restricted"
)

var pinnedPrivileges = []string{"SeChangeNotifyPrivilege"}

var (
	localSystemRe = regexp.MustCompile(`(?i)local\s*system|nt\s*authority\\+system|localservice|networkservice|nt\s*authority\\+(local|network)\s*service|s-1-5-18\b|s-1-5-19\b|s-1-5-20\b`)
	agentFileRe   = regexp.MustCompile(`(?i)agent`)
	agentBodyRe   = regexp.MustCompile(`(?i)activediq-agent|activediqagent`)
)

// agentInstallerFiles are the files under packaging/ that name the agent in their file name or body:
// WiX sources and also install scripts, custom actions and anything else a service account can be set in
// (ADR-0006 A1 covers any LocalSystem string in the MSI source). Binary and very large files are skipped.
func agentInstallerFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(filepath.Join(root, "packaging"), func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		if info, err := e.Info(); err != nil || info.Size() > 4<<20 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil || bytes.IndexByte(b, 0) >= 0 {
			return nil
		}
		if agentFileRe.MatchString(filepath.Base(p)) || agentBodyRe.Match(b) {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func isWixXML(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".wxs", ".wxi", ".wixproj", ".xml":
		return true
	}
	return false
}

// scAccountRe finds a service created or reconfigured with an account: sc.exe config/create ... obj=,
// Set-Service/New-Service ... -Credential. Such a line must name the pinned account and nothing else.
var scAccountRe = regexp.MustCompile(`(?i)(sc(\.exe)?\s+(config|create)|set-service|new-service)[^\n]*(obj\s*=|-credential)`)

func checkInstaller(root string) Result {
	r := Result{ID: "A1", What: "agent installer names " + pinnedAccount + ", service SID type " + pinnedSidType + ", the pinned RequiredPrivileges, and no LocalSystem (ADR-0006 rules 1, 3)"}
	files := agentInstallerFiles(root)
	if len(files) == 0 {
		r.Inactive = "no agent installer source under packaging/ (windows-engineer's MSI ticket)"
		return r
	}
	services := 0
	var sids []string
	var privs []string
	for _, f := range files {
		rel, _ := filepath.Rel(root, f)
		rel = filepath.ToSlash(rel)
		b, err := os.ReadFile(f)
		if err != nil {
			r.Violations = append(r.Violations, rel+": "+err.Error())
			continue
		}
		if m := localSystemRe.FindString(string(b)); m != "" {
			r.Violations = append(r.Violations, fmt.Sprintf("%s names %q: the agent never runs as LocalSystem or a shared service identity (ADR-0006 rule 1)", rel, m))
		}
		for _, line := range strings.Split(string(b), "\n") {
			if scAccountRe.MatchString(line) && !strings.Contains(strings.ToLower(line), strings.ToLower(pinnedAccount)) {
				r.Violations = append(r.Violations, fmt.Sprintf("%s sets a service account other than %s: %q", rel, pinnedAccount, strings.TrimSpace(line)))
			}
		}
		if !isWixXML(f) {
			continue
		}
		x := judgeInstallerXML(rel, b)
		services += x.services
		sids = append(sids, x.sids...)
		privs = append(privs, x.privs...)
		r.Violations = append(r.Violations, x.violations...)
	}
	switch {
	case services == 0:
		r.Violations = append(r.Violations, "no ServiceInstall in the agent installer source: the account cannot be verified")
	case services > 1:
		r.Violations = append(r.Violations, fmt.Sprintf("%d ServiceInstall elements in the agent installer source, must be exactly one", services))
	default:
		// Every ServiceSid seen must be the pin: a later unrestricted setting must not hide behind an earlier one.
		if len(sids) == 0 {
			r.Violations = append(r.Violations, fmt.Sprintf("no ServiceSid in the agent installer source, must be %q (ServiceSid on ServiceInstall/ServiceConfig)", pinnedSidType))
		}
		for _, v := range sids {
			if !strings.EqualFold(v, pinnedSidType) {
				r.Violations = append(r.Violations, fmt.Sprintf("service SID type is %q, must be %q (every ServiceSid seen must be the pin)", v, pinnedSidType))
			}
		}
		if !sameSet(privs, pinnedPrivileges) {
			r.Violations = append(r.Violations, fmt.Sprintf("RequiredPrivileges are %v, must be exactly %v", privs, pinnedPrivileges))
		}
	}
	return r
}

type xmlEl struct {
	Name  string
	Attrs map[string]string
	Text  string
	Depth int
}

type installerFacts struct {
	services   int
	sids       []string
	privs      []string
	violations []string
}

// judgeInstallerXML reads one WiX file: the ServiceInstall count, every ServiceSid and privilege it sets,
// and the violations that are local to the element (account, password).
func judgeInstallerXML(rel string, b []byte) installerFacts {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = false
	var els []xmlEl
	var stack []int
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return installerFacts{violations: []string{rel + ": not parseable as XML: " + err.Error()}}
		}
		switch t := tok.(type) {
		case xml.StartElement:
			e := xmlEl{Name: t.Name.Local, Attrs: map[string]string{}, Depth: len(stack)}
			for _, a := range t.Attr {
				e.Attrs[strings.ToLower(a.Name.Local)] = a.Value
			}
			els = append(els, e)
			stack = append(stack, len(els)-1)
		case xml.CharData:
			if len(stack) > 0 {
				els[stack[len(stack)-1]].Text += string(t)
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	var f installerFacts
	for _, e := range els {
		switch e.Name {
		case "ServiceInstall":
			f.services++
			if acct := e.Attrs["account"]; acct != pinnedAccount {
				f.violations = append(f.violations, fmt.Sprintf("%s: ServiceInstall Account is %q, must be exactly %q", rel, acct, pinnedAccount))
			}
			if e.Attrs["password"] != "" {
				f.violations = append(f.violations, rel+": ServiceInstall carries a Password; a virtual account has none")
			}
			fallthrough
		case "ServiceConfig":
			if v, ok := e.Attrs["servicesid"]; ok {
				f.sids = append(f.sids, v)
			}
			if v := e.Attrs["requiredprivileges"]; v != "" {
				f.privs = append(f.privs, splitPrivs(v)...)
			}
		case "RequiredPrivilege", "Privilege":
			if v := e.Attrs["name"]; v != "" {
				f.privs = append(f.privs, v)
			} else if v := strings.TrimSpace(e.Text); v != "" {
				f.privs = append(f.privs, v)
			}
		}
	}
	return f
}

func splitPrivs(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '[' || r == ']' || r == '\n' || r == '\t'
	})
}

func sameSet(a, b []string) bool {
	m := map[string]bool{}
	for _, s := range a {
		m[s] = true
	}
	if len(m) != len(b) {
		return false
	}
	for _, s := range b {
		if !m[s] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------------------------
// A4: the agent binary's import closure.

// a4Banned import-path prefixes: no LDAP, SMB, RPC, Kerberos or SSPI client (ADR-0006 rule 4). They
// exist for the message; the allowlist (closure-allow.txt) is what makes the check complete, because a
// denylist of third-party clients can never be.
var a4Banned = []string{
	"github.com/go-ldap/", "gopkg.in/ldap", "github.com/nmcclain/ldap", "github.com/mavricknz/ldap", "github.com/go-krb5/", "github.com/jcmturner/gokrb5",
	"github.com/alexbrainman/sspi", "github.com/hirochachacha/go-smb2", "github.com/cloudsoda/go-smb2",
	"github.com/oiweiwei/go-msrpc", "github.com/stacktitan/smb", "github.com/microsoft/go-mssqldb",
	"github.com/azure/go-ntlmssp", "github.com/masterzen/winrm", "github.com/bodgit/",
	"golang.org/x/sys/windows/svc/mgr", "golang.org/x/sys/windows/registry",
}

// a4BannedFragments match our own directory and connector packages anywhere in the closure.
var a4BannedFragments = []string{"/internal/directory", "/internal/connector"}

//go:embed closure-allow.txt
var embeddedClosureAllow string

// parseAllow reads an allowlist: one import path per line, `path/...` for a subtree, `#` comments.
func parseAllow(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if i := strings.Index(l, "#"); i >= 0 {
			l = l[:i]
		}
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func allowed(path string, allow []string) bool {
	for _, a := range allow {
		if a == path || (strings.HasSuffix(a, "/...") && strings.HasPrefix(path, strings.TrimSuffix(a, "..."))) {
			return true
		}
	}
	return false
}

func checkAgentImports(root string, allow []string) Result {
	r := Result{ID: "A4", What: "agent binary closure (linux and windows) holds only allowlisted non-stdlib packages and no LDAP, SMB, RPC, Kerberos or SSPI client (ADR-0006 rule 4)"}
	if _, err := os.Stat(filepath.Join(root, "cmd/agent")); err != nil {
		r.Inactive = "no cmd/agent"
		return r
	}
	seen := map[string]bool{}
	for _, goos := range []string{"windows", "linux"} {
		pkgs, err := goClosure(root, goos)
		if err != nil {
			r.Violations = append(r.Violations, "go list -deps ./cmd/agent (GOOS="+goos+"): "+err.Error())
			continue
		}
		for _, d := range judgeDeps(pkgs, allow) {
			if !seen[d] {
				seen[d] = true
				r.Violations = append(r.Violations, d+" (GOOS="+goos+")")
			}
		}
	}
	return r
}

// judgeDeps returns one message per package of the closure that is banned by name or, being outside the
// standard library, not on the allowlist.
func judgeDeps(deps []pkgInfo, allow []string) []string {
	var out []string
	for _, p := range deps {
		d := p.Path
		l := strings.ToLower(d)
		named := false
		for _, b := range a4Banned {
			if strings.HasPrefix(l, b) {
				out = append(out, "agent closure imports "+d+", a directory/network-identity client (ADR-0006 rule 4)")
				named = true
			}
		}
		for _, f := range a4BannedFragments {
			if strings.Contains(l, f) {
				out = append(out, "agent closure imports "+d+", our directory/connector code (ADR-0002 rule 3)")
				named = true
			}
		}
		if !named && !p.Std && !allowed(d, allow) {
			out = append(out, "agent closure imports "+d+", which is not on the allowlist tools/fitness/agenthost/closure-allow.txt (review what it can reach, then add it there)")
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// P1-P8, F1: the Go tests that carry ADR-0007's fitness function. They must exist, run and pass; a
// renamed, skipped or deleted test is a failure, not a silent pass.

var requiredTests = []struct{ ID, Prefix, Pkg string }{
	{"P1", "TestP1", "./internal/platform/agentpolicy"},
	{"P2", "TestP2", "./internal/platform/agentpolicy"},
	{"P3", "TestP3", "./internal/platform/agentpolicy"},
	{"P4", "TestP4", "./internal/platform/agentpolicy"},
	{"P5", "TestP5", "./internal/platform/agentpolicy"},
	{"P6", "TestP6", "./internal/platform/agentpolicy"},
	{"P7", "TestP7", "./internal/platform/agentpolicy"},
	{"P8", "TestP8", "./internal/platform/agentpolicy/signer"},
	{"F1", "TestF1", "./internal/platform/agentpolicy"},
	{"F1", "FuzzF1", "./internal/platform/agentpolicy"},
}

type testEvent struct {
	Action  string
	Package string
	Test    string
}

func checkTests(root string) Result {
	r := Result{ID: "P", What: pTestsWhat}
	cmd := exec.Command("go", "test", "-count=1", "-json", "-run", `^(TestP[1-8]|TestF1|FuzzF1)`,
		"./internal/platform/agentpolicy/...")
	cmd.Dir = root
	var out bytes.Buffer
	cmd.Stdout = &out
	var errb bytes.Buffer
	cmd.Stderr = &errb
	runErr := cmd.Run()
	r.Violations = judgeTests(out.Bytes())
	if runErr != nil && len(r.Violations) == 0 {
		r.Violations = append(r.Violations, "go test failed: "+runErr.Error()+" "+strings.TrimSpace(errb.String()))
	}
	return r
}

// judgeTests reads `go test -json` output and returns a violation for every required test that failed,
// was skipped, or never ran.
func judgeTests(jsonOut []byte) []string {
	status := map[string]string{} // package + "." + top-level test -> last terminal action
	var buildFail []string
	for _, line := range bytes.Split(jsonOut, []byte("\n")) {
		var e testEvent
		if len(bytes.TrimSpace(line)) == 0 || json.Unmarshal(line, &e) != nil {
			continue
		}
		if e.Test == "" {
			if e.Action == "fail" {
				buildFail = append(buildFail, e.Package)
			}
			continue
		}
		if strings.Contains(e.Test, "/") {
			if e.Action == "fail" {
				status[e.Package+"."+strings.SplitN(e.Test, "/", 2)[0]] = "fail"
			}
			continue
		}
		switch e.Action {
		case "pass", "fail", "skip":
			if status[e.Package+"."+e.Test] != "fail" {
				status[e.Package+"."+e.Test] = e.Action
			}
		}
	}
	var vs []string
	for _, rt := range requiredTests {
		pkg := "github.com/skenzeriq/activediq/" + strings.TrimPrefix(rt.Pkg, "./")
		found := false
		for k, st := range status {
			if !strings.HasPrefix(k, pkg+".") {
				continue
			}
			name := strings.TrimPrefix(k, pkg+".")
			if !strings.HasPrefix(name, rt.Prefix) {
				continue
			}
			found = true
			if st != "pass" {
				vs = append(vs, fmt.Sprintf("%s: %s %s", rt.ID, name, st))
			}
		}
		if !found {
			vs = append(vs, fmt.Sprintf("%s: no test named %s* ran in %s (renamed or deleted?)", rt.ID, rt.Prefix, rt.Pkg))
		}
	}
	for _, p := range buildFail {
		vs = append(vs, "package "+p+" failed")
	}
	sort.Strings(vs)
	return uniq(vs)
}

func uniq(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
