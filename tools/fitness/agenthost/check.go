package main

import (
	"archive/zip"
	"bytes"
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const pTestsWhat = "P1-P8 (ADR-0007) and F1 (out-of-bounds policy) tests exist, run and pass"

// Options selects what Run does.
type Options struct {
	SkipTests    bool
	Only         string
	ClosureAllow []string // overrides closure-allow.txt (fixtures); nil uses the reviewed file
	// InstallerAllow overrides installer-allow.txt (fixtures); nil uses the reviewed file.
	InstallerAllow []string
}

func installerAllow(o Options) []string {
	if o.InstallerAllow != nil {
		return o.InstallerAllow
	}
	return parseAllow(embeddedInstallerAllow)
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
	add("A1", checkInstallerAllow(root, installerAllow(o)))
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
// encoding, time and synchronisation. Package "os" is not here: it is allowed only as the named
// selectors in r3AllowedOS, because methods on its values (OpenRoot().Create, FindProcess().Kill,
// File.Chmod) cannot be told apart by name. To add one, review what it can reach.
var r3AllowedStd = setOf(
	"bytes", "bufio", "context", "errors", "fmt", "io", "log/slog", "maps", "math", "math/big", "math/bits",
	"path", "path/filepath", "regexp", "slices", "sort", "strconv", "strings", "sync", "sync/atomic",
	"time", "unicode", "unicode/utf16", "unicode/utf8", "encoding/binary", "encoding/hex", "encoding/json",
	"encoding/base64", "encoding/xml", "crypto/sha256", "crypto/subtle", "hash", "hash/fnv", "iter", "cmp",
)

// r3AllowedExt: the third-party packages an agent module may import (T-0688 ruling 1): pure text
// computation, no I/O, no process, no socket. Exact paths only; a new line is a security-architect review.
var r3AllowedExt = setOf("golang.org/x/text/cases", "golang.org/x/text/unicode/norm")

// r3AllowedOS: the only selectors of package os an agent module may use (environment and error values).
var r3AllowedOS = setOf("os.Getenv", "os.LookupEnv", "os.ErrNotExist", "os.ErrExist", "os.ErrPermission",
	"os.IsNotExist", "os.IsExist", "os.IsPermission")

// r3FilepathBanned: selectors of path/filepath that read the host filesystem directly (they enumerate
// C:\Windows\NTDS, follow links); contract §1 routes reads through the host's dependency struct.
var r3FilepathBanned = setOf("filepath.WalkDir", "filepath.Walk", "filepath.Glob", "filepath.EvalSymlinks")

// r3OwnPrefix and r3OwnExact: the own packages an agent module may import (its siblings, and the host's
// policy and dependency-struct packages), as paths under the module path read from go.mod.
var (
	r3OwnPrefix = []string{"/internal/agentmodules"}
	// internal/agenthost/api is the module boundary (T-0688 ruling 1): ModuleDeps, the event source and
	// sink, aliases for the wire data types and for grpc.ServiceRegistrar. internal/proto/activediq/addc/v1
	// is the module's own contract (typed data; a module gets its own, never skenzeriq/agent/v1 or fleet).
	r3OwnExact = []string{"/internal/platform/agentpolicy", "/internal/agenthost/api", "/internal/proto/activediq/addc/v1"}
)

const defaultModulePath = "github.com/skenzeriq/activediq"

// modulePath reads the module path from root/go.mod (fixture trees without one use the product's).
func modulePath(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "module" {
				return strings.Trim(f[1], "\"")
			}
		}
	}
	return defaultModulePath
}

// r3Named: the reason given for the imports most likely to be tried, so the message teaches.
var r3Named = map[string]string{
	"os/exec":                               "process execution (C1/C2)",
	"os/signal":                             "process signals",
	"os/user":                               "account lookup",
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
	foreign := foreignModuleFiles(root)
	if len(files) == 0 && len(foreign) == 0 {
		r.Inactive = "no Go source under internal/agentmodules (T-0600 onward)"
		return r
	}
	for _, f := range foreign {
		r.Violations = append(r.Violations, f+": only .go files (and testdata/) may sit in an agent module directory; assembly, objects and C sources link code the import scan cannot see")
	}
	mod := modulePath(root)
	// The module boundary itself (T-0688 ruling 1): it hands modules capabilities, so it may import only
	// pure standard-library packages, the wire data types it aliases, and grpc for ServiceRegistrar. It
	// can never be the way a module reaches os/exec, net, syscall or x/sys.
	for _, f := range goFiles(root, []string{"internal/agenthost/api"}) {
		scanGo(root, f, func(rel, imp, name string, line int) {
			if msg := judgeAPIImport(mod, imp, name); msg != "" {
				r.Violations = append(r.Violations, fmt.Sprintf("%s:%d %s", rel, line, msg))
			}
		}, func(string, string, int) {})
	}
	for _, f := range files {
		scanGo(root, f, func(rel, imp, name string, line int) {
			if msg := judgeModuleImport(mod, imp, name); msg != "" {
				r.Violations = append(r.Violations, fmt.Sprintf("%s:%d %s", rel, line, msg))
			}
		}, func(rel, call string, line int) {
			if strings.HasPrefix(call, "os.") && !r3AllowedOS[call] {
				r.Violations = append(r.Violations, fmt.Sprintf("%s:%d uses %s: an agent module may use only os.Getenv/LookupEnv and the os.Err* values; files and processes come from the host's dependency struct", rel, line, call))
			} else if r3FilepathBanned[call] {
				r.Violations = append(r.Violations, fmt.Sprintf("%s:%d calls %s: reading the host filesystem goes through the host's dependency struct (contract §1)", rel, line, call))
			} else if r3BannedCalls[call] || strings.HasPrefix(call, "ioutil.") {
				r.Violations = append(r.Violations, fmt.Sprintf("%s:%d calls %s: an agent module cannot mutate files or start processes (write through the host's data-directory capability)", rel, line, call))
			}
		})
	}
	return r
}

// judgeAPIImport: what internal/agenthost/api may import. Strictly the standard library the modules
// themselves may use, the agent wire types it aliases, and grpc (ServiceRegistrar). Not os, net, syscall.
func judgeAPIImport(mod, imp, name string) string {
	if name == "." || name == "_" {
		return fmt.Sprintf("dot or blank import of %s in the module boundary package", imp)
	}
	if r3AllowedStd[imp] || imp == mod+"/internal/proto/skenzeriq/agent/v1" || imp == "google.golang.org/grpc" {
		return ""
	}
	return fmt.Sprintf("the module boundary package internal/agenthost/api imports %s: it may import only the pure standard library, skenzeriq/agent/v1 and grpc (T-0688 ruling 1)", imp)
}

// foreignModuleFiles lists files under the agent-module directories that are not .go sources and not in
// a testdata directory (.s, .syso, .c, .h, .cc, .m, .S, .swig, ... all link code the AST scan cannot see).
func foreignModuleFiles(root string) []string {
	var out []string
	for _, d := range agentModuleDirs {
		_ = filepath.WalkDir(filepath.Join(root, d), func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				if e.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") {
				rel, _ := filepath.Rel(root, p)
				out = append(out, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

// judgeModuleImport returns "" when an agent module may import imp under the local name, else the reason.
func judgeModuleImport(mod, imp, name string) string {
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
	if r3AllowedStd[imp] || r3AllowedExt[imp] || imp == "os" {
		return ""
	}
	for _, o := range r3OwnPrefix {
		if imp == mod+o || strings.HasPrefix(imp, mod+o+"/") {
			return ""
		}
	}
	for _, o := range r3OwnExact {
		if imp == mod+o {
			return ""
		}
	}
	return fmt.Sprintf("imports %s, which is not on the agent-module allowlist (tools/fitness/agenthost r3AllowedStd, r3OwnPrefix, r3OwnExact): a module gets only the host's dependency struct", imp)
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
			case imp == "google.golang.org/grpc/credentials/insecure":
				add(fmt.Sprintf("%s:%d imports grpc/credentials/insecure: the agent's only network use is outbound mTLS (C5, T-0688 ruling 2)", rel, line))
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

// instFile is one file under packaging/ that concerns the agent, decoded to text.
type instFile struct {
	path, rel, text string
	agent           bool   // the path or body names the agent (a WiX file is judged either way)
	unreadable      string // why it could not be read as text; empty when text is valid
	xml             bool   // WiX by content (root element Wix/Include/WixLocalization) whatever the file is called (T-0677)
	problem         string // a walk error or symlink: reported as an A1 violation as it is (fail closed, T-0677)
}

var binaryExts = setOf(".ico", ".bmp", ".png", ".jpg", ".gif", ".dll", ".exe", ".cab", ".msi", ".cer", ".pfx", ".zip", ".gz", ".bin")

// decodeText returns the text of b, decoding UTF-16 (BOM or the NUL pattern of ASCII-range UTF-16) and
// stripping a UTF-8 BOM. ok is false when b has NULs and does not look like UTF-16.
func decodeText(b []byte) (string, bool) {
	switch {
	case bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}):
		return string(b[3:]), bytes.IndexByte(b, 0) < 0
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE, 0, 0}):
		return utf32Text(b[4:], false), true // T-0677: UTF-32LE BOM before the UTF-16LE case it prefixes
	case bytes.HasPrefix(b, []byte{0, 0, 0xFE, 0xFF}):
		return utf32Text(b[4:], true), true
	case bytes.HasPrefix(b, []byte{0xFF, 0xFE}):
		return utf16Text(b[2:], false), true
	case bytes.HasPrefix(b, []byte{0xFE, 0xFF}):
		return utf16Text(b[2:], true), true
	}
	// T-0677: mirror .NET XmlTextReaderImpl.DetectEncoding, which switches on the first two bytes of a
	// BOM-less document (XML 1.0 Appendix F is only the example): 3C00 is UTF-16LE (UCS-4LE when the next
	// two bytes are 0000) and 003C is UTF-16BE (the 3412 UCS-4 order, exotic, when they are 0000).
	if len(b) >= 4 {
		switch {
		case b[0] == 0x3C && b[1] == 0 && b[2] == 0 && b[3] == 0:
			return utf32Text(b, false), true
		case b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0x3C:
			return utf32Text(b, true), true
		}
	}
	if len(b) >= 2 {
		switch {
		case b[0] == 0x3C && b[1] == 0:
			return utf16Text(b, false), true
		case b[0] == 0 && b[1] == 0x3C:
			return utf16Text(b, true), true
		}
	}
	if bytes.IndexByte(b, 0) < 0 {
		return string(b), true
	}
	odd, even := 0, 0
	for i, c := range b {
		if c == 0 {
			if i%2 == 1 {
				odd++
			} else {
				even++
			}
		}
	}
	switch {
	case odd*4 >= len(b):
		return utf16Text(b, false), true
	case even*4 >= len(b):
		return utf16Text(b, true), true
	}
	return "", false
}

// exoticXMLEncoding reports the Appendix F signatures this check does not decode (unusual UCS-4 byte
// orders, EBCDIC): a file starting so is not classifiable and fails closed.
func exoticXMLEncoding(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	h := [4]byte{b[0], b[1], b[2], b[3]}
	// 2143 and 3412 orders (BOM and bare '<'), and EBCDIC '<?xm'.
	return h == [4]byte{0, 0, 0x3C, 0} || h == [4]byte{0, 0x3C, 0, 0} || h == [4]byte{0x4C, 0x6F, 0xA7, 0x94} ||
		h == [4]byte{0xFE, 0xFF, 0, 0} || h == [4]byte{0, 0, 0xFF, 0xFE}
}

const exoticProblem = "starts with an XML byte-order signature this check cannot decode (unusual UCS-4 order or EBCDIC): it could be a WiX document, so it is not classifiable"

// declEncodingRe matches the encoding pseudo-attribute of a leading XML declaration.
var declEncodingRe = regexp.MustCompile(`(?is)^\s*<\?xml\s[^>]*?\bencoding\s*=\s*["']([^"']*)["']`)

// wideEncoded reports whether decodeText decodes b as UTF-16 or UTF-32 (the detection .NET keeps for the
// utf-16, ucs-2 and ucs-4 declarations).
func wideEncoded(b []byte) bool {
	if bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
		return false
	}
	return bytes.IndexByte(b, 0) >= 0 || bytes.HasPrefix(b, []byte{0xFF, 0xFE}) || bytes.HasPrefix(b, []byte{0xFE, 0xFF})
}

// encodingProblem mirrors the two ways .NET's XmlTextReaderImpl picks an encoding (T-0677): DetectEncoding on
// the first bytes (exoticXMLEncoding fails closed on what is not decoded) and CheckEncoding/SwitchEncoding on
// the declaration's encoding name. Only names whose bytes this check decodes the same way are accepted; any
// other name could make the parser re-decode the rest of the file into WiX this check never saw.
func encodingProblem(b []byte) string {
	if exoticXMLEncoding(b) {
		return exoticProblem
	}
	t, _ := decodeText(b) // undecodable: the raw bytes below still carry an ASCII declaration
	wide := wideEncoded(b)
	// The declaration is read from the decoded text and from the raw bytes: a document whose prolog is ASCII
	// and whose body is another encoding (utf-32 declared in an ASCII prolog) decodes as garbage as a whole.
	for _, src := range []string{strings.TrimPrefix(t, "\uFEFF"), string(b)} {
		m := declEncodingRe.FindStringSubmatch(src)
		if m == nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(m[1])) {
		case "utf-16", "ucs-2", "iso-10646-ucs-2", "ucs-4":
			if wide {
				continue
			}
		case "utf-8":
			if !wide {
				continue
			}
		case "us-ascii", "iso-8859-1", "windows-1252":
			// .NET's ASCII decoder turns every byte >= 0x80 into '?', which can hide a document boundary
			// from this check; only pure-ASCII files decode identically under these names.
			if !wide && isPureASCII(b) {
				continue
			}
		}
		return "declares an encoding this check does not decode (" + m[1] + "): it could be a WiX document the build reads differently, so it is not classifiable"
	}
	return ""
}

func isPureASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

func utf32Text(b []byte, bigEndian bool) string {
	r := make([]rune, 0, len(b)/4)
	for i := 0; i+3 < len(b); i += 4 {
		var v uint32
		if bigEndian {
			v = uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
		} else {
			v = uint32(b[i+3])<<24 | uint32(b[i+2])<<16 | uint32(b[i+1])<<8 | uint32(b[i])
		}
		if v > utf8.MaxRune {
			v = utf8.RuneError
		}
		r = append(r, rune(v))
	}
	return string(r)
}

func utf16Text(b []byte, bigEndian bool) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if bigEndian {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		} else {
			u = append(u, uint16(b[i+1])<<8|uint16(b[i]))
		}
	}
	return string(utf16.Decode(u))
}

// agentInstallerFiles are every WiX source under packaging/ (a service or custom action can name the agent
// through a variable) and the other files that name the agent in their relative path or body:
// also install scripts, custom actions and anything else a service account can be set in
// (ADR-0006 A1 covers any LocalSystem string in the MSI source). UTF-16 files are decoded. A file whose
// path names the agent that cannot be read as text, or is too large, fails closed (no extension
// exempts a file from the content check).
func agentInstallerFiles(root string) []instFile {
	var out []instFile
	rootReal, rerr := filepath.EvalSymlinks(root)
	if rerr != nil {
		rootReal = root
	}
	_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		relp, _ := filepath.Rel(root, p)
		relp = filepath.ToSlash(relp)
		if err != nil {
			// T-0677: a directory or file the walk cannot read hides WiX the SDK may still compile; fail closed.
			out = append(out, instFile{path: p, rel: relp, problem: "cannot be walked (" + err.Error() + "): an unreadable path under the repo could hide a WiX source the build compiles"})
			if e != nil && e.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if e.Type()&fs.ModeSymlink != 0 {
			// T-0677: WalkDir does not follow symlinks, MSBuild globs and Includes may. A link anywhere in the
			// repo that is WiX-named, dangling, resolves to a directory, leaves the repo, or whose target is
			// WiX (by name or content) is a violation, so nothing the build reaches through a link was left
			// unscanned. Plain file links that stay inside the repo (node_modules/.bin) pass.
			if prob := linkProblem(rootReal, p); prob != "" {
				out = append(out, instFile{path: p, rel: relp, problem: prob})
			}
			return nil
		}
		if e.IsDir() {
			switch e.Name() {
			case ".git":
				return filepath.SkipDir
			}
			// testdata/ and node_modules/ are deliberately NOT skipped (T-0664): the WiX SDK compiles
			// **/*.wxs and a .wixproj can Compile-Include any path, so reachability cannot be guessed;
			// every WiX-named file in the repo, tools/fitness included, is scanned or fails A1. Test
			// fixtures therefore must not have WiX names on disk (they are Go strings in t.TempDir()).
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if wixIntermediateExts[ext] {
			out = append(out, instFile{path: p, rel: relp, problem: "is a prebuilt WiX intermediate (" + ext + "): it is opaque and can carry a compiled ServiceInstall; the installer is built from reviewed source only"})
			return nil
		}
		if hasWixIR(p) {
			out = append(out, instFile{path: p, rel: relp, problem: "is an archive holding wix-ir.json (a prebuilt WiX intermediate under another name): the installer is built from reviewed source only"})
			return nil
		}
		inPack := strings.HasPrefix(relp, "packaging/")
		named := isRepoWix(p)
		info, ierr := e.Info()
		if binaryExts[ext] && !named {
			// T-0677: an extension never exempts a file from the content check (WiX compiles whatever the
			// file is called). A real binary has NULs and is not text, so it passes cheaply.
			if ierr != nil {
				out = append(out, instFile{path: p, rel: relp, problem: "cannot be inspected: " + ierr.Error()})
				return nil
			}
			text, wix, prob := sniffWix(p, info.Size())
			switch {
			case prob != "":
				out = append(out, instFile{path: p, rel: relp, problem: prob})
			case wix:
				out = append(out, instFile{path: p, rel: relp, text: text, agent: agentBodyRe.MatchString(text), xml: true})
			}
			return nil
		}
		if !inPack && !named {
			// T-0677: WiX compiles whatever the file is called and <?include?> takes any name, so every text
			// file is classified by CONTENT: a well-formed XML document rooted at Wix, Include or
			// WixLocalization is WiX wherever it sits.
			if ierr != nil {
				out = append(out, instFile{path: p, rel: relp, problem: "cannot be inspected: " + ierr.Error()})
				return nil
			}
			text, wix, prob := sniffWix(p, info.Size())
			switch {
			case prob != "":
				out = append(out, instFile{path: p, rel: relp, problem: prob})
			case wix:
				out = append(out, instFile{path: p, rel: relp, text: text, agent: agentBodyRe.MatchString(text), xml: true})
			}
			return nil
		}
		rel := relp
		inPath := inPack && agentFileRe.MatchString(strings.TrimPrefix(rel, "packaging/"))
		wix := isWixXML(p) || isTemplate(p) || !inPack
		if ierr != nil || info.Size() > 4<<20 {
			if inPath || wix {
				out = append(out, instFile{path: p, rel: rel, unreadable: "is too large to scan"})
			}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			if inPath || wix {
				out = append(out, instFile{path: p, rel: rel, unreadable: err.Error()})
			}
			return nil
		}
		if prob := encodingProblem(b); prob != "" {
			out = append(out, instFile{path: p, rel: rel, problem: prob})
			return nil
		}
		text, ok := decodeText(b)
		if !ok {
			if inPath || wix {
				out = append(out, instFile{path: p, rel: rel, unreadable: "cannot be read as text"})
			}
			return nil
		}
		content := false
		if !isWixXML(p) && !isTemplate(p) {
			content, _ = wixByContent(text)
		}
		isAgent := inPath || agentBodyRe.MatchString(text)
		if isAgent || wix || content {
			out = append(out, instFile{path: p, rel: rel, text: text, agent: isAgent, xml: content})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out
}

// wixIntermediateExts are prebuilt WiX intermediates (zips holding wix-ir.json): opaque to this check.
var wixIntermediateExts = setOf(".wixlib", ".wixipl", ".wixobj")

// wixRoots are the root elements of a WiX compiler input (any namespace).
var wixRoots = setOf("Wix", "Include", "WixLocalization")

// wixByContent reports whether text is a well-formed-at-the-start XML document whose root element is a WiX
// one. undecided is true when only a prolog (comments, PIs, whitespace) was seen before the text ended.
func wixByContent(text string) (wix, undecided bool) {
	d := xml.NewDecoder(strings.NewReader(text))
	d.Strict = false
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	for {
		tok, err := d.RawToken()
		if err != nil {
			// Only a text that ends inside its prolog is undecided; a syntax error is not an XML document.
			var se *xml.SyntaxError
			return false, err == io.EOF || (errors.As(err, &se) && strings.Contains(se.Msg, "unexpected EOF"))
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return wixRoots[t.Name.Local], false
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return false, false // not an XML document (a Go or shell file holding a snippet)
			}
		}
	}
}

// sniffWix classifies an unnamed file by content: the head first, the whole file (up to 4 MiB) when the head
// is only a prolog. A file that stays undecided and is too large to read fails closed.
func sniffWix(p string, size int64) (text string, wix bool, problem string) {
	const head = 64 << 10
	f, err := os.Open(p)
	if err != nil {
		return "", false, "cannot be read (" + err.Error() + "): an unreadable file could be WiX the build compiles"
	}
	buf := make([]byte, head)
	n, _ := io.ReadFull(f, buf)
	f.Close()
	if prob := encodingProblem(buf[:n]); prob != "" {
		return "", false, prob
	}
	t, ok := decodeText(buf[:n])
	if !ok {
		return "", false, ""
	}
	w, undecided := wixByContent(t)
	if w {
		if size > 4<<20 {
			return "", false, "is a WiX document too large to scan"
		}
		full, ok, prob := readCheckedText(p)
		if prob != "" {
			return "", false, prob
		}
		if !ok {
			return "", false, "is a WiX document that cannot be read as text"
		}
		return full, true, ""
	}
	if undecided && size > int64(n) {
		if size > 4<<20 {
			return "", false, "starts with a long XML prolog and is too large to classify: it could be a WiX document"
		}
		full, ok, prob := readCheckedText(p)
		if prob != "" {
			return "", false, prob
		}
		if !ok {
			return "", false, ""
		}
		if w, _ := wixByContent(full); w {
			return full, true, ""
		}
	}
	return "", false, ""
}

// readCheckedText reads the whole file, runs encodingProblem on every byte, then decodes. Every full read
// goes through here so no path can skip the encoding rule.
func readCheckedText(p string) (text string, ok bool, problem string) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false, "cannot be read (" + err.Error() + ")"
	}
	if prob := encodingProblem(b); prob != "" {
		return "", false, prob
	}
	text, ok = decodeText(b)
	return text, ok, ""
}

// hasWixIR: a zip (PK\x03\x04) holding a wix-ir.json entry is a WiX intermediate whatever its name.
func hasWixIR(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	var m [4]byte
	_, rerr := io.ReadFull(f, m[:])
	f.Close()
	if rerr != nil || m != [4]byte{'P', 'K', 3, 4} {
		return false
	}
	z, err := zip.OpenReader(p)
	if err != nil {
		return false
	}
	defer z.Close()
	for _, zf := range z.File {
		if path.Base(zf.Name) == "wix-ir.json" {
			return true
		}
	}
	return false
}

// linkProblem judges a symlink: empty means it is a harmless in-repo link to a non-WiX file.
func linkProblem(rootReal, p string) string {
	if isRepoWix(p) {
		return "is a symbolic link named like a WiX source: the scan does not follow it, the build might; copy the content in instead"
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "is a symbolic link that cannot be resolved (dangling or looping): the build agent may resolve it to WiX the scan never saw"
	}
	if rel, rerr := filepath.Rel(rootReal, real); rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "is a symbolic link that leaves the repository: its target is outside the scan"
	}
	st, err := os.Stat(real)
	if err != nil {
		return "is a symbolic link whose target cannot be read"
	}
	if st.IsDir() {
		return "is a symbolic link to a directory: the scan does not follow it, an MSBuild glob or Include might; copy the content in instead"
	}
	if isRepoWix(real) || wixIntermediateExts[strings.ToLower(filepath.Ext(real))] || hasWixIR(real) {
		return "is a symbolic link to a WiX file: the scan does not follow it; copy the content in instead"
	}
	if _, wix, prob := sniffWix(real, st.Size()); wix || prob != "" {
		return "is a symbolic link to a WiX document (by content) or to a file that cannot be classified: copy the content in instead"
	}
	return ""
}

// templateExts are generators of WiX (heat/xslt transforms, preprocessed templates): they are not parsed,
// so they are denied under packaging/ unless a reviewed installer-allow.txt entry lists them.
var templateExts = setOf(".in", ".tmpl", ".tpl", ".template", ".xsl", ".xslt", ".j2", ".erb", ".mustache")

func isTemplate(p string) bool { return templateExts[strings.ToLower(filepath.Ext(p))] }

// isRepoWix: a WiX source or WiX template anywhere in the repo, not only under packaging/ (ADR-0006 A1 says
// any LocalSystem string in the MSI source fails, wherever the MSI source sits).
func isRepoWix(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".wxs", ".wxi", ".wxl", ".wixproj":
		return true
	}
	return wixTemplateRe.MatchString(strings.ToLower(filepath.Base(p)))
}

var wixTemplateRe = regexp.MustCompile(`\.(wxs|wxi|wxl|wixproj)\.[a-z0-9]+$`)

func isWixXML(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".wxs", ".wxi", ".wxl", ".wixproj", ".xml":
		return true
	}
	return false
}

var (
	docTypeRe     = regexp.MustCompile(`(?i)<!(DOCTYPE|ENTITY)`)
	namedEntityRe = regexp.MustCompile(`(?i)&([a-z_][\w.-]*);`)
)

func hasNamedEntity(text string) bool {
	for _, m := range namedEntityRe.FindAllStringSubmatch(text, -1) {
		switch strings.ToLower(m[1]) {
		case "amp", "lt", "gt", "quot", "apos":
		default:
			return true
		}
	}
	return false
}

// scAccountRe finds a service created or reconfigured with an account: sc.exe config/create ... obj=,
// Set-Service/New-Service ... -Credential. Such a line must name the pinned account and nothing else.
var scAccountRe = regexp.MustCompile(`(?i)((sc(\.exe)?\s+(config|create)|set-service|new-service)[^\n]*(obj\s*=|-credential)|win32_service[^\n]*(change|create|startname)|startname|changeserviceconfig|createservice)`)

// svcRegistryRe finds any reference to a service's registry key, where the account (ObjectName), SID type
// (ServiceSidType) and privileges (RequiredPrivileges) can be set without ServiceInstall: from WiX
// RegistryKey/RegistryValue, reg.exe, New-ItemProperty or Set-ItemProperty alike.
var svcRegistryRe = regexp.MustCompile(`(?i)(currentcontrolset|controlset\d+)\\+services`)

var scriptExts = setOf(".ps1", ".psm1", ".psd1", ".cmd", ".bat", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".sh", ".py", ".pl", ".hta")

func checkInstaller(root string) Result {
	return checkInstallerAllow(root, parseAllow(embeddedInstallerAllow))
}

func checkInstallerAllow(root string, allow []string) Result {
	r := Result{ID: "A1", What: "agent installer names " + pinnedAccount + ", service SID type " + pinnedSidType + ", the pinned RequiredPrivileges, no LocalSystem, and no custom action or script unless reviewed (ADR-0006 rules 1, 3)"}
	files := agentInstallerFiles(root)
	if len(files) == 0 {
		r.Inactive = "no agent installer source under packaging/ (windows-engineer's MSI ticket)"
		return r
	}
	services := 0
	namedAgent := false
	for _, f := range files {
		rel := f.rel
		if f.problem != "" {
			r.Violations = append(r.Violations, fmt.Sprintf("%s %s (ADR-0006 A1 fails closed)", rel, f.problem))
			continue
		}
		if f.unreadable != "" {
			r.Violations = append(r.Violations, fmt.Sprintf("%s %s: a WiX source or agent packaging file must be readable text", rel, f.unreadable))
			continue
		}
		// Every file here is WiX or names the agent: LocalSystem and the Services registry key are
		// forbidden in all of it, whichever service the element claims to configure.
		if svcRegistryRe.MatchString(f.text) {
			r.Violations = append(r.Violations, fmt.Sprintf("%s references the Services registry key: the account, SID type and privileges are set only by ServiceInstall/ServiceConfig, never through the registry (ADR-0006 rules 1, 3)", rel))
		}
		if m := localSystemRe.FindString(f.text); m != "" {
			r.Violations = append(r.Violations, fmt.Sprintf("%s names %q: the agent never runs as LocalSystem or a shared service identity (ADR-0006 rule 1)", rel, m))
		}
		if isTemplate(f.path) && !allowed(rel, allow) {
			r.Violations = append(r.Violations, fmt.Sprintf("%s is a template or transform under packaging/: it is not parsed, so it could emit a ServiceInstall, ServiceSid or ACL the check never sees; list it in installer-allow.txt after a security-architect review", rel))
		}
		if (isWixXML(f.path) || f.xml) && (docTypeRe.MatchString(f.text) || hasNamedEntity(f.text)) && !allowed(rel, allow) {
			r.Violations = append(r.Violations, fmt.Sprintf("%s declares a DOCTYPE or ENTITY, or uses a named entity other than amp, lt, gt, quot, apos: a name, account or SID built from an entity cannot be read", rel))
		}
		if (isWixXML(f.path) || f.xml) && strings.Contains(f.text, "&#") && !allowed(rel, allow) {
			r.Violations = append(r.Violations, fmt.Sprintf("%s contains a numeric character reference (&#...): names, accounts and SIDs must be plain text so they can be read", rel))
		}
		if f.agent {
			for _, line := range strings.Split(f.text, "\n") {
				if scAccountRe.MatchString(line) && !strings.Contains(strings.ToLower(line), strings.ToLower(pinnedAccount)) {
					r.Violations = append(r.Violations, fmt.Sprintf("%s sets a service account other than %s: %q", rel, pinnedAccount, strings.TrimSpace(line)))
				}
			}
			if scriptExts[strings.ToLower(filepath.Ext(f.path))] && !allowed(rel, allow) {
				r.Violations = append(r.Violations, fmt.Sprintf("%s is a script in the agent packaging: nothing may compute the service account, SID type or privileges in a script; list it in installer-allow.txt after a security-architect review", rel))
			} else if !isWixXML(f.path) && !f.xml && !isTemplate(f.path) && !scriptExts[strings.ToLower(filepath.Ext(f.path))] && !allowed(rel, allow) {
				r.Violations = append(r.Violations, fmt.Sprintf("%s is an unknown file type in the agent packaging: only WiX (parsed), known binaries and files listed in installer-allow.txt are allowed", rel))
			}
		}
		if !isWixXML(f.path) && !f.xml {
			continue
		}
		x := judgeInstallerXML(rel, []byte(f.text), allow, f.agent)
		if x.namesAgent {
			namedAgent = true
		}
		if m := localSystemRe.FindString(x.attrText); m != "" && !localSystemRe.MatchString(f.text) {
			r.Violations = append(r.Violations, fmt.Sprintf("%s names %q once its XML is decoded: the agent never runs as LocalSystem or a shared service identity (ADR-0006 rule 1)", rel, m))
		}
		services += x.services
		r.Violations = append(r.Violations, x.violations...)
	}
	switch {
	case !anyAgentSource(files) && !namedAgent:
		// Only WiX sources that never name the agent (a core MSI): their LocalSystem, registry, action and
		// literal-name rules above still apply, but there is no agent service to pin yet.
	case services == 0:
		r.Violations = append(r.Violations, "no ServiceInstall naming the agent service in the installer source: the account cannot be verified")
	case services > 1:
		r.Violations = append(r.Violations, fmt.Sprintf("%d ServiceInstall elements for the agent service in the installer source, must be exactly one", services))
	default:
	}
	return r
}

// anyAgentSource reports whether some packaging file names the agent (or cannot be read to tell).
func anyAgentSource(files []instFile) bool {
	for _, f := range files {
		if f.agent || f.unreadable != "" {
			return true
		}
	}
	return false
}

type xmlEl struct {
	Name   string
	Attrs  map[string]string
	Text   string
	Parent int // index of the parent element, -1 at the root
}

type installerFacts struct {
	services   int
	namesAgent bool   // a parsed (entity-decoded) element names the agent service
	attrText   string // every decoded attribute value and text node, for the string rules
	violations []string
}

// dynamicRe: a WiX value that is resolved at build or install time, so the text cannot be judged.
var dynamicRe = regexp.MustCompile(`\$\(|\[|!\(`)

// serviceEls are the WiX elements that name a service; the name must be a literal.
var serviceEls = setOf("ServiceInstall", "ServiceConfig", "ServiceControl")

// registryEls write or remove registry data.
var registryEls = setOf("RegistryKey", "RegistryValue", "RemoveRegistryKey", "RemoveRegistryValue")

// actionEls run code at install time; each needs a reviewed allowlist entry by Id.
var actionEls = setOf("CustomAction", "Binary")

// pinnedActions: the CustomActions approved in T-0688 ruling 4, with the exact attributes reviewed. Each
// runs agentsetup.exe from the private directory AgentDir (mixed case: not a public property, so it cannot
// be redirected from the msiexec command line), as SYSTEM, deferred, with a fixed command line.
var pinnedActions = func() map[string]map[string]string {
	cmd := func(sub string) string { return `"[AgentDir]agentsetup.exe" ` + sub }
	a := func(exec, ret, sub string) map[string]string {
		return map[string]string{"execute": exec, "impersonate": "no", "return": ret, "directory": "AgentDir", "execommand": cmd(sub)}
	}
	return map[string]map[string]string{
		"WriteConfig":          a("deferred", "check", "write-config"),
		"PrepareDataDir":       a("deferred", "check", "prepare-datadir"),
		"GrantChannel":         a("deferred", "check", "grant-channel"),
		"RollbackGrantChannel": a("rollback", "ignore", "revoke-channel"),
		"RevokeChannel":        a("deferred", "ignore", "revoke-channel"),
	}
}()

// pinnedPermissions: the reviewed Permission/PermissionEx elements, keyed "<parent element>/<parent Id>"
// (WiX Ids are unique per table, not globally, so the Id alone is not an identity). Each value holds the
// exact attributes (lower-cased names) plus "" -> the element's local name. Empty today: the installer
// source grants no ACL through WiX. Adding an entry is a security-architect review (T-0725).
var pinnedPermissions = map[string]map[string]string{}

// isDirEl: the elements that define or reference a directory.
func isDirEl(n string) bool {
	return n == "Directory" || n == "StandardDirectory" || n == "DirectoryRef"
}

// dirChain returns the pin string for the directory defined by element k: the chain of Directory and
// StandardDirectory elements from the outermost down, each as "Element:Id:Name". A DirectoryRef never ends
// the chain: it is resolved to the single element in this file that defines its Id. ok is false when an Id
// has no definition, or more than one, in this file (it may live in another fragment), or on a cycle.
func dirChain(els []xmlEl, k, depth int) (string, bool) {
	if depth > 32 {
		return "", false
	}
	var parts []string
	for ; k >= 0; k = els[k].Parent {
		switch els[k].Name {
		case "Directory", "StandardDirectory":
			parts = append([]string{els[k].Name + ":" + els[k].Attrs["id"] + ":" + els[k].Attrs["name"]}, parts...)
		case "DirectoryRef":
			d, ok := dirByID(els, els[k].Attrs["id"], depth+1)
			if !ok {
				return "", false
			}
			return strings.Join(append([]string{d}, parts...), "/"), true
		}
	}
	return strings.Join(parts, "/"), len(parts) > 0
}

// dirByID resolves a directory Id to its one defining Directory/StandardDirectory element in the file.
func dirByID(els []xmlEl, id string, depth int) (string, bool) {
	def := -1
	for i, e := range els {
		if (e.Name == "Directory" || e.Name == "StandardDirectory") && id != "" && e.Attrs["id"] == id {
			if def >= 0 {
				return "", false
			}
			def = i
		}
	}
	if def < 0 {
		return "", false
	}
	return dirChain(els, def, depth)
}

// effectiveDirectory resolves the directory a CreateFolder or File acts on, walking up from element i:
// the element's own Directory attribute, else the nearest Component (or ComponentGroup) Directory
// attribute, else the nearest enclosing Directory/StandardDirectory/DirectoryRef. Every Id is resolved to
// its defining element and the whole chain is pinned, so renaming or re-parenting it changes the pin.
func effectiveDirectory(els []xmlEl, i int) (string, bool) {
	if d := els[i].Attrs["directory"]; d != "" {
		return dirByID(els, d, 0)
	}
	for j := els[i].Parent; j >= 0; j = els[j].Parent {
		switch els[j].Name {
		case "Component", "ComponentGroup":
			if d := els[j].Attrs["directory"]; d != "" {
				return dirByID(els, d, 0)
			}
		case "Directory", "StandardDirectory", "DirectoryRef":
			return dirChain(els, j, 0)
		}
	}
	return "", false
}

// parentTarget returns the pin keys ("parent.<attr>") naming the object a Permission's parent acts on,
// resolved through its ancestors; ok is false when the target cannot be resolved or the parent type is
// unknown, which fails closed (T-0730).
func parentTarget(els []xmlEl, p int) (map[string]string, bool) {
	e := els[p]
	t := map[string]string{}
	switch e.Name {
	case "ServiceInstall":
		t["parent.name"] = e.Attrs["name"]
		return t, e.Attrs["name"] != ""
	case "CreateFolder":
		d, ok := effectiveDirectory(els, p)
		t["parent.directory"] = d
		return t, ok
	case "File":
		d, ok := effectiveDirectory(els, p)
		name := e.Attrs["name"]
		if name == "" {
			name = e.Attrs["source"]
			if n := strings.LastIndexAny(name, `\/`); n >= 0 {
				name = name[n+1:]
			}
		}
		t["parent.directory"], t["parent.name"] = d, name
		return t, ok && name != ""
	case "RegistryKey", "RegistryValue":
		root, key := registryRootKey(els, p)
		t["parent.root"], t["parent.key"] = root, key
		if e.Name == "RegistryValue" {
			t["parent.name"] = e.Attrs["name"]
		}
		return t, root != ""
	}
	return nil, false
}

func samePermission(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			return false
		}
	}
	return true
}

func isAgentName(s string) bool { return agentBodyRe.MatchString(s) }

// judgeInstallerXML reads one WiX file. The ServiceInstall for the agent service, every ServiceSid and
// privilege on the agent service, the literal-name rule for every service element, the deny-by-default
// custom action rule and the ban on HKLM\SYSTEM registry writes are judged here.
func judgeInstallerXML(rel string, b []byte, allow []string, agentFile bool) installerFacts {
	dec := xml.NewDecoder(bytes.NewReader(b))
	dec.Strict = false
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil } // text is already decoded
	var els []xmlEl
	var stack []int
	var attrText strings.Builder
	var attrDups []string
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
			e := xmlEl{Name: t.Name.Local, Attrs: map[string]string{}, Parent: -1}
			if len(stack) > 0 {
				e.Parent = stack[len(stack)-1]
			}
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
					continue // namespace declarations are not WiX attributes
				}
				k := strings.ToLower(a.Name.Local)
				if _, dup := e.Attrs[k]; dup {
					// T-0730: last-wins would let a second spelling hide the value that is judged.
					attrDups = append(attrDups, fmt.Sprintf("%s: element %s has attribute %q more than once (duplicate, or names differing only by case or namespace): the judged value would be ambiguous", rel, t.Name.Local, k))
				}
				e.Attrs[k] = a.Value
				attrText.WriteString(a.Value + "\n")
			}
			els = append(els, e)
			stack = append(stack, len(els)-1)
		case xml.CharData:
			if len(stack) > 0 {
				els[stack[len(stack)-1]].Text += string(t)
				attrText.Write(t)
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	var f installerFacts
	f.violations = append(f.violations, attrDups...)
	f.attrText = attrText.String()
	fail := func(format string, a ...any) { f.violations = append(f.violations, rel+": "+fmt.Sprintf(format, a...)) }
	// agentSvc: the element is the agent's ServiceInstall, or sits under it.
	agentSvc := func(i int) bool {
		for ; i >= 0; i = els[i].Parent {
			if els[i].Name == "ServiceInstall" && isAgentName(els[i].Attrs["name"]) {
				return true
			}
		}
		return false
	}
	for i, e := range els {
		switch {
		case serviceEls[e.Name]:
			name := e.Attrs["name"]
			if e.Name == "ServiceConfig" {
				if v, ok := e.Attrs["servicename"]; ok {
					name = v
				}
			}
			if dynamicRe.MatchString(name) {
				fail("%s names its service %q through a variable or property: the service name must be a literal so the account and SID type can be judged", e.Name, name)
			}
			if e.Name == "ServiceInstall" {
				acct := e.Attrs["account"]
				switch {
				case acct == "":
					fail("ServiceInstall %q has no Account: the service would run as LocalSystem", name)
				case !isAgentName(name) && !strings.EqualFold(acct, `NT SERVICE\`+name) && !allowed(e.Attrs["id"], allow):
					fail("ServiceInstall %q runs as %q: every service must run as its own virtual account NT SERVICE\\<its name> (or be listed by Id in installer-allow.txt after review)", name, acct)
				}
			}
			if isAgentName(name) || agentSvc(i) {
				f.namesAgent = true
			}
			if e.Name == "ServiceInstall" && agentSvc(i) && isAgentName(name) {
				f.services++
				if acct := e.Attrs["account"]; acct != pinnedAccount {
					fail("ServiceInstall Account is %q, must be exactly %q", acct, pinnedAccount)
				}
				if e.Attrs["password"] != "" {
					fail("ServiceInstall carries a Password; a virtual account has none")
				}
			}
		case e.Name == "Permission" || e.Name == "PermissionEx":
			// T-0725: WiX Ids are per table, so a parent Id that equals a reviewed CustomAction Id says
			// nothing about the ACL. A permission is judged by parent element type + Id, with its exact
			// attributes pinned in pinnedPermissions; installer-allow.txt plays no part.
			ptype, pid := "", ""
			if e.Parent >= 0 {
				ptype, pid = els[e.Parent].Name, els[e.Parent].Attrs["id"]
			}
			want, ok := pinnedPermissions[ptype+"/"+pid]
			switch {
			case pid == "" || dynamicRe.MatchString(pid) || !ok:
				fail("%s under %s %q grants an ACL that is not in the reviewed permission pins: a weak service or data-directory DACL lets any local user reconfigure the agent (on a DC that is SYSTEM); pin the parent element type, Id and exact attributes in pinnedPermissions after a security-architect review (T-0725)", e.Name, ptype, pid)
			default:
				got := map[string]string{"": e.Name}
				for k, v := range e.Attrs {
					got[k] = v
				}
				// T-0730: the pin also fixes the parent's target, so retargeting the parent cannot
				// carry a reviewed ACL onto another object. Pin keys: "parent.<attr>".
				tgt, resolved := parentTarget(els, e.Parent)
				if !resolved {
					fail("%s under %s %q: the parent's effective target cannot be resolved (unknown parent type, or its directory/registry root comes from a ComponentRef or another fragment); an unresolved target cannot be pinned (T-0730)", e.Name, ptype, pid)
					break
				}
				for k, v := range tgt {
					got[k] = v
				}
				if !samePermission(got, want) {
					fail("%s under %s %q differs from the reviewed pin (attributes %v, reviewed %v): a changed SDDL or grant is a new ACL and needs a new review (T-0725)", e.Name, ptype, pid, got, want)
				}
			}
		case actionEls[e.Name]:
			id := e.Attrs["id"]
			if id == "" || dynamicRe.MatchString(id) || !allowed(id, allow) {
				fail("%s %q runs code at install time: the account, SID type and privileges may not be computed there; list the Id in installer-allow.txt after a security-architect review", e.Name, id)
			} else if want, pinned := pinnedActions[id]; pinned && e.Name == "CustomAction" {
				// T-0688 ruling 4: an approved Id is approved with exactly these attributes; a changed
				// command line, sequence type or identity is a new action and needs a new review.
				for _, k := range []string{"execute", "impersonate", "return", "directory", "execommand"} {
					if got := e.Attrs[k]; got != want[k] {
						fail("CustomAction %q attribute %s is %q, the reviewed value is %q (T-0688 ruling 4)", id, k, got, want[k])
					}
				}
				for k := range e.Attrs {
					if k != "id" && want[k] == "" {
						fail("CustomAction %q has attribute %s, which the reviewed action does not have (T-0688 ruling 4)", id, k)
					}
				}
			}
		case registryEls[e.Name]:
			root, key := registryRootKey(els, i)
			upper := strings.ToUpper(root)
			if upper == "HKCU" || upper == "HKCR" || upper == "HKU" {
				continue
			}
			trim := strings.TrimLeft(strings.ToLower(key), `\/ `)
			if strings.HasPrefix(trim, `system\`) || trim == "system" || dynamicRe.MatchString(key) || dynamicRe.MatchString(root) {
				fail("%s writes HKLM key %q: the installer has no business under HKLM\\SYSTEM (the service account, SID type and privileges live there) and a key built from a property or variable cannot be judged", e.Name, key)
			}
		}
	}
	// Rule 3 for EVERY service: the SID type and privileges of each ServiceInstall (its own attributes, its
	// descendants, and any ServiceConfig naming it in this file) must be the pin, unless the ServiceInstall
	// Id is on the reviewed list. A second service running the agent binary gets no weaker SID or extra
	// privileges.
	var orphans []int
	for i, e := range els {
		if e.Name != "ServiceConfig" {
			continue
		}
		owned := false
		for j := i; j >= 0; j = els[j].Parent {
			if els[j].Name == "ServiceInstall" {
				owned = true
			}
		}
		if !owned {
			orphans = append(orphans, i)
		}
	}
	for i, e := range els {
		if e.Name != "ServiceInstall" {
			continue
		}
		name := e.Attrs["name"]
		var sids, privs []string
		take := func(x xmlEl) {
			if v, ok := x.Attrs["servicesid"]; ok {
				sids = append(sids, v)
			}
			if v := x.Attrs["requiredprivileges"]; v != "" {
				privs = append(privs, splitPrivs(v)...)
			}
		}
		take(e)
		for k, c := range els {
			under := false
			for j := k; j >= 0; j = els[j].Parent {
				if j == i {
					under = true
				}
			}
			if !under || k == i {
				continue
			}
			take(c)
			if c.Name == "RequiredPrivilege" || c.Name == "Privilege" {
				if v := c.Attrs["name"]; v != "" {
					privs = append(privs, v)
				} else if v := strings.TrimSpace(c.Text); v != "" {
					privs = append(privs, v)
				}
			}
		}
		for _, k := range orphans {
			if strings.EqualFold(els[k].Attrs["servicename"], name) {
				take(els[k])
				// A RequiredPrivilege child of a ServiceConfig that sits beside the ServiceInstall
				// counts too (T-0688: the privilege must be readable wherever WiX lets it be written).
				for c, ce := range els {
					for j := c; j >= 0; j = els[j].Parent {
						if j == k && c != k && (ce.Name == "RequiredPrivilege" || ce.Name == "Privilege") {
							if v := ce.Attrs["name"]; v != "" {
								privs = append(privs, v)
							}
						}
					}
				}
			}
		}
		if id := e.Attrs["id"]; id != "" && !isAgentName(name) && allowed(id, allow) {
			continue
		}
		if len(sids) == 0 {
			fail("ServiceInstall %q has no ServiceSid, must be %q (every service in the MSI source is pinned unless its Id is in installer-allow.txt)", name, pinnedSidType)
		}
		for _, v := range sids {
			if !strings.EqualFold(v, pinnedSidType) {
				fail("service SID type of %q is %q, must be %q (every ServiceSid seen must be the pin)", name, v, pinnedSidType)
			}
		}
		if !sameSet(privs, pinnedPrivileges) {
			fail("RequiredPrivileges of %q are %v, must be exactly %v", name, privs, pinnedPrivileges)
		}
	}
	for _, k := range orphans {
		n := els[k].Attrs["servicename"]
		matched := false
		for _, e := range els {
			if e.Name == "ServiceInstall" && strings.EqualFold(e.Attrs["name"], n) {
				matched = true
			}
		}
		rp := els[k].Attrs["requiredprivileges"]
		if v := els[k].Attrs["servicesid"]; !matched && ((v != "" && !strings.EqualFold(v, pinnedSidType)) || (rp != "" && !sameSet(splitPrivs(rp), pinnedPrivileges))) {
			fail("ServiceConfig for %q has a SID type or privileges other than the pin", n)
		}
	}
	// One ServiceInstall in the agent's Component (WiX runs it on the Component's KeyPath file) and in any
	// file that names the agent.
	total := 0
	perComp := map[int]int{}
	agentComp := map[int]bool{}
	for i, e := range els {
		if e.Name != "ServiceInstall" {
			continue
		}
		total++
		for j := i; j >= 0; j = els[j].Parent {
			if els[j].Name == "Component" {
				perComp[j]++
				if isAgentName(e.Attrs["name"]) {
					agentComp[j] = true
				}
				break
			}
		}
	}
	for c := range agentComp {
		if perComp[c] > 1 {
			fail("%d ServiceInstall elements in the Component that installs the agent service: a second service would run the agent binary under another name; there must be exactly one", perComp[c])
		}
	}
	if agentFile && total > 1 {
		fail("%d ServiceInstall elements in a file that names the agent: there must be exactly one", total)
	}
	return f
}

// registryRootKey resolves the Root and the full Key of a registry element, joining the keys of the
// RegistryKey elements it sits in (outermost first); Root comes from the nearest element that sets it.
func registryRootKey(els []xmlEl, i int) (root, key string) {
	var keys []string
	for j := i; j >= 0; j = els[j].Parent {
		if registryEls[els[j].Name] {
			if k := els[j].Attrs["key"]; k != "" {
				keys = append([]string{k}, keys...)
			}
			if root == "" {
				root = els[j].Attrs["root"]
			}
		}
	}
	return root, strings.Join(keys, `\`)
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

//go:embed installer-allow.txt
var embeddedInstallerAllow string

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
