package main

import (
	"bytes"
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
	SkipTests bool
	Only      string
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
	add("A4", checkAgentImports(root))
	if want("P") || want("F1") {
		if o.SkipTests {
			add("P", Result{ID: "P", What: pTestsWhat, Inactive: "tests skipped by -skip-tests"})
		} else {
			add("P", checkTests(root))
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
// because the banned things are named packages and functions).

// agentModuleDirs hold code that runs inside the agent host with only the dependency struct.
var agentModuleDirs = []string{"internal/agentmodules"}

// agentOwnedDirs are all code only the agent binary runs.
var agentOwnedDirs = []string{"cmd/agent", "internal/agentmodules", "internal/compose/agent"}

// r3BannedImports: a module cannot execute, change services/registry, or load code.
var r3BannedImports = map[string]string{
	"os/exec":                               "process execution (C1/C2)",
	"plugin":                                "loading code",
	"golang.org/x/sys/windows/registry":     "registry change (C3)",
	"golang.org/x/sys/windows/svc/mgr":      "service configuration change (C3)",
	"golang.org/x/sys/windows/svc/eventlog": "writes the host's log, reserved for the host",
}

// r3BannedCalls: file mutation by an agent module (C2). Reading is the module's own business through
// the host's dependency struct; any write goes through the host (the data directory only).
var r3BannedCalls = map[string]bool{
	"os.Create": true, "os.WriteFile": true, "os.OpenFile": true, "os.Remove": true, "os.RemoveAll": true,
	"os.Rename": true, "os.Mkdir": true, "os.MkdirAll": true, "os.Chmod": true, "os.Chown": true,
	"os.Truncate": true, "os.Symlink": true, "os.Link": true, "os.Chtimes": true,
	"syscall.Exec": true, "syscall.ForkExec": true, "syscall.StartProcess": true, "os.StartProcess": true,
}

func checkModuleCapabilities(root string) Result {
	r := Result{ID: "R3", What: "agent modules import no exec/registry/service-manager package and call no file-mutating or process API (C2, C3)"}
	files := goFiles(root, agentModuleDirs)
	if len(files) == 0 {
		r.Inactive = "no Go source under internal/agentmodules (T-0600 onward)"
		return r
	}
	for _, f := range files {
		scanGo(root, f, func(rel string, imp string, line int) {
			if why, bad := r3BannedImports[imp]; bad {
				r.Violations = append(r.Violations, fmt.Sprintf("%s:%d imports %s: %s", rel, line, imp, why))
			}
		}, func(rel, call string, line int) {
			if r3BannedCalls[call] {
				r.Violations = append(r.Violations, fmt.Sprintf("%s:%d calls %s: an agent module cannot mutate files or start processes (write through the host's data-directory capability)", rel, line, call))
			}
		})
	}
	return r
}

var listenCalls = map[string]bool{
	"net.Listen": true, "net.ListenTCP": true, "net.ListenUDP": true, "net.ListenPacket": true,
	"net.ListenIP": true, "net.ListenUnix": true, "net.ListenUnixgram": true, "net.FileListener": true,
	"http.ListenAndServe": true, "http.ListenAndServeTLS": true, "http.Serve": true, "http.ServeTLS": true,
	"tls.Listen": true, "npipe.Listen": true, "winio.ListenPipe": true,
}

func checkNoListener(root string) Result {
	r := Result{ID: "R4", What: "agent-owned code opens no listening socket (C5): outbound mTLS and the reverse tunnel on it only"}
	files := goFiles(root, agentOwnedDirs)
	if len(files) == 0 {
		r.Inactive = "no agent-owned Go source"
		return r
	}
	for _, f := range files {
		scanGo(root, f, func(rel, imp string, line int) {
			if imp == "net/http/httptest" {
				r.Violations = append(r.Violations, fmt.Sprintf("%s:%d imports net/http/httptest, a listener in a shipped binary", rel, line))
			}
		}, func(rel, call string, line int) {
			if listenCalls[call] || (strings.HasSuffix(call, ".ListenAndServe") || strings.HasSuffix(call, ".ListenAndServeTLS")) {
				r.Violations = append(r.Violations, fmt.Sprintf("%s:%d calls %s: the agent has no listener (TM-D13)", rel, line, call))
			}
		})
	}
	return r
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

// scanGo reports every import and every pkg.Func / x.Method call selector (as written) of a file.
func scanGo(root, path string, onImport func(rel, imp string, line int), onCall func(rel, call string, line int)) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	rel, _ := filepath.Rel(root, path)
	rel = filepath.ToSlash(rel)
	if err != nil {
		onImport(rel, "unparseable:"+err.Error(), 0)
		return
	}
	names := map[string]string{} // local name -> import path (last element when unnamed)
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		onImport(rel, p, fset.Position(im.Pos()).Line)
		n := filepath.Base(p)
		if im.Name != nil {
			n = im.Name.Name
		}
		names[n] = p
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			if p, ok := names[id.Name]; ok {
				onCall(rel, filepath.Base(p)+"."+sel.Sel.Name, fset.Position(sel.Pos()).Line)
				return true
			}
			onCall(rel, id.Name+"."+sel.Sel.Name, fset.Position(sel.Pos()).Line)
		}
		return true
	})
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
	localSystemRe = regexp.MustCompile(`(?i)local\s*system|nt\s*authority\\system|localservice|networkservice|nt\s*authority\\(local|network)\s*service|s-1-5-18\b|s-1-5-19\b|s-1-5-20\b`)
	agentFileRe   = regexp.MustCompile(`(?i)agent`)
	agentBodyRe   = regexp.MustCompile(`(?i)activediq-agent|activediqagent`)
)

// agentInstallerFiles are WiX sources under packaging/ that name the agent in their file name or body.
func agentInstallerFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(filepath.Join(root, "packaging"), func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".wxs", ".wxi", ".wxl", ".wixproj", ".xml":
		default:
			return nil
		}
		if agentFileRe.MatchString(filepath.Base(p)) {
			out = append(out, p)
			return nil
		}
		if b, err := os.ReadFile(p); err == nil && agentBodyRe.Match(b) {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func checkInstaller(root string) Result {
	r := Result{ID: "A1", What: "agent installer names " + pinnedAccount + ", service SID type " + pinnedSidType + ", the pinned RequiredPrivileges, and no LocalSystem (ADR-0006 rules 1, 3)"}
	files := agentInstallerFiles(root)
	if len(files) == 0 {
		r.Inactive = "no agent installer source under packaging/ (windows-engineer's MSI ticket)"
		return r
	}
	var sawService bool
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
		svc, vs := judgeInstallerXML(rel, b)
		sawService = sawService || svc
		r.Violations = append(r.Violations, vs...)
	}
	if !sawService {
		r.Violations = append(r.Violations, "no ServiceInstall in the agent installer source: the account cannot be verified")
	}
	return r
}

type xmlEl struct {
	Name  string
	Attrs map[string]string
	Text  string
	Depth int
}

// judgeInstallerXML returns whether a ServiceInstall was seen and the violations of the pinned identity.
func judgeInstallerXML(rel string, b []byte) (bool, []string) {
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
			return false, []string{rel + ": not parseable as XML: " + err.Error()}
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
	var vs []string
	saw := false
	sid := ""
	var privs []string
	for _, e := range els {
		switch e.Name {
		case "ServiceInstall":
			saw = true
			if acct := e.Attrs["account"]; acct != pinnedAccount {
				vs = append(vs, fmt.Sprintf("%s: ServiceInstall Account is %q, must be exactly %q", rel, acct, pinnedAccount))
			}
			if e.Attrs["password"] != "" {
				vs = append(vs, rel+": ServiceInstall carries a Password; a virtual account has none")
			}
			if v := e.Attrs["servicesid"]; v != "" {
				sid = v
			}
			if v := e.Attrs["requiredprivileges"]; v != "" {
				privs = append(privs, splitPrivs(v)...)
			}
		case "ServiceConfig":
			if v := e.Attrs["servicesid"]; v != "" {
				sid = v
			}
			if v := e.Attrs["requiredprivileges"]; v != "" {
				privs = append(privs, splitPrivs(v)...)
			}
		case "RequiredPrivilege", "Privilege":
			if v := e.Attrs["name"]; v != "" {
				privs = append(privs, v)
			} else if v := strings.TrimSpace(e.Text); v != "" {
				privs = append(privs, v)
			}
		}
	}
	if saw {
		if !strings.EqualFold(sid, pinnedSidType) {
			vs = append(vs, fmt.Sprintf("%s: service SID type is %q, must be %q (ServiceSid on ServiceInstall/ServiceConfig)", rel, sid, pinnedSidType))
		}
		if !sameSet(privs, pinnedPrivileges) {
			vs = append(vs, fmt.Sprintf("%s: RequiredPrivileges are %v, must be exactly %v", rel, privs, pinnedPrivileges))
		}
	}
	return saw, vs
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

// a4Banned import-path prefixes and fragments: no LDAP, SMB, RPC, Kerberos or SSPI client (ADR-0006 rule 4).
var a4Banned = []string{
	"github.com/go-ldap/", "gopkg.in/ldap", "github.com/go-krb5/", "github.com/jcmturner/gokrb5",
	"github.com/alexbrainman/sspi", "github.com/hirochachma/", "github.com/cloudsoda/go-smb2", "github.com/hirochikon/",
	"github.com/oiweiwei/go-msrpc", "github.com/stacktitan/smb", "github.com/microsoft/go-mssqldb",
	"github.com/azure/go-ntlmssp", "github.com/masterzen/winrm", "github.com/bodgit/",
	"golang.org/x/sys/windows/svc/mgr", "golang.org/x/sys/windows/registry",
}

// a4BannedFragments match our own directory and connector packages anywhere in the closure.
var a4BannedFragments = []string{"/internal/directory", "/internal/connector"}

func checkAgentImports(root string) Result {
	r := Result{ID: "A4", What: "agent binary closure (linux and windows) has no LDAP, SMB, RPC, Kerberos or SSPI client (ADR-0006 rule 4)"}
	if _, err := os.Stat(filepath.Join(root, "cmd/agent")); err != nil {
		r.Inactive = "no cmd/agent"
		return r
	}
	seen := map[string]bool{}
	for _, goos := range []string{"windows", "linux"} {
		deps, err := goDeps(root, goos)
		if err != nil {
			r.Violations = append(r.Violations, "go list -deps ./cmd/agent (GOOS="+goos+"): "+err.Error())
			continue
		}
		for _, d := range judgeDeps(deps) {
			if !seen[d] {
				seen[d] = true
				r.Violations = append(r.Violations, d+" (GOOS="+goos+")")
			}
		}
	}
	return r
}

func goDeps(root, goos string) ([]string, error) {
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/agent")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.Fields(string(out)), nil
}

// judgeDeps returns one message per banned import in the closure.
func judgeDeps(deps []string) []string {
	var out []string
	for _, d := range deps {
		l := strings.ToLower(d)
		for _, b := range a4Banned {
			if strings.HasPrefix(l, b) {
				out = append(out, "agent closure imports "+d+", a directory/network-identity client (ADR-0006 rule 4)")
			}
		}
		for _, f := range a4BannedFragments {
			if strings.Contains(l, f) {
				out = append(out, "agent closure imports "+d+", our directory/connector code (ADR-0002 rule 3)")
			}
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
