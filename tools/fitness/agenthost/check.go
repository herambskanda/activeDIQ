package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const wxs = "packaging/windows/agent/Agent.wxs"

// pinnedPrivileges is ADR-0006 decision 3. internal/platform/agent.PinnedPrivileges must equal it.
const pinnedPrivileges = "SeChangeNotifyPrivilege"

// forbiddenImports are packages the agent must never link (A4/R3). Prefix match on the import path.
var forbiddenImports = []string{
	"github.com/go-ldap", "github.com/jcmturner", "github.com/hirochachacha/go-smb2", "github.com/alexbrainman/sspi",
	"golang.org/x/sys/windows/registry", "golang.org/x/sys/windows/svc/mgr", "os/exec", "net/rpc", "net/smtp", "plugin",
	"github.com/skenzeriq/activediq/internal/directory", "github.com/skenzeriq/activediq/internal/connector",
}

func read(root, rel string, v *[]string) string {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		*v = append(*v, rel+": missing ("+err.Error()+")")
		return ""
	}
	return string(b)
}

// Check returns every violation under root.
func Check(root string) []string {
	var v []string
	m := stripComments(read(root, wxs, &v))
	if m != "" {
		for _, tok := range []struct{ tok, why string }{
			{`Account="NT SERVICE\activeDIQAgent"`, "the service must run as the virtual account"},
			{`ServiceSid="restricted"`, "the service SID type must be restricted"},
			{`Name="RequiredPrivileges"`, "RequiredPrivileges must be set"},
			{`Value="` + pinnedPrivileges + `"`, "RequiredPrivileges must be exactly the pinned list"},
			{`Name="grant-channel"`, ""},
		} {
			if tok.why != "" && !strings.Contains(m, tok.tok) {
				v = append(v, fmt.Sprintf("%s: %s (expected %s)", wxs, tok.why, tok.tok))
			}
		}
		for _, bad := range []string{"LocalSystem", "NT AUTHORITY\\SYSTEM", "NetworkService", "LocalService", "powershell", "PowerShell", "cmd.exe", "$"} {
			if strings.Contains(m, bad) && !(bad == "$" && !strings.Contains(strings.ReplaceAll(m, "$(var.", ""), "$")) {
				v = append(v, fmt.Sprintf("%s: forbidden text %q", wxs, bad))
			}
		}
		if strings.Contains(m, `SeChangeNotifyPrivilege`) {
			// exactly one privilege: no second Se*Privilege name anywhere
			re := regexp.MustCompile(`Se[A-Z][A-Za-z]+Privilege`)
			seen := map[string]bool{}
			for _, p := range re.FindAllString(m, -1) {
				seen[p] = true
			}
			if len(seen) != 1 {
				var names []string
				for p := range seen {
					names = append(names, p)
				}
				sort.Strings(names)
				v = append(v, fmt.Sprintf("%s: privileges named %v, want only %s", wxs, names, pinnedPrivileges))
			}
		}
		// Install-time custom actions that change host configuration must fail closed.
		for _, id := range []string{"GrantChannel", "PrepareDataDir", "WriteConfig"} {
			re := regexp.MustCompile(`<CustomAction Id="` + id + `"[^>]*Return="check"`)
			if !re.MatchString(m) {
				v = append(v, fmt.Sprintf("%s: custom action %s must have Return=\"check\" (fail closed)", wxs, id))
			}
		}
		if strings.Contains(m, "FirewallException") {
			v = append(v, wxs+": the agent has no listener; it must install no firewall exception")
		}
		if !strings.Contains(m, `Value="ReallySuppress"`) {
			v = append(v, wxs+": the installer must never force a reboot (REBOOT=ReallySuppress)")
		}
	}

	// A4/R3 import scans use the Go toolchain's own dependency graph for Windows.
	for _, pkg := range []string{"./cmd/agent", "./internal/agentmodules/addc"} {
		deps, err := goDeps(root, pkg)
		if err != nil {
			v = append(v, pkg+": cannot list dependencies: "+err.Error())
			continue
		}
		for _, d := range deps {
			for _, f := range forbiddenImports {
				if d == f || strings.HasPrefix(d, f+"/") {
					v = append(v, fmt.Sprintf("%s links %s (forbidden for the agent: %s)", pkg, d, f))
				}
			}
		}
	}
	// R3: the addc module opens no listener and spawns nothing, by source.
	for _, f := range goFiles(filepath.Join(root, "internal/agentmodules/addc")) {
		b, _ := os.ReadFile(f)
		for _, bad := range []string{"net.Listen", "http.ListenAndServe", "exec.Command", "os/exec", "syscall.Exec"} {
			if strings.Contains(string(b), bad) {
				v = append(v, fmt.Sprintf("%s: forbidden %q in the addc module", f, bad))
			}
		}
	}
	return v
}

var xmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)

// stripComments removes XML comments: prose may name what the installer must never do.
func stripComments(s string) string { return xmlComment.ReplaceAllString(s, "") }

func goFiles(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func goDeps(root, pkg string) ([]string, error) {
	cmd := exec.Command("go", "list", "-deps", pkg)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}
