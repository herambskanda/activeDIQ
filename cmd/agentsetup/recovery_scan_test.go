package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The service's recovery policy is code now, not an MSI table, so fitness-built-msi no longer refuses a
// reboot or run-command failure action. This source scan carries that rule on every platform (CI is Linux):
// a crash loop of the agent must never reboot a domain controller or run a command as SYSTEM (TM-A9,
// agent-host-fitness-rulings.md, T-0724 addendum). Lab case A6 checks the same settings on a real service.

// forbiddenRecovery are the x/sys/windows/svc/mgr names that would turn a restart-only policy into a
// reboot or a command. Matched by name whatever the import alias.
var forbiddenRecovery = map[string]string{
	"ServiceReboot":                        "reboots the host on failure",
	"ServiceRunCommand":                    "runs a command on failure",
	"NoAction":                             "is not a restart (every action must be mgr.ServiceRestart)",
	"SetRecoveryCommand":                   "sets a command to run on failure",
	"SetRebootMessage":                     "sets a reboot message (only meaningful with a reboot action)",
	"SetRecoveryActionsOnNonCrashFailures": "extends recovery to non-crash failures (not reviewed)",
}

// scanRecovery parses Go sources (build tags ignored) and returns every violation of the recovery rule plus
// the number of mgr.RecoveryAction literals it saw.
func scanRecovery(srcs map[string]string) (problems []string, literals int) {
	fset := token.NewFileSet()
	for name, src := range srcs {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			problems = append(problems, name+": does not parse: "+err.Error())
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if why, bad := forbiddenRecovery[x.Sel.Name]; bad {
					problems = append(problems, fset.Position(x.Pos()).String()+": "+x.Sel.Name+" "+why)
				}
			case *ast.Ident: // dot-import or a local alias
				if why, bad := forbiddenRecovery[x.Name]; bad {
					problems = append(problems, fset.Position(x.Pos()).String()+": "+x.Name+" "+why)
				}
			case *ast.CompositeLit:
				sel, ok := x.Type.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "RecoveryAction" {
					return true
				}
				literals++
				typ := ""
				for _, e := range x.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Type" {
							if v, ok := kv.Value.(*ast.SelectorExpr); ok {
								typ = v.Sel.Name
							} else {
								typ = "?"
							}
						}
					}
				}
				if typ != "ServiceRestart" {
					problems = append(problems, fset.Position(x.Pos()).String()+": RecoveryAction Type is "+typ+"; must be mgr.ServiceRestart")
				}
			}
			return true
		})
	}
	return problems, literals
}

func TestRecoveryPolicyIsRestartOnly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	srcs := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		srcs[f] = string(b)
	}
	problems, literals := scanRecovery(srcs)
	for _, p := range problems {
		t.Error(p)
	}
	if literals == 0 {
		t.Fatal("no mgr.RecoveryAction literal found; test is stale")
	}
}

// The numbers lab case A6 asserts (lab/windows/guest/agent-verify.ps1): restart x3, 30 s, reset after a day.
func TestRecoveryPolicyValues(t *testing.T) {
	if recoveryRestarts != 3 || recoveryDelay != 30*time.Second || recoveryResetSeconds != 86400 {
		t.Fatalf("recovery policy = %d restarts, %v delay, %d s reset; lab case A6 and the T-0724 ruling pin 3, 30s, 86400", recoveryRestarts, recoveryDelay, recoveryResetSeconds)
	}
}

// The scan has to bite: each of these drifts must be reported.
func TestRecoveryScanBites(t *testing.T) {
	const head = "package main\nimport \"golang.org/x/sys/windows/svc/mgr\"\nvar _ = mgr.ServiceRestart\n"
	cases := map[string]struct{ body, want string }{
		"reboot action":      {"var a = mgr.RecoveryAction{Type: mgr.ServiceReboot, Delay: 0}", "ServiceReboot"},
		"run command action": {"var a = mgr.RecoveryAction{Type: mgr.ServiceRunCommand}", "ServiceRunCommand"},
		"no action":          {"var a = mgr.RecoveryAction{Type: mgr.NoAction}", "NoAction"},
		"type from variable": {"var t uint32\nvar a = mgr.RecoveryAction{Type: t}", "must be mgr.ServiceRestart"},
		"type omitted":       {"var a = mgr.RecoveryAction{Delay: 1}", "Type is"},
		"recovery command":   {"func f(s *mgr.Service) { s.SetRecoveryCommand(\"x\") }", "SetRecoveryCommand"},
		"reboot message":     {"func f(s *mgr.Service) { s.SetRebootMessage(\"x\") }", "SetRebootMessage"},
		"non-crash failures": {"func f(s *mgr.Service) { s.SetRecoveryActionsOnNonCrashFailures(true) }", "SetRecoveryActionsOnNonCrashFailures"},
		"aliased import":     {"var a = m.RecoveryAction{Type: m.ServiceReboot}", "ServiceReboot"},
	}
	for name, c := range cases {
		problems, _ := scanRecovery(map[string]string{"x.go": head + c.body})
		if len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), c.want) {
			t.Errorf("%s: scan reported %q; want a problem containing %q", name, problems, c.want)
		}
	}
	good := head + "var a = mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 1}"
	if problems, n := scanRecovery(map[string]string{"x.go": good}); len(problems) != 0 || n != 1 {
		t.Errorf("restart-only fixture: problems %q, literals %d; want none, 1", problems, n)
	}
}
