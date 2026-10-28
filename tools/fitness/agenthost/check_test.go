package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryPasses(t *testing.T) {
	if v := Check("../../.."); len(v) > 0 {
		t.Fatalf("violations:\n%s", strings.Join(v, "\n"))
	}
}

func TestMutationsAreCaught(t *testing.T) {
	src, _ := os.ReadFile("../../../" + wxs)
	for name, mut := range map[string]func(string) string{
		"localsystem": func(s string) string {
			return strings.Replace(s, `Account="NT SERVICE\activeDIQAgent"`, `Account="LocalSystem"`, 1)
		},
		"extra priv": func(s string) string {
			return strings.Replace(s, `Value="SeChangeNotifyPrivilege"`, `Value="SeChangeNotifyPrivilege SeDebugPrivilege"`, 1) + `<Property Id="P" Value="SeDebugPrivilege" />`
		},
		"unrestricted": func(s string) string {
			return strings.Replace(s, `ServiceSid="restricted"`, `ServiceSid="unrestricted"`, 1)
		},
		"fail open ca": func(s string) string {
			return strings.Replace(s, `Id="GrantChannel" Directory="INSTALLFOLDER" Execute="deferred" Impersonate="no" Return="check"`, `Id="GrantChannel" Directory="INSTALLFOLDER" Execute="deferred" Impersonate="no" Return="ignore"`, 1)
		},
		"powershell": func(s string) string {
			return strings.Replace(s, "<Component ", `<CustomAction Id="X" ExeCommand="powershell -c x" /><Component `, 1)
		},
		"reboot": func(s string) string { return strings.Replace(s, "ReallySuppress", "Force", 1) },
	} {
		root := t.TempDir()
		p := filepath.Join(root, wxs)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte(mut(string(src))), 0o644)
		// Only the manifest half is judged here; the dependency scans need the real module.
		found := false
		for _, s := range Check(root) {
			if strings.HasPrefix(s, wxs) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: mutation not caught", name)
		}
	}
}
