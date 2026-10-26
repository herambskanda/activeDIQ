package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	r, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// copyTree copies the packaging files into a temp root, applying mutate to one file.
func fixture(t *testing.T, file string, mutate func(string) string) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range []string{winACL, winTest, linPrep, linCompose} {
		b, err := os.ReadFile(filepath.Join(repoRoot(t), f))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if f == file {
			s = mutate(s)
		}
		dst := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte(s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestMain(m *testing.M) {
	// Fixtures hold only the packaging files; the PowerShell image pin lives in the real repository.
	r, _ := filepath.Abs("../../..")
	os.Setenv("ADIQ_REPO_ROOT", r)
	os.Exit(m.Run())
}

func TestRepositoryIsClean(t *testing.T) {
	if v := Check(repoRoot(t)); len(v) != 0 {
		t.Fatalf("violations: %v", v)
	}
}

func TestViolationsAreCaught(t *testing.T) {
	cases := []struct {
		name, file, want string
		mutate           func(string) string
	}{
		{"inheritance left on", winACL, "inheritance must be disabled", func(s string) string {
			return strings.ReplaceAll(s, "SetAccessRuleProtection($true, $false)", "SetAccessRuleProtection($false, $false)")
		}},
		{"Everyone granted", winACL, "broad principal", func(s string) string { return s + "\n# grant Everyone read\n" }},
		{"no Administrators", winACL, "Administrators must be granted", func(s string) string {
			return strings.ReplaceAll(s, "S-1-5-32-544", "S-1-5-32-000")
		}},
		{"no behavioural probe", winTest, "probe as a non-administrator", func(s string) string {
			return strings.ReplaceAll(s, "ProbeCredential", "Nothing")
		}},
		{"recursion added", winACL, "must not recurse", func(s string) string { return s + "\nGet-ChildItem -Recurse $Path\n" }},
		{"owner check dropped", winACL, "refuse", func(s string) string { return strings.ReplaceAll(s, "refusing to adopt", "adopting") }},
		{"path interpolated in probe", winTest, "interpolating the path", func(s string) string { return s + "\n\"Get-ChildItem -LiteralPath '$Path'\"\n" }},
		{"root chowns by path", linPrep, "root must not chown", func(s string) string { return s + "\nfind \"$dir\" -exec chown 1 {} +\n" }},
		{"symlink entries accepted", linPrep, "non-regular entries", func(s string) string { return strings.ReplaceAll(s, "! -type f", "-type d") }},
		{"hardlinks accepted", linPrep, "hard-linked", func(s string) string { return strings.ReplaceAll(s, "-links +1", "-links +99") }},
		{"mode loosened", linPrep, "mode 0700", func(s string) string { return strings.ReplaceAll(s, "chmod 0700", "chmod 0755") }},
		{"root allowed", linPrep, "uid 0 must be refused", func(s string) string { return strings.ReplaceAll(s, "0 | ''", "'' ") }},
		{"container runs as root", linCompose, "numeric non-root user", func(s string) string {
			return strings.ReplaceAll(s, `"10001:10001"          #`, `"0:0"          #`)
		}},
		{"script does not parse", winACL, "PowerShell parse error", func(s string) string {
			return s + "\nWrite-Output \"ACL set on $Path: broken\"\n"
		}},
		{"existing dir DACL unchecked", winACL, "own DACL", func(s string) string {
			return strings.ReplaceAll(s, "Assert-NoUnprivilegedWrite $Path", "# skipped $Path")
		}},
		{"generic rights not masked", winACL, "generic rights", func(s string) string { return strings.ReplaceAll(s, "0x52000000", "0") }},
		{"hardlink check fails open", winACL, "fail closed", func(s string) string { return strings.ReplaceAll(s, "$LASTEXITCODE", "$null") }},
		{"privileged", linCompose, "must not be privileged", func(s string) string { return s + "    privileged: true\n" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := Check(fixture(t, c.file, c.mutate))
			if !strings.Contains(strings.Join(v, "\n"), c.want) {
				t.Fatalf("want a violation containing %q, got %v", c.want, v)
			}
		})
	}
}
