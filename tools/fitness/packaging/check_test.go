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
	for _, f := range []string{winACL, winTest, winMsi, winDC, linPrep, linCompose} {
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
		{"DC no longer refused", winMsi, "exactly one <Launch", func(s string) string {
			return strings.ReplaceAll(s, "MsiNTProductType &lt;&gt; 2", "MsiNTProductType &lt;&gt; 9")
		}},
		{"refusal as custom action", winMsi, "<CustomAction> is not allowed", func(s string) string { return addToPackage(s, `<CustomAction Id="X" />`) }},
		{"product type overridden by SetProperty", winMsi, "<SetProperty> is not allowed", func(s string) string {
			return addToPackage(s, `<SetProperty Id="MsiNTProductType" Value="3" Before="LaunchConditions" Sequence="both" />`)
		}},
		{"product type authored as Property", winMsi, "MsiNTProductType, which must not", func(s string) string { return addToPackage(s, `<Property Id="MsiNTProductType" Value="3" />`) }},
		{"product type single-quoted Property", winMsi, "MsiNTProductType, which must not", func(s string) string { return addToPackage(s, `<Property Id='MsiNTProductType' Value='3' />`) }},
		{"Installed authored as Property", winMsi, "Installed, which must not", func(s string) string { return addToPackage(s, `<Property Id="Installed" Value="" />`) }},
		{"LaunchConditions suppressed in execute sequence", winMsi, "must not be authored", func(s string) string {
			return addToPackage(s, `<InstallExecuteSequence><LaunchConditions Suppress="yes" /></InstallExecuteSequence>`)
		}},
		{"LaunchConditions Condition=0 in execute sequence", winMsi, "<LaunchConditions> is not allowed", func(s string) string {
			return addToPackage(s, `<InstallExecuteSequence><LaunchConditions Condition="0" /></InstallExecuteSequence>`)
		}},
		{"LaunchConditions suppressed in UI sequence", winMsi, "must not be authored", func(s string) string {
			return addToPackage(s, `<InstallUISequence><LaunchConditions Suppress="yes" /></InstallUISequence>`)
		}},
		{"LaunchConditions Condition=0 in UI sequence", winMsi, "<LaunchConditions> is not allowed", func(s string) string {
			return addToPackage(s, `<InstallUISequence><LaunchConditions Condition="0" /></InstallUISequence>`)
		}},
		{"Launch commented out", winMsi, "exactly one <Launch", func(s string) string {
			s = strings.Replace(s, `<Launch Condition="Installed OR (MsiNTProductType`, `<!-- <Launch Condition="Installed OR (MsiNTProductType`, 1)
			return strings.Replace(s, `domain controllers host only the activeDIQ agent." />`, `domain controllers host only the activeDIQ agent." /> -->`, 1)
		}},
		{"Launch moved out of Package", winMsi, "direct child of <Package>", func(s string) string {
			return strings.Replace(s, `<MediaTemplate EmbedCab="yes" />`, `<MediaTemplate EmbedCab="yes" /><Feature Id="F2" Title="x"><Launch Condition="Installed OR (MsiNTProductType &lt;&gt; 2)" Message="cannot be installed on a domain controller" /></Feature>`, 1)
		}},
		{"Launch duplicated", winMsi, "exactly one <Launch", func(s string) string {
			return addToPackage(s, `<Launch Condition="Installed OR (MsiNTProductType &lt;&gt; 2)" Message="cannot be installed on a domain controller" />`)
		}},
		{"Launch message changed", winMsi, "message must contain", func(s string) string {
			return strings.ReplaceAll(s, "cannot be installed on a domain controller", "is not for this machine")
		}},
		{"preprocessor can drop the Launch", winMsi, "preprocessor instruction", func(s string) string {
			return addToPackage(s, `<?if $(var.Lab) = 1 ?><?endif?>`)
		}},
		{"msiexec line interpolated", winDC, "msiexec arguments", func(s string) string {
			return strings.ReplaceAll(s, "-ArgumentList $msiArgs", "-ArgumentList \"/i $MsiPath\"")
		}},
		{"msiexec path validation removed", winDC, "must be validated", func(s string) string {
			return strings.ReplaceAll(s, "Assert-SafeMsiexecPath 'MsiPath' $MsiPath", "# no validation")
		}},
		{"msiexec log path validation removed", winDC, "log path must be validated", func(s string) string {
			return strings.ReplaceAll(s, "Assert-SafeMsiexecPath 'LogPath' $LogPath", "# no validation")
		}},
		{"msiexec path not quoted", winDC, "MSI path must be quoted", func(s string) string {
			return strings.ReplaceAll(s, `('"{0}"' -f $MsiPath)`, "$MsiPath")
		}},
		{"msiexec path not resolved", winDC, "full path", func(s string) string {
			return strings.ReplaceAll(s, "GetFullPath($MsiPath)", "Resolve($MsiPath)")
		}},
		{"automatic variable reused", winDC, "automatic variable", func(s string) string { return s + "\n$args = @()\n" }},
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
		{"ancestor walk dropped", winACL, "every ancestor", func(s string) string {
			return strings.ReplaceAll(s, "Assert-TrustedAncestor $a", "Write-Verbose $a")
		}},
		{"ancestor owner unchecked", winACL, "ancestor owned by an untrusted", func(s string) string {
			return strings.ReplaceAll(s, "Ancestor '$Target' is owned by", "Ancestor '$Target' has")
		}},
		{"ancestor reparse unchecked", winACL, "ancestor that is a junction", func(s string) string {
			return strings.ReplaceAll(s, "Ancestor '$Target' is a reparse point", "Ancestor '$Target' is fine")
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

// addToPackage inserts an element just before </Package>.
func addToPackage(s, el string) string {
	return strings.Replace(s, "</Package>", el+"\n  </Package>", 1)
}

func TestBuiltMsiTables(t *testing.T) {
	launch := "Condition\tDescription\ns255\tl255\nLaunchCondition\tCondition\n" + dcCondition + "\tactiveDIQ Server " + dcMessage + ".\n"
	seq := "Action\tCondition\tSequence\ns72\tS255\tI2\nInstallExecuteSequence\tAction\nLaunchConditions\t\t410\n"
	if v := judgeMsiTables(launch, seq); len(v) != 0 {
		t.Fatalf("good tables rejected: %v", v)
	}
	for name, c := range map[string][2]string{
		"no row":        {"", seq},
		"not sequenced": {launch, "Action\tCondition\tSequence\n"},
		"conditioned":   {launch, "Action\tCondition\tSequence\nLaunchConditions\t0\t410\n"},
	} {
		if v := judgeMsiTables(c[0], c[1]); len(v) == 0 {
			t.Errorf("%s: want a violation", name)
		}
	}
}
