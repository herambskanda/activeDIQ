package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	winACL     = "packaging/windows/Set-ApiTlsDirAcl.ps1"
	winTest    = "packaging/windows/Test-ApiTlsDirAcl.ps1"
	linPrep    = "packaging/linux-oci/prepare-tls-dir.sh"
	linCompose = "packaging/linux-oci/compose.tls.yaml"
)

func read(root, rel string, v *[]string) string {
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		*v = append(*v, rel+": missing ("+err.Error()+")")
		return ""
	}
	return string(b)
}

func need(v *[]string, file, text, token, why string) {
	if text != "" && !strings.Contains(text, token) {
		*v = append(*v, fmt.Sprintf("%s: %s (expected %q)", file, why, token))
	}
}

func forbid(v *[]string, file, text, token, why string) {
	if strings.Contains(text, token) {
		*v = append(*v, fmt.Sprintf("%s: %s (found %q)", file, why, token))
	}
}

// Check returns every violation under root (a repository checkout).
func Check(root string) []string {
	var v []string

	w := read(root, winACL, &v)
	need(&v, winACL, w, "SetAccessRuleProtection($true, $false)", "inheritance must be disabled without copying inherited entries")
	need(&v, winACL, w, "S-1-5-32-544", "Administrators must be granted by SID")
	need(&v, winACL, w, "Set-Acl -LiteralPath $Path", "the ACL must be applied to the directory")
	for _, s := range []string{"S-1-1-0", "S-1-5-11", "S-1-5-32-545"} {
		need(&v, winACL, w, s, "the service identity must be refused when it is a broad group")
	}
	for _, s := range []string{"Everyone", "Authenticated Users", `BUILTIN\Users`, "LocalSystem", "icacls", "/inheritance:e"} {
		forbid(&v, winACL, w, s, "must not grant or rely on a broad principal")
	}
	forbid(&v, winACL, w, "-Recurse", "must not recurse: a planted junction would be followed")
	need(&v, winACL, w, "ReparsePoint", "reparse points must be refused")
	need(&v, winACL, w, "hardlink", "hard-linked files must be refused")
	need(&v, winACL, w, "refusing to adopt", "a pre-existing directory with an untrusted owner must be refused")
	need(&v, winACL, w, "grants write access", "a parent writable by unprivileged users must be refused")
	need(&v, winACL, w, "Assert-NoUnprivilegedWrite $Path", "an existing directory's own DACL must be checked for unprivileged write access")
	need(&v, winACL, w, "Assert-TrustedAncestor $a", "every ancestor up to the volume root must be walked")
	need(&v, winACL, w, "Ancestor '$Target' is a reparse point", "an ancestor that is a junction/symlink must be refused (Get-Acl resolves it to the target)")
	need(&v, winACL, w, "Ancestor '$Target' is owned by", "an ancestor owned by an untrusted principal must be refused")
	need(&v, winACL, w, "0x52000000", "the danger mask must include the raw generic rights (GENERIC_ALL/WRITE, MAXIMUM_ALLOWED)")
	need(&v, winACL, w, "$LASTEXITCODE", "the hard-link check must fail closed when fsutil fails")
	t := read(root, winTest, &v)
	need(&v, winTest, t, "AreAccessRulesProtected", "the lab test must assert the ACL is protected")
	need(&v, winTest, t, "ProbeCredential", "the lab test must probe as a non-administrator")

	forbid(&v, winTest, t, "'$Path'", "the probe script must not be built by interpolating the path")
	need(&v, winTest, t, "ADIQ_PROBE_PATH", "the path must reach the probe as data")
	need(&v, winTest, t, "read a file inside", "the probe must read a file, not only list")

	p := read(root, linPrep, &v)
	need(&v, linPrep, p, "! -type f", "non-regular entries must be refused")
	need(&v, linPrep, p, "-links +1", "hard-linked files must be refused")
	need(&v, linPrep, p, "setpriv", "modes inside the directory must be tightened as the service uid, not root")
	forbid(&v, linPrep, p, "-exec chown", "root must not chown by path inside a service-writable directory")
	need(&v, linPrep, p, "chmod 0700", "the directory must be mode 0700")
	need(&v, linPrep, p, "chown", "the directory must be owned by the service uid")
	need(&v, linPrep, p, "0 | ''", "uid 0 must be refused")
	c := read(root, linCompose, &v)
	if c != "" {
		if !regexp.MustCompile(`(?m)^\s+user:\s*"?([1-9][0-9]*):([0-9]+)"?\s*(#.*)?$`).MatchString(c) {
			v = append(v, linCompose+": the server must run as a numeric non-root user: \"uid:gid\"")
		}
		need(&v, linCompose, c, "ACTIVEDIQ_API_TLS_DIR", "the TLS directory env var must be set")
		need(&v, linCompose, c, "type: bind", "the TLS directory must be a bind mount of the prepared host directory")
		forbid(&v, linCompose, c, "privileged: true", "the server must not be privileged")
	}

	v = append(v, parsePowerShell(root, repoRootOf(root))...)

	if p != "" && runtime.GOOS != "windows" {
		v = append(v, runPrepare(root)...)
	}
	return v
}

// runPrepare executes the prepare script for real as the current user: mode 0700, our uid:gid, files
// tightened, uid 0 and symlinks refused.
func runPrepare(root string) []string {
	var v []string
	tmp, err := os.MkdirTemp("", "fitness-packaging-")
	if err != nil {
		return []string{"packaging: " + err.Error()}
	}
	defer os.RemoveAll(tmp)
	script := filepath.Join(root, linPrep)
	dir := filepath.Join(tmp, "tls")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return []string{err.Error()}
	}
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(key, []byte("k"), 0o644); err != nil {
		return []string{err.Error()}
	}
	uid, gid := fmt.Sprint(os.Getuid()), fmt.Sprint(os.Getgid())
	if os.Getuid() == 0 {
		uid, gid = "10001", "10001"
	}
	if out, err := exec.Command("sh", script, dir, uid, gid).CombinedOutput(); err != nil {
		return []string{linPrep + ": failed on a clean directory: " + strings.TrimSpace(string(out))}
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		v = append(v, linPrep+": directory is not mode 0700 afterwards")
	}
	if st, err := os.Stat(key); err != nil || st.Mode().Perm() != 0o600 {
		v = append(v, linPrep+": an existing file was not tightened to 0600")
	}
	if out, err := exec.Command("sh", script, dir, "0", "0").CombinedOutput(); err == nil {
		v = append(v, linPrep+": accepted uid 0 "+strings.TrimSpace(string(out)))
	}
	link := filepath.Join(tmp, "link")
	if err := os.Symlink(dir, link); err == nil {
		if _, err := exec.Command("sh", script, link, uid, gid).CombinedOutput(); err == nil {
			v = append(v, linPrep+": accepted a symlink as the directory")
		}
	}
	v = append(v, runHostile(script, tmp, uid, gid)...)
	return v
}

// runHostile plants entries a compromised container could leave and requires each to be refused with a
// file outside the directory untouched.
func runHostile(script, tmp, uid, gid string) []string {
	var v []string
	outside := filepath.Join(tmp, "outside")
	if err := os.WriteFile(outside, []byte("o"), 0o644); err != nil {
		return []string{err.Error()}
	}
	cases := []struct {
		name  string
		plant func(dir string) error
	}{
		{"subdirectory", func(d string) error { return os.Mkdir(filepath.Join(d, "sub"), 0o755) }},
		{"symlink entry", func(d string) error { return os.Symlink(outside, filepath.Join(d, "ln")) }},
		{"hardlinked file", func(d string) error { return os.Link(outside, filepath.Join(d, "hl")) }},
	}
	for _, c := range cases {
		dir, err := os.MkdirTemp(tmp, "h-")
		if err != nil {
			return []string{err.Error()}
		}
		if err := c.plant(dir); err != nil {
			continue // e.g. hard links unsupported here
		}
		if out, err := exec.Command("sh", script, dir, uid, gid).CombinedOutput(); err == nil {
			v = append(v, linPrep+": accepted a "+c.name+": "+strings.TrimSpace(string(out)))
		}
		if st, err := os.Stat(outside); err != nil || st.Mode().Perm() != 0o644 {
			v = append(v, linPrep+": a file outside the directory was modified via a "+c.name)
		}
	}
	if os.Getuid() == 0 { // a file owned by another uid can only be made as root
		dir, _ := os.MkdirTemp(tmp, "h-")
		f := filepath.Join(dir, "other")
		_ = os.WriteFile(f, []byte("x"), 0o644)
		_ = os.Chown(f, 4242, 4242)
		if _, err := exec.Command("sh", script, dir, uid, gid).CombinedOutput(); err == nil {
			v = append(v, linPrep+": accepted a file owned by another uid")
		}
	}
	return v
}

// repoRootOf finds the checkout that holds the oracle pin: root itself, or the real repository when
// Check runs on a fixture copy (ADIQ_REPO_ROOT overrides).
func repoRootOf(root string) string {
	if r := os.Getenv("ADIQ_REPO_ROOT"); r != "" {
		return r
	}
	return root
}
