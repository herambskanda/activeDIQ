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
	t := read(root, winTest, &v)
	need(&v, winTest, t, "AreAccessRulesProtected", "the lab test must assert the ACL is protected")
	need(&v, winTest, t, "ProbeCredential", "the lab test must probe as a non-administrator")

	p := read(root, linPrep, &v)
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
	return v
}
