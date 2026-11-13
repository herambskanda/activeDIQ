//go:build lab

package sync_test

import (
	"bufio"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// T-1250 AC1: every mapper bound on an attribute a non-admin can write is at or above the schema's
// rangeUpper, read from the schema NC of the running Samba lab (make lab-up). Samba's schema is the
// Samba schema: this proves the check mechanism and Samba's values only. Windows Server's rangeUpper
// stays [UNVERIFIED] until T-1243/T-1715 runs the same check there; Samba must not stand in for it.
func Test_lab_mapper_bounds_cover_the_schema_range_upper(t *testing.T) {
	env := map[string]string{}
	f, err := os.Open(filepath.Join("..", "..", "..", "lab", ".lab.env"))
	if err != nil {
		t.Fatalf("lab not up (make lab-up): %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "export "))
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			env[k] = strings.Trim(v, `"'`)
		}
	}
	c := env["LAB_CONTAINER"]
	attrsRead := []string{"sAMAccountName", "userPrincipalName", "displayName", "mail", "company", "description",
		"dNSHostName", "operatingSystem", "operatingSystemVersion"}
	m := mapper(dirsync.Config{})
	for _, a := range attrsRead {
		out, err := exec.Command("docker", "exec", c, "ldbsearch", "-H", "/var/lib/samba/private/sam.ldb",
			"-b", "CN=Schema,CN=Configuration,DC=lab,DC=activediq,DC=test", "-s", "one",
			"(lDAPDisplayName="+a+")", "rangeUpper").CombinedOutput()
		if err != nil {
			t.Fatalf("ldbsearch %s: %v\n%s", a, err, out)
		}
		upper := 0
		for _, l := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(l, "rangeUpper: "); ok {
				upper, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
		if upper == 0 {
			t.Logf("%s: no rangeUpper in the Samba schema; skipped (Windows check: T-1243)", a)
			continue
		}
		// A value of exactly rangeUpper characters (multi-byte, so a byte count would refuse it) must map.
		v := strings.Repeat("é", upper)
		e := entry(90, "CN=PC1,OU=Staff,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("top", "computer").with(a, txt(v)))
		if _, err := m.Map(e); err != nil {
			t.Errorf("%s: a value of its rangeUpper (%d chars) is refused: %v", a, upper, err)
		}
	}
}
