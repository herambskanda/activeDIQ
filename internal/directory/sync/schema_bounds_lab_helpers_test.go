//go:build lab

package sync_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
)

// boundsAttrs are the attributes whose mapper bound T-1250 checks against the schema's rangeUpper.
var boundsAttrs = []string{"sAMAccountName", "userPrincipalName", "displayName", "mail", "company", "description",
	"dNSHostName", "operatingSystem", "operatingSystemVersion"}

// schemaFilter renders (lDAPDisplayName=<attr>) with the safe filter builder (T-1880 AC3: the lab test no
// longer concatenates a filter).
func schemaFilter(t *testing.T, attr string) string {
	t.Helper()
	sc := ldapfilter.NewSchema(ldapfilter.AttrInfo{Name: "lDAPDisplayName", Syntax: ldapfilter.SynString})
	name, err := ldapfilter.ParseAttrName("lDAPDisplayName", sc)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ldapfilter.Render(ldapfilter.Eq(name, ldapfilter.String(attr)), sc)
	if err != nil {
		t.Fatalf("render schema filter for %q: %v", attr, err)
	}
	return f.String()
}

// readEnvFile parses a KEY=VALUE lab env file (optional "export ").
func readEnvFile(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("lab not up (%s): %v", path, err)
	}
	defer f.Close()
	env := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(sc.Text()), "export "))
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			env[k] = strings.Trim(v, `"'`)
		}
	}
	return env
}

func labDir(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "..", "lab"}, parts...)...)
}

// mapsAtRangeUpper maps a computer whose attribute a holds exactly upper multi-byte characters and
// reports the refusal, if any. A byte count would refuse it, a character count must not.
func mapsAtRangeUpper(a string, upper int) error {
	v := strings.Repeat("é", upper)
	e := entry(90, "CN=PC1,OU=Staff,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("top", "computer").with(a, txt(v)))
	_, err := mapper(dirsync.Config{}).Map(e)
	return err
}
