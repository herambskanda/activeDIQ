//go:build lab && windowslab

package inventory_test

// T-1070, Windows target: the same oracle as lab_groups_test.go against the real Windows DC
// (`make windows-lab-up`), for what Samba cannot hold: a foreign security principal member and Windows'
// own primary-group and tokenGroups semantics. The lab must carry the OU=GroupOracle seed, including an
// FSP in GG-Oracle-Top (lab/seed/README: Windows seed, follow-up ticket). Nothing is skipped when the lab or
// the seed is missing: the run fails and says what to do.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

const (
	winNC   = "DC=win,DC=activediq,DC=test"
	winBind = "svc-activediq@win.activediq.test"
)

func winFile(envVar, def string) string {
	if p := os.Getenv(envVar); p != "" {
		return p
	}
	return filepath.Join("..", "..", "..", "lab", "windows", def)
}

func TestLabGroupDatasetsMatchLDAPAndTokenGroupsWindows(t *testing.T) {
	f, err := os.Open(winFile("WIN_LAB_ENV", ".win-lab.env"))
	if err != nil {
		t.Fatalf("windows lab not up (make windows-lab-up): %v", err)
	}
	defer f.Close()
	env := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "="); ok && !strings.HasPrefix(k, "#") {
			env[k] = strings.Trim(v, `"'`)
		}
	}
	pw := env["WIN_LAB_SVC_PASSWORD"]
	host := os.Getenv("WIN_LAB_DC_ADDR")
	if host == "" {
		host = "192.168.77.10"
	}
	tlsName := os.Getenv("WIN_LAB_TLS_NAME")
	if tlsName == "" {
		tlsName = "dc1.win.activediq.test"
	}
	caPath := winFile("WIN_LAB_CA", ".win-lab-ca.pem")
	pem, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad windows lab CA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := ad.Open(ctx, ad.Config{Servers: []string{host + ":636"}, ServerName: tlsName, RootCAs: pool, PageSize: 500,
		Credential: ad.Credential{BindName: winBind, Password: secret.FromBytes([]byte(pw))}})
	if err != nil {
		t.Fatalf("open windows lab: %v", err)
	}
	defer s.Close()
	runGroupOracle(t, &labTarget{name: "windows", sess: s, nc: winNC, managed: "OU=Managed," + winNC, wantFSP: true,
		ldapsearch: func(t *testing.T, args ...string) string {
			t.Helper()
			// the reference client is the host's ldapsearch; the DC name (WIN_LAB_TLS_NAME) must resolve on the host, the certificate names it
			cmd := exec.Command("ldapsearch", append([]string{"-H", "ldaps://" + tlsName + ":636", "-x", "-D", winBind, "-y", "/dev/stdin", "-LLL", "-o", "ldif-wrap=no"}, args...)...)
			cmd.Env = append(os.Environ(), "LDAPTLS_CACERT="+caPath, "LDAPTLS_REQCERT=demand")
			cmd.Stdin = strings.NewReader(pw)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("host ldapsearch: %v\n%s", err, stderr.String())
			}
			return string(out)
		}})
}
