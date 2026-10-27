//go:build lab && windowslab

// Windows lab tests (T-0254): the connector against the real Windows Server 2025 DC from
// `make windows-lab-up`. Run with `make lab-test-connector-windows`; the run log lands in
// knowledge/development/runbooks/windows-lab-runs/. Credentials come from lab/windows/.win-lab.env and the trust anchor from
// lab/windows/.win-lab-ca.pem; nothing is skipped when the lab is missing, so the run fails loudly.
package ad

import (
	"bufio"
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/secret"
)

const (
	winBase = "DC=win,DC=activediq,DC=test"
	winBind = "svc-activediq@win.activediq.test"
	winName = "dc1.win.activediq.test" // the name in the DC's certificate; dialled by IP via ServerName
)

// winLabPath returns the file named by envVar (external-host mode, T-0428) or the default beside lab/windows.
func winLabPath(envVar, def string) string {
	if p := os.Getenv(envVar); p != "" {
		return p
	}
	return filepath.Join("..", "..", "..", "lab", "windows", def)
}

// winTLSName is the name in the DC's certificate; WIN_LAB_TLS_NAME overrides it for an external DC.
func winTLSName() string {
	if n := os.Getenv("WIN_LAB_TLS_NAME"); n != "" {
		return n
	}
	return winName
}

func winEnv(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(winLabPath("WIN_LAB_ENV", ".win-lab.env"))
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
	return env
}

func winConfig(t *testing.T, pw string, trust bool) Config {
	t.Helper()
	host := os.Getenv("WIN_LAB_DC_ADDR")
	if host == "" {
		host = "192.168.77.10"
	}
	cfg := Config{
		Servers: []string{host + ":636"}, ServerName: winTLSName(), PageSize: 500,
		Credential: Credential{BindName: winBind, Password: secret.FromBytes([]byte(pw))},
	}
	if trust {
		pem, err := os.ReadFile(winLabPath("WIN_LAB_CA", ".win-lab-ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatal("bad windows lab CA")
		}
		cfg.RootCAs = pool
	}
	return cfg
}

func TestWindowsLabLDAPSBindAndRootDSE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := Open(ctx, winConfig(t, winEnv(t)["WIN_LAB_SVC_PASSWORD"], true))
	if err != nil {
		t.Fatalf("open over LDAPS: %v", err)
	}
	defer s.Close()
	r, err := s.RootDSE(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(r.DefaultNamingContext, winBase) {
		t.Errorf("defaultNamingContext = %q, want %q", r.DefaultNamingContext, winBase)
	}
	for _, oid := range []string{"1.2.840.113556.1.4.319", "1.2.840.113556.1.4.801"} {
		if !r.SupportsControl(oid) {
			t.Errorf("DC does not advertise control %s", oid)
		}
	}
}

func TestWindowsLabRejectsWrongPasswordAndUntrustedCert(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, winConfig(t, "wrong-password", true)); CodeOf(err) != CodeBindFailed {
		t.Errorf("wrong password: %v", err)
	}
	// System roots do not trust the lab CA: the connection must fail, never fall back.
	if _, err := Open(ctx, winConfig(t, winEnv(t)["WIN_LAB_SVC_PASSWORD"], false)); CodeOf(err) != CodeUnreachable {
		t.Errorf("untrusted CA: %v", err)
	}
}
