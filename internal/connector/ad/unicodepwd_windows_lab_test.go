//go:build lab && windowslab

package ad

import (
	"crypto/x509"
	"os"
	"testing"
)

// TestWindowsLabUnicodePwdVectors runs the same vectors against the Windows Server 2025 lab (T-0074).
func TestWindowsLabUnicodePwdVectors(t *testing.T) {
	host := os.Getenv("WIN_LAB_DC_ADDR")
	if host == "" {
		host = "192.168.77.10"
	}
	pem, err := os.ReadFile(labFile(os.Getenv("WIN_LAB_CA"), ".win-lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad windows lab CA")
	}
	runUnicodePwdVectors(t, pwTarget{
		label: "windows", addr: host + ":636", serverName: winTLSName(), roots: pool,
		adminBind: "Administrator@win.activediq.test", adminPW: winEnv(t)["WIN_LAB_ADMIN_PASSWORD"],
		base: winBase, upnSuffix: "win.activediq.test",
	})
}
