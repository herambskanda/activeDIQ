//go:build lab

package ad

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

// TestLabUnicodePwdVectors runs PW-04, PW-14 and PW-09 against the Samba AD lab (T-0074).
func TestLabUnicodePwdVectors(t *testing.T) {
	env := labEnv(t)
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad lab CA")
	}
	port := env["LAB_LDAPS_PORT"]
	if port == "" {
		port = "636"
	}
	runUnicodePwdVectors(t, pwTarget{
		label: "samba", addr: "localhost:" + port, serverName: "localhost", roots: pool,
		adminBind: "Administrator@lab.activediq.test", adminPW: env["LAB_ADMIN_PASSWORD"],
		base: labBase, upnSuffix: "lab.activediq.test", acceptsOverCap: true,
	})
}
