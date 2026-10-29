package credprovspike

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"credprovspike/importscan"
)

func TestImportScanOnRealPE(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "m.go")
	os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o600)
	out := filepath.Join(dir, "m.exe")
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot cross-build: %v %s", err, b)
	}
	f, _ := os.Open(out)
	defer f.Close()
	bad, err := importscan.Scan(f)
	if err != nil || len(bad) != 0 {
		t.Fatalf("err=%v bad=%v", err, bad)
	}
	// A non-PE must be an error, never a pass.
	g, _ := os.Open(src)
	defer g.Close()
	if _, err := importscan.Scan(g); err == nil {
		t.Fatal("non-PE passed")
	}
}
