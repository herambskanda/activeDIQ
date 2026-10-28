package ports

// TM-F-PORTS boot proof (threat model §8.1, §15): build the real cmd/server, boot it against a real
// PostgreSQL, and compare the sockets the kernel says it holds with the §8.1 rows the configuration
// enables. The server is the only process of every profile manifest today (internal/compose/profile), so
// each configuration below is a boot of what each profile installs; when config selects a profile, add it
// to the matrix. The test skips (does not pass) with the usual storetest message when Docker is missing,
// and CI has Docker.

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

func buildServer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "server")
	out, err := exec.Command("go", "build", "-trimpath", "-o", bin, "github.com/skenzeriq/activediq/cmd/server").CombinedOutput()
	if err != nil {
		t.Fatalf("go build cmd/server: %v\n%s", err, out)
	}
	return bin
}

// boot starts the server and returns once every expected listener is up (or fails after 30 s with the
// server's stderr).
func boot(t *testing.T, bin, dsn string, env []string, wantPorts int) (pid int) {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "ACTIVEDIQ_DATABASE_DSN=" + dsn}, env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if ss, err := Listening(cmd.Process.Pid); err == nil && len(ss) >= wantPorts {
			return cmd.Process.Pid
		}
	}
	t.Fatalf("server did not open %d listener(s) in 30s; stderr:\n%s", wantPorts, stderr.String())
	return 0
}

func TestBootedServerListensOnlyOnSection81(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("socket enumeration reads /proc; the Windows service is proven in the lab (runbook tm-f-ports)")
	}
	bin := buildServer(t)
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		api := freePort(t)
		ops := freePort(t)
		tok := filepath.Join(t.TempDir(), "ops-token")
		if err := os.WriteFile(tok, []byte(strings.Repeat("t", 40)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		base := []string{fmt.Sprintf("ACTIVEDIQ_API_ADDR=127.0.0.1:%d", api)}
		withOps := append(base, fmt.Sprintf("ACTIVEDIQ_OPS_ADDR=127.0.0.1:%d", ops), "ACTIVEDIQ_OPS_TOKEN_FILE="+tok)
		l1 := Allowed{Row: "L1", Proto: "tcp", Port: api}
		l4 := Allowed{Row: "L4", Proto: "tcp", Port: ops, Loopback: true}

		cases := []struct {
			name  string
			env   []string
			allow []Allowed
		}{
			{"default: L1 only", base, []Allowed{l1}},
			{"ops enabled: L1 and L4", withOps, []Allowed{l1, l4}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				pid := boot(t, bin, d.AppDSN(), c.env, len(c.allow))
				time.Sleep(500 * time.Millisecond) // a late listener (worker, sidecar) would show by now
				got, err := Listening(pid)
				if err != nil {
					t.Fatal(err)
				}
				if v := Compare(got, c.allow); len(v) != 0 {
					t.Fatalf("TM-F-PORTS: %s", strings.Join(v, "; "))
				}
			})
		}

		// The proof must fail when the install carries a listener §8.1 does not list: boot with ops on
		// but declare only L1, as if L4 were an undeclared extra socket.
		t.Run("an undeclared listener fails the proof and names its port", func(t *testing.T) {
			pid := boot(t, bin, d.AppDSN(), withOps, 2)
			got, err := Listening(pid)
			if err != nil {
				t.Fatal(err)
			}
			v := Compare(got, []Allowed{l1})
			if len(v) != 1 || !strings.Contains(v[0], fmt.Sprint(ops)) {
				t.Fatalf("want one violation naming port %d, got %q", ops, v)
			}
		})
	})
}
