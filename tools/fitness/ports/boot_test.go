package ports

// TM-F-PORTS boot proof (threat model §8.1, §15): build the real cmd/server, boot it against a real
// PostgreSQL, and compare the sockets the kernel says it holds with the §8.1 rows the configuration
// enables. The server is the only process of every profile manifest today (internal/compose/profile), so
// each configuration below is a boot of what each profile installs; when config selects a profile, add it
// to the matrix. The test skips (does not pass) with the usual storetest message when Docker is missing,
// and CI has Docker.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/server"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// kekEnv provisions the installation KEK the way an installer does (the product's own `kek init`, with a
// passphrase generated for this run and never committed) and returns the settings that make the server
// boot. The server refuses to start without a custody model, so every boot below needs them.
func kekEnv(t *testing.T, bin string) []string {
	t.Helper()
	dir := t.TempDir()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	pass := filepath.Join(dir, "kek-passphrase")
	if err := os.WriteFile(pass, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kekDir := filepath.Join(dir, "kek")
	env := []string{
		server.EnvKEKProvider + "=" + server.ProviderPassphrase,
		server.EnvKEKDir + "=" + kekDir,
		server.EnvKEKPassphraseFile + "=" + pass,
	}
	cmd := exec.Command(bin, "kek", "init")
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kek init: %v\n%s", err, out)
	}
	return env
}

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
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, "github.com/skenzeriq/activediq/cmd/server")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux") // static: it runs in a stock Debian container
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build cmd/server: %v\n%s", err, out)
	}
	return bin
}

// runnerImage is the stock image the server binary runs in. It is only a userland (sh, readlink, cat) to
// read /proc with; no product code or licensed content ships in it. Licence-register row: Debian.
const runnerImage = "debian:trixie-slim"

// snapshot reads the kernel's socket tables for the container's init process (the server) as root inside
// the container and rebuilds them as a /proc-shaped tree, so Listening's own parser runs on it. This is
// needed because the server sets PR_SET_DUMPABLE=0 (T-0644), which makes /proc/<pid>/fd unreadable to a
// non-root runner on the host; root in the container (which the run grants CAP_SYS_PTRACE, only for the
// exec; the server itself is non-root and holds no capability) reads it.
func snapshot(t *testing.T, id string) ([]Socket, error) {
	t.Helper()
	const script = `for f in /proc/1/fd/*; do readlink "$f"; done; echo @@; for t in tcp tcp6 udp udp6; do echo "=$t"; cat /proc/1/net/$t; done`
	out, err := exec.Command("docker", "exec", "-u", "0", id, "sh", "-c", script).Output()
	if err != nil {
		return nil, fmt.Errorf("docker exec snapshot: %w", err)
	}
	fds, nets, _ := strings.Cut(string(out), "@@\n")
	root := t.TempDir()
	fdDir := filepath.Join(root, "1", "fd")
	netDir := filepath.Join(root, "1", "net")
	for _, d := range []string{fdDir, netDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	for i, l := range strings.Split(strings.TrimSpace(fds), "\n") {
		if l == "" {
			continue
		}
		if err := os.Symlink(l, filepath.Join(fdDir, fmt.Sprint(i))); err != nil {
			return nil, err
		}
	}
	for _, blk := range strings.Split(nets, "=")[1:] {
		name, body, _ := strings.Cut(blk, "\n")
		if err := os.WriteFile(filepath.Join(netDir, name), []byte(body), 0o644); err != nil {
			return nil, err
		}
	}
	return listening(root, "1")
}

// boot starts the server in a container on the host network (so it reaches the test PostgreSQL and binds
// the real ports) and returns its id once every expected listener is up (or fails after 30 s with the
// server's logs). Paths are mounted at the same location inside, so the settings in env hold unchanged.
func boot(t *testing.T, bin, dsn string, env []string, wantPorts int) (id string) {
	t.Helper()
	args := []string{"run", "-d", "--network", "host", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--security-opt", "no-new-privileges:true", "-v", filepath.Dir(bin) + ":" + filepath.Dir(bin) + ":ro"}
	mounted := map[string]bool{filepath.Dir(bin): true}
	all := append([]string{"ACTIVEDIQ_DATABASE_DSN=" + dsn}, env...)
	for _, e := range all {
		args = append(args, "-e", e)
		_, v, _ := strings.Cut(e, "=")
		if filepath.IsAbs(v) { // a file or directory setting: mount its directory (the KEK dir itself, a file's parent)
			d := v
			if fi, err := os.Stat(v); err == nil && !fi.IsDir() {
				d = filepath.Dir(v)
			}
			if !mounted[d] {
				mounted[d] = true
				args = append(args, "-v", d+":"+d)
			}
		}
	}
	args = append(args, runnerImage, bin)
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	id = strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "-v", id).Run() })
	var lastErr error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		ss, err := snapshot(t, id)
		if err == nil && len(ss) >= wantPorts {
			return id
		}
		lastErr = err
	}
	logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
	t.Fatalf("server did not open %d listener(s) in 30s (last socket-enumeration error: %v); logs:\n%s", wantPorts, lastErr, logs)
	return ""
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
		base := append(kekEnv(t, bin), fmt.Sprintf("ACTIVEDIQ_API_ADDR=127.0.0.1:%d", api))
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
				id := boot(t, bin, d.AppDSN(), c.env, len(c.allow))
				time.Sleep(500 * time.Millisecond) // a late listener (worker, sidecar) would show by now
				got, err := snapshot(t, id)
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
			id := boot(t, bin, d.AppDSN(), withOps, 2)
			got, err := snapshot(t, id)
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
