package hostcheck

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/skenzeriq/activediq/tools/fitness/pgharness"
)

const (
	imageDockerfile = "packaging/linux-oci/Dockerfile.server"
	tlsMount        = "/var/lib/activediq/tls"
	serviceUID      = 10001
)

func docker(ctx context.Context, stdin io.Reader, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = stdin
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("docker %s: %v: %s", strings.Join(args[:min(2, len(args))], " "), err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// BuildImage builds cmd/server for linux (static, no cgo) and the scratch image from packaging/linux-oci.
func BuildImage(ctx context.Context, repo, tag string) error {
	dir, err := os.MkdirTemp("", "host-image-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", filepath.Join(dir, "server"), "./cmd/server")
	build.Dir = repo
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if b, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("go build ./cmd/server: %v: %s", err, b)
	}
	df, err := os.ReadFile(filepath.Join(repo, imageDockerfile))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), df, 0o600); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(dir, "tls"), 0o700); err != nil {
		return err
	}
	_, err = docker(ctx, nil, "build", "-q", "-t", tag, dir)
	return err
}

type container struct{ id string }

func (c *container) rm() {
	if c.id != "" {
		_, _ = docker(context.Background(), nil, "rm", "-f", "-v", c.id)
	}
}

func runServer(ctx context.Context, tag string, env []string, extra ...string) (*container, error) {
	args := []string{"run", "-d", "--network", "host", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"}
	args = append(args, extra...)
	for _, e := range env {
		args = append(args, "-e", e)
	}
	args = append(args, tag)
	out, err := docker(ctx, nil, args...)
	if err != nil {
		return nil, err
	}
	return &container{id: strings.TrimSpace(out)}, nil
}

func waitExit(ctx context.Context, c *container, d time.Duration) (code int, logs string, exited bool) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		out, _ := docker(ctx, nil, "inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", c.id)
		f := strings.Fields(out)
		if len(f) == 2 && f[0] == "false" {
			n, _ := strconv.Atoi(f[1])
			return n, "", true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0, "", false
}

func combinedLogs(ctx context.Context, c *container) string {
	cmd := exec.CommandContext(ctx, "docker", "logs", c.id)
	b, _ := cmd.CombinedOutput()
	return string(b)
}

// CollectOCI boots the real server and returns what it observed. pg is a running PostgreSQL harness.
func CollectOCI(ctx context.Context, repo string, pg *pgharness.Server, log func(string, ...any)) (Observation, error) {
	o := Observation{Profile: "linux-oci"}
	tag := "activediq-host-proof:" + strconv.FormatInt(time.Now().UnixNano(), 36)
	log("building cmd/server and %s", imageDockerfile)
	if err := BuildImage(ctx, repo, tag); err != nil {
		return o, err
	}
	defer func() { _, _ = docker(context.Background(), nil, "rmi", "-f", tag) }()

	// --- remote DSN cases: each is a real boot of the real server, offered a DSN to a non-loopback host.
	// 192.0.2.1 is TEST-NET-1 (RFC 5737): nothing answers, so "Contacted" is judged by how long the boot
	// took to refuse, and by the refusal text, which the store emits before any dial.
	bad := []struct{ mode, extra string }{
		{"disable", "sslmode=disable"},
		{"allow", "sslmode=allow"},
		{"prefer", "sslmode=prefer"},
		{"require", "sslmode=require"},
		{"verify-ca (no sslrootcert)", "sslmode=verify-ca"},
	}
	for _, b := range bad {
		p, err := freePort()
		if err != nil {
			return o, err
		}
		c, err := runServer(ctx, tag, []string{
			"ACTIVEDIQ_DATABASE_DSN=postgres://u:p@192.0.2.1:5432/d?" + b.extra,
			fmt.Sprintf("ACTIVEDIQ_API_ADDR=127.0.0.1:%d", p),
		}, "--user", fmt.Sprintf("%d:%d", serviceUID, serviceUID), "--tmpfs", tlsMount+":uid=10001,gid=10001,mode=0700")
		if err != nil {
			return o, err
		}
		start := time.Now()
		code, _, exited := waitExit(ctx, c, 20*time.Second)
		logs := combinedLogs(ctx, c)
		took := time.Since(start)
		c.rm()
		refused := exited && code != 0 && strings.Contains(logs, "refusing the database connection")
		o.DSN = append(o.DSN, DSNProbe{Mode: b.mode, Remote: true, Accepted: !refused, Contacted: !refused || took > 5*time.Second})
		log("dsn %-28s refused=%v exit=%d in %s", b.mode, refused, code, took.Round(time.Millisecond))
	}

	// --- the booted install: PostgreSQL on loopback (exempt from the TLS rule), migrated.
	db, err := pg.NewDatabase(ctx)
	if err != nil {
		return o, err
	}
	defer db.Drop(context.Background())
	ms, ps, err := pgharness.ListMigrations(filepath.Join(repo, "migrations"))
	if err != nil || len(ps) > 0 {
		return o, fmt.Errorf("migrations: %v %v", err, ps)
	}
	if failed, msg, err := pgharness.Apply(ctx, db, ms); err != nil || failed != "" {
		return o, fmt.Errorf("migrate %s: %s %v", failed, msg, err)
	}
	port, err := freePort()
	if err != nil {
		return o, err
	}
	vol := "host-proof-tls-" + strconv.Itoa(port)
	defer func() { _, _ = docker(context.Background(), nil, "volume", "rm", "-f", vol) }()
	c, err := runServer(ctx, tag, []string{
		"ACTIVEDIQ_DATABASE_DSN=" + db.AppDSN(),
		fmt.Sprintf("ACTIVEDIQ_API_ADDR=127.0.0.1:%d", port),
		"ACTIVEDIQ_API_TLS_DIR=" + tlsMount,
	}, "--user", fmt.Sprintf("%d:%d", serviceUID, serviceUID), "-v", vol+":"+tlsMount)
	if err != nil {
		return o, err
	}
	defer c.rm()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := waitListen(ctx, c, addr, 30*time.Second); err != nil {
		return o, fmt.Errorf("the install did not boot: %v\n%s", err, combinedLogs(ctx, c))
	}
	log("booted %s", addr)

	// Positive control for the DSN case: the same server, loopback DSN, completes boot (above); the
	// compliant remote form is covered by store.CheckTransport's own tests (verify-full needs a TLS PostgreSQL).
	o.DSN = append(o.DSN, DSNProbe{Mode: "loopback (exempt)", Remote: false, Accepted: true, MustAccept: true})

	// Service identity: what the kernel says, not what the image config says.
	pidOut, _ := docker(ctx, nil, "inspect", "-f", "{{.State.Pid}}", c.id)
	pid := strings.TrimSpace(pidOut)
	uid, err := procUID(pid)
	if err != nil {
		return o, err
	}
	cfgUser, _ := docker(ctx, nil, "inspect", "-f", "{{.Config.User}}", c.id)
	o.Service = &Service{Account: strings.TrimSpace(cfgUser), UID: &uid}

	// First-run state: TLS only, nothing answers plaintext, no well-known login works.
	o.First = firstRun(addr)

	// Files: the TLS directory and its contents, from the container's own tar headers.
	fs, err := tlsFiles(ctx, c, uid)
	if err != nil {
		return o, err
	}
	o.Files = fs

	// Dump posture: kernel view of the live process.
	o.Dumps = dumpPosture(ctx, c, pid)
	return o, nil
}

func waitListen(ctx context.Context, c *container, addr string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		out, _ := docker(ctx, nil, "inspect", "-f", "{{.State.Running}}", c.id)
		if strings.TrimSpace(out) != "true" {
			return fmt.Errorf("container exited")
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // probing our own fresh listener for its presence
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("no TLS listener on %s after %s", addr, d)
}

func procUID(pid string) (int, error) {
	b, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return 0, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 3 && f[0] == "Uid:" {
			return strconv.Atoi(f[2]) // effective uid
		}
	}
	return 0, fmt.Errorf("no Uid line in /proc/%s/status", pid)
}

func firstRun(addr string) *FirstRun {
	fr := &FirstRun{}
	l := Listener{Addr: addr}
	// Plaintext probe: an HTTP request in the clear must not get an HTTP answer.
	if conn, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		l.PlaintextResponds = PlaintextServes(string(buf[:n]))
		_ = conn.Close()
	}
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // the probe asks whether any login works; the certificate is the subject of another proof
	if r, err := cl.Get("https://" + addr + "/"); err == nil {
		l.TLS = true
		_ = r.Body.Close()
	} else if conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}); err == nil { //nolint:gosec // see above
		l.TLS = true
		_ = conn.Close()
	}
	fr.Listeners = []Listener{l}
	for _, cred := range [][2]string{{"admin", "admin"}, {"admin", "password"}, {"administrator", "administrator"}, {"root", "root"}, {"activediq", "activediq"}} {
		for _, path := range []string{"/", "/api/v1/", "/api/v1/session"} {
			req, _ := http.NewRequest(http.MethodGet, "https://"+addr+path, nil)
			req.SetBasicAuth(cred[0], cred[1])
			r, err := cl.Do(req)
			if err != nil {
				continue
			}
			_ = r.Body.Close()
			if r.StatusCode/100 == 2 && path != "/" { // "/" may serve the public shell; only an API 2xx is a login
				fr.DefaultCredentials = append(fr.DefaultCredentials, cred[0]+" on "+path)
			}
		}
	}
	return fr
}

func tlsFiles(ctx context.Context, c *container, svcUID int) ([]File, error) {
	cmd := exec.CommandContext(ctx, "docker", "cp", c.id+":"+tlsMount+"/.", "-")
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker cp: %v", err)
	}
	var fs []File
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := filepath.Clean(h.Name)
		kind := "tls-key"
		if h.Typeflag == tar.TypeDir {
			kind = "tls-dir"
			if name == "." {
				name = tlsMount
			}
		}
		mode := h.FileInfo().Mode().Perm()
		f := File{Path: name, Kind: kind, Mode: fmt.Sprintf("%04o", mode), Owner: strconv.Itoa(h.Uid)}
		f.ReadableByOthers = mode&0o044 != 0 || (h.Uid != svcUID && h.Uid != 0)
		f.WritableByOthers = mode&0o022 != 0
		if kind == "tls-key" && !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".pem") || kind == "tls-dir" {
			fs = append(fs, f)
		} else if mode&0o022 != 0 { // a certificate may be world-readable, never writable
			fs = append(fs, f)
		}
	}
	if len(fs) == 0 {
		return nil, fmt.Errorf("the TLS directory is empty: the server wrote no key")
	}
	return fs, nil
}

func dumpPosture(ctx context.Context, c *container, pid string) *Dumps {
	d := &Dumps{}
	if b, err := os.ReadFile("/proc/" + pid + "/limits"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "Max core file size") {
				f := strings.Fields(l)
				d.CoreLimitZero = len(f) >= 6 && f[4] == "0" && f[5] == "0"
			}
		}
	}
	// A non-dumpable process's /proc/<pid> entries are owned by root, not by the process's uid.
	if st, err := os.Stat("/proc/" + pid); err == nil {
		d.NotDumpable = fileOwner(st) == 0
	}
	env, _ := docker(ctx, nil, "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", c.id)
	d.TracebackCrash = strings.Contains(env, "GOTRACEBACK=crash")
	// pprof: the default mux route must not answer.
	return d
}
