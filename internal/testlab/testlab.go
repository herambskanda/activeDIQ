// Package testlab is the single source of truth for lab tests (T-0373): it reads lab/.lab.env
// (written by `make lab-up`, per worktree) and returns the LDAPS port, container name, CA and
// credentials. A missing or unreachable lab is a test FAILURE with a `make lab-up` message,
// never a skip — a skipped Tier-0 refusal test is a false green.
package testlab

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Env is the running lab as recorded by `make lab-up`.
type Env struct {
	Values    map[string]string
	Port      string // LDAPS host port
	Container string // DC container name
	CAPath    string
	Pool      *x509.CertPool
}

// Load returns the lab or fails the test with a clear instruction.
func Load(tb testing.TB) *Env {
	tb.Helper()
	root, err := repoRoot()
	if err != nil {
		tb.Fatalf("%v", err)
	}
	e, err := load(root, true)
	if err != nil {
		tb.Fatalf("%v", err)
	}
	return e
}

func repoRoot() (string, error) {
	d, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(d, "lab", "docker-compose.yml")); err == nil {
			return d, nil
		}
		p := filepath.Dir(d)
		if p == d {
			return "", errors.New("repository root (lab/docker-compose.yml) not found")
		}
		d = p
	}
}

func load(root string, dial bool) (*Env, error) {
	const hint = "run `make lab-up` in this worktree first (lab tests fail, not skip, when the lab is missing)"
	vals, err := readEnv(filepath.Join(root, "lab", ".lab.env"))
	if err != nil {
		return nil, fmt.Errorf("lab not up: %v: %s", err, hint)
	}
	pem, err := os.ReadFile(filepath.Join(root, "lab", ".lab-ca.pem"))
	if err != nil {
		return nil, fmt.Errorf("lab CA missing: %v: %s", err, hint)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("lab CA is not valid PEM: " + hint)
	}
	e := &Env{Values: vals, Port: vals["LAB_LDAPS_PORT"], Container: vals["LAB_CONTAINER"],
		CAPath: filepath.Join(root, "lab", ".lab-ca.pem"), Pool: pool}
	if e.Port == "" || e.Container == "" {
		return nil, errors.New("lab/.lab.env predates per-worktree labs (no LAB_LDAPS_PORT/LAB_CONTAINER): " + hint)
	}
	if dial {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+e.Port, 3*time.Second)
		if err != nil {
			return nil, fmt.Errorf("lab DC not reachable on 127.0.0.1:%s: %v: %s", e.Port, err, hint)
		}
		_ = c.Close()
	}
	return e, nil
}

func readEnv(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
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
	return env, sc.Err()
}
