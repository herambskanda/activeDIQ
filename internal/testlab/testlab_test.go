package testlab

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestMissingLabIsAnErrorNamingMakeLabUp(t *testing.T) {
	_, err := load(t.TempDir(), false)
	if err == nil || !strings.Contains(err.Error(), "make lab-up") {
		t.Fatalf("want error naming make lab-up, got %v", err)
	}
}

func TestOldEnvWithoutPortIsRejected(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "lab"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "lab", ".lab.env"), []byte("LAB_ENV_ID=x\n"), 0o600)
	_ = os.WriteFile(filepath.Join(root, "lab", ".lab-ca.pem"), []byte(testCA), 0o600)
	if _, err := load(root, false); err == nil || !strings.Contains(err.Error(), "make lab-up") {
		t.Fatalf("got %v", err)
	}
}

func TestUnreachableLabFailsAndReachableLoads(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "lab"), 0o755)
	write := func(p int) {
		env := "LAB_LDAPS_PORT=" + strconv.Itoa(p) + "\nLAB_CONTAINER=c\n"
		_ = os.WriteFile(filepath.Join(root, "lab", ".lab.env"), []byte(env), 0o600)
	}
	_ = os.WriteFile(filepath.Join(root, "lab", ".lab-ca.pem"), []byte(testCA), 0o600)
	write(port)
	e, err := load(root, true)
	if err != nil || e.Container != "c" {
		t.Fatalf("reachable: %v %v", e, err)
	}
	ln.Close()
	if _, err := load(root, true); err == nil || !strings.Contains(err.Error(), "make lab-up") {
		t.Fatalf("closed port must fail naming make lab-up, got %v", err)
	}
}

const testCA = `-----BEGIN CERTIFICATE-----
MIIBbTCCAROgAwIBAgIUM8o/xotFgDHnZyjmg2CFPvfFmnIwCgYIKoZIzj0EAwIw
DDEKMAgGA1UEAwwBdDAeFw0yNjEwMjYxMTM1MTBaFw0zNjEwMjMxMTM1MTBaMAwx
CjAIBgNVBAMMAXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9FOd3NiaMQiGu
gjKOFnsr4nTbTE3qby8ftsO1wFkkUKNC+l9Q9R5VAp2V3QYI4+C4Iu8A+q0CPPYF
gKGP9yQto1MwUTAdBgNVHQ4EFgQUwuTUeiVSXODAXRFhwB4YodJ72JMwHwYDVR0j
BBgwFoAUwuTUeiVSXODAXRFhwB4YodJ72JMwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAgNIADBFAiEAvdboIaf/ZyDHaRXg14ASjC9MsrwllTrxX7546i0RCMQC
IHuLNQFQGLf2AeQF4XcWWSR2WbUxIdfHS8HUXnaslp0j
-----END CERTIFICATE-----
`
