package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Acceptance 1: a remote host with sslmode absent, disable, allow, prefer or require is refused with the
// typed error, and Open returns before any connection is attempted (192.0.2.1 is TEST-NET-1: a dial would
// hang until the deadline and fail with a different error).
func TestOpenRefusesRemoteWithoutVerifiedTLS(t *testing.T) {
	clearPGEnv(t)
	for name, q := range map[string]string{
		"absent":                        "",
		"disable":                       "?sslmode=disable",
		"allow":                         "?sslmode=allow",
		"prefer":                        "?sslmode=prefer",
		"require":                       "?sslmode=require",
		"verify-ca without sslrootcert": "?sslmode=verify-ca",
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			start := time.Now()
			db, err := Open(ctx, Config{DSN: "postgres://activediq_app:s3cret@192.0.2.1:5432/db" + q})
			var te *TransportError
			if db != nil || !errors.Is(err, ErrInsecureTransport) || !errors.As(err, &te) || te.Host != "192.0.2.1" {
				t.Fatalf("want a TransportError for 192.0.2.1, got db=%v err=%v", db, err)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("error leaks the password: %v", err)
			}
			if time.Since(start) > time.Second {
				t.Fatalf("Open took %v: it attempted a connection", time.Since(start))
			}
		})
	}
}

// The same refusals for the keyword/value DSN form, the PG* environment, hostname hosts and multi-host
// DSNs where one host is not verified.
func TestCheckTransportRefusals(t *testing.T) {
	clearPGEnv(t)
	ca := writeCA(t)
	for name, dsn := range map[string]string{
		"keyword form":                         "host=db.example.com user=u dbname=d sslmode=require",
		"hostname, no sslmode":                 "postgres://u@db.example.com/d",
		"loopback + remote":                    "postgres://u@127.0.0.1:5432,db.example.com:5432/d?sslmode=prefer",
		"second host plain":                    "host=127.0.0.1,db.example.com port=5432,5432 user=u dbname=d sslmode=disable",
		"ipv6 remote":                          "postgres://u@[2001:db8::1]/d?sslmode=disable",
		"allow with sslrootcert, remote hosts": "postgres://u@a.example.com,b.example.com/d?sslmode=allow&sslrootcert=" + ca,
		"host named like loopback":             "postgres://u@127.0.0.1.example.com/d?sslmode=disable",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CheckTransport(dsn, false); !errors.Is(err, ErrInsecureTransport) {
				t.Fatalf("want ErrInsecureTransport, got %v", err)
			}
		})
	}
	t.Run("PGSSLMODE from the environment", func(t *testing.T) {
		t.Setenv("PGSSLMODE", "disable")
		if _, err := CheckTransport("postgres://u@db.example.com/d", false); !errors.Is(err, ErrInsecureTransport) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("invalid DSN is not a transport error", func(t *testing.T) {
		_, err := CheckTransport("postgres://u:pw@db.example.com/d?sslmode=bogus", false)
		if err == nil || errors.Is(err, ErrInsecureTransport) || strings.Contains(err.Error(), "pw") {
			t.Fatalf("got %v", err)
		}
	})
}

// Acceptance 2: unix sockets, loopback and verify-full / verify-ca-with-pinned-root to a remote host are
// accepted, and none of them is reported as relaxed.
func TestCheckTransportAccepts(t *testing.T) {
	clearPGEnv(t)
	ca := writeCA(t)
	for name, dsn := range map[string]string{
		"unix socket":              "host=/var/run/postgresql user=u dbname=d sslmode=disable",
		"unix socket, no sslmode":  "postgres:///d?host=/var/run/postgresql&user=u",
		"loopback v4":              "postgres://u@127.0.0.1:5432/d?sslmode=disable",
		"loopback v4 other octets": "postgres://u@127.1.2.3/d",
		"loopback v6":              "postgres://u@[::1]:5432/d?sslmode=prefer",
		"localhost":                "postgres://u@localhost/d",
		"verify-full remote":       "postgres://u@db.example.com/d?sslmode=verify-full",
		"verify-full remote IP":    "postgres://u@192.0.2.1/d?sslmode=verify-full",
		"verify-ca pinned":         "postgres://u@db.example.com/d?sslmode=verify-ca&sslrootcert=" + ca,
		"require + sslrootcert":    "postgres://u@db.example.com/d?sslmode=require&sslrootcert=" + ca,
		"multi-host all verified":  "postgres://u@a.example.com,b.example.com/d?sslmode=verify-full&target_session_attrs=read-write",
		"loopback + verified":      "postgres://u@127.0.0.1,db.example.com/d?sslmode=verify-full",
	} {
		t.Run(name, func(t *testing.T) {
			st, err := CheckTransport(dsn, false)
			if err != nil || st.Insecure() || st.OverrideConfigured {
				t.Fatalf("want accepted and not relaxed, got %+v, %v", st, err)
			}
		})
	}
}

// The operator override accepts the refused DSN and reports exactly the hosts it relaxed; a compliant DSN
// under the override reports none.
func TestCheckTransportOverride(t *testing.T) {
	clearPGEnv(t)
	st, err := CheckTransport("postgres://u@db.example.com,127.0.0.1,db.example.com/d?sslmode=disable", true)
	if err != nil || !st.OverrideConfigured || strings.Join(st.RelaxedHosts, ",") != "db.example.com" {
		t.Fatalf("got %+v, %v", st, err)
	}
	st, err = CheckTransport("postgres://u@db.example.com/d?sslmode=verify-full", true)
	if err != nil || !st.OverrideConfigured || st.Insecure() {
		t.Fatalf("got %+v, %v", st, err)
	}
}

func clearPGEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"PGSSLMODE", "PGSSLROOTCERT", "PGHOST", "PGHOSTADDR", "PGSSLCERT", "PGSSLKEY", "PGSSLNEGOTIATION"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}
