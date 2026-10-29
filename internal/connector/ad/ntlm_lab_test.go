//go:build lab

package ad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// dialRecorder records every TCP destination the session's dialer is asked to connect to.
type dialRecorder struct {
	mu    sync.Mutex
	addrs []string
}

func (r *dialRecorder) dialer() *net.Dialer {
	return &net.Dialer{Timeout: 15 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		r.mu.Lock()
		r.addrs = append(r.addrs, address)
		r.mu.Unlock()
		return nil
	}}
}

// attackerListener stands in for the attacker's SMB host named by the planted UNC path. Any
// accepted connection means the connector (or something it triggered) dialled the UNC target.
func attackerListener(t *testing.T) (host string, accepted func() int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	n := 0
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			n++
			mu.Unlock()
			c.Close()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l.Addr().String(), func() int { mu.Lock(); defer mu.Unlock(); return n }
}

// proveNoSideDial plants a UNC homeDirectory/profilePath on a fresh user (using an admin bind
// outside the connector), then binds, searches and reads that user through the connector Session
// with a recording dialer. Asserts: homeDirectory is returned as inert data, every dial goes to the
// DC, and the attacker listener sees zero connections. Network-level (any port) and NTLM event
// evidence (4776, 8001-8004) must additionally come from the Windows lab (see windows lab test).
func proveNoSideDial(t *testing.T, cfg Config, server, adminBind, adminPW, base string, roots *x509.CertPool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	attacker, accepted := attackerListener(t)
	host, _, _ := net.SplitHostPort(attacker)
	unc := `\\` + host + `\evil\home`

	adm, err := ldap.DialURL("ldaps://"+server, ldap.DialWithTLSConfig(&tls.Config{RootCAs: roots, ServerName: cfg.ServerName, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer adm.Close()
	if err := adm.Bind(adminBind, adminPW); err != nil {
		t.Fatalf("admin bind: %v", err)
	}
	samName := "ntlmplant" + time.Now().Format("150405")
	userDN := "CN=" + samName + ",CN=Users," + base
	add := ldap.NewAddRequest(userDN, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{samName})
	add.Attribute("homeDirectory", []string{unc})
	add.Attribute("homeDrive", []string{"H:"})
	add.Attribute("profilePath", []string{unc})
	add.Attribute("scriptPath", []string{unc + `\logon.bat`})
	if err := adm.Add(add); err != nil {
		t.Fatalf("plant user: %v", err)
	}
	t.Cleanup(func() { _ = adm.Del(ldap.NewDelRequest(userDN, nil)) })

	rec := &dialRecorder{}
	cfg.Dialer = rec.dialer()
	s, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	var g guid.GUID
	found := 0
	root, err := dn.Parse(base, dn.Strict)
	if err != nil {
		t.Fatal(err)
	}
	sam, err := ldapfilter.ParseAttrName("sAMAccountName", s.schema)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Search(ctx, SearchRequest{Base: dn.DNRef(root), Scope: ScopeSubtree, Filter: ldapfilter.Eq(sam, ldapfilter.String(samName)),
		Attributes: []string{"objectGUID", "homeDirectory"}}, func(e *Entry) error {
		found++
		g, _ = e.GUID()
		return nil
	})
	if err != nil || found != 1 {
		t.Fatalf("search planted user: found=%d err=%v", found, err)
	}
	e, err := s.Read(ctx, dn.GUIDRef(g), []string{"homeDirectory", "homeDrive", "profilePath", "scriptPath"}, ReadOptions{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := e.Strings("homeDirectory"); len(got) != 1 || got[0] != unc {
		t.Fatalf("homeDirectory = %q, want the planted UNC returned as data", got)
	}
	time.Sleep(2 * time.Second) // let any lazy side-connection surface

	if n := accepted(); n != 0 {
		t.Errorf("attacker host %s received %d connection(s): the UNC path was dialled", attacker, n)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.addrs) == 0 {
		t.Fatal("recording dialer saw no dials: proof is vacuous")
	}
	dcHost, dcPort, _ := net.SplitHostPort(server)
	for _, a := range rec.addrs {
		h, p, _ := net.SplitHostPort(a)
		if p != dcPort || (h != dcHost && !isLoopbackPair(h, dcHost)) {
			t.Errorf("session dialled %s; only the DC %s is allowed", a, server)
		}
	}
}

func isLoopbackPair(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia != nil && ia.IsLoopback() {
		return b == "localhost" || (ib != nil && ib.IsLoopback())
	}
	return false
}

func TestLabNoSideDialOnPlantedUNC(t *testing.T) {
	env := labEnv(t)
	port := env["LAB_LDAPS_PORT"]
	if port == "" {
		port = "636"
	}
	cfg, roots := labConfigForProof(t, env, port)
	proveNoSideDial(t, cfg, "localhost:"+port, "Administrator@lab.activediq.test", env["LAB_ADMIN_PASSWORD"], labBase, roots)
}

func labConfigForProof(t *testing.T, env map[string]string, port string) (Config, *x509.CertPool) {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad lab CA")
	}
	return Config{
		Servers: []string{"localhost:" + port}, ServerName: "localhost", RootCAs: pool, PageSize: 500,
		Credential: Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))},
	}, pool
}
