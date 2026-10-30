//go:build lab && windowslab

package tier0

// Shared Windows-lab connection helper (T-0864, folds in T-0720). Before this file the two lab test
// files (windows_lab_test.go, T-0404; win_lab_tm26_test.go, T-0346) each declared their own winLab,
// so the package did not type-check under -tags 'lab windowslab'. There is exactly one winLab now:
// newWinLab dials the Windows lab DC twice, as the lab Administrator (planting and removing test
// state) and as the delegated connector account svc-activediq (the identity the classifier runs as).
//
// Environment (same for every Windows-lab test): WIN_LAB_ENV (default lab/windows/.win-lab.env),
// WIN_LAB_CA (default lab/windows/.win-lab-ca.pem), WIN_LAB_DC_ADDR (default 192.168.77.10),
// WIN_LAB_TLS_NAME (default dc1.win.activediq.test). A missing lab fails the test loudly; it is
// never skipped.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

const (
	winDom    = "DC=win,DC=activediq,DC=test" // domain head DN
	winFQDN   = "win.activediq.test"
	winTLS    = "dc1." + winFQDN
	winHostIP = "192.168.77.10"
)

// winLab is the one Windows-lab handle used by every lab-tagged test in this package that needs
// both an admin connection and a connector session.
type winLab struct {
	t      *testing.T
	env    map[string]string
	pool   *x509.CertPool
	host   string
	admin  *ldap.Conn
	sess   *ad.Session
	svc    ad.Credential
	svcSID []byte // raw objectSid of the connector account
	cls    *ADClassifier
	head   string // domain head DN
	prefix string // domain SID text
}

// labFile returns p, the value of a WIN_LAB_* variable the caller read by its constant name, or the
// default file beside lab/windows when p is empty. It takes the value, not the name, so
// fitness-profiles P1 can see which variable each call site reads (T-0889, T-0942).
func labFile(p, def string) string {
	if p != "" {
		return p
	}
	return filepath.Join("..", "..", "..", "lab", "windows", def)
}

func winCreds(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(labFile(os.Getenv("WIN_LAB_ENV"), ".win-lab.env"))
	if err != nil {
		t.Fatalf("windows lab not up or credentials missing (make windows-lab-up; runbook windows-lab.md §10): %v", err)
	}
	defer f.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "="); ok && !strings.HasPrefix(k, "#") {
			m[k] = strings.Trim(v, `"'`)
		}
	}
	return m
}

func winTLSName() string {
	if n := os.Getenv("WIN_LAB_TLS_NAME"); n != "" {
		return n
	}
	return winTLS
}

func newWinLab(t *testing.T) *winLab {
	t.Helper()
	host := os.Getenv("WIN_LAB_DC_ADDR")
	if host == "" {
		host = winHostIP
	}
	env := winCreds(t)
	pem, err := os.ReadFile(labFile(os.Getenv("WIN_LAB_CA"), ".win-lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad windows lab CA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	svc := ad.Credential{BindName: "svc-activediq@" + winFQDN, Password: secret.FromBytes([]byte(env["WIN_LAB_SVC_PASSWORD"]))}
	sess, err := ad.Open(ctx, ad.Config{Servers: []string{host + ":636"}, ServerName: winTLSName(), RootCAs: pool, PageSize: 500, Credential: svc})
	if err != nil {
		t.Fatalf("service bind (open as connector): %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	admin, err := ldap.DialURL("ldaps://"+host+":636", ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: winTLSName()}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	if err := admin.Bind("Administrator@"+winFQDN, env["WIN_LAB_ADMIN_PASSWORD"]); err != nil {
		t.Fatalf("admin bind: %v", err)
	}
	l := &winLab{t: t, env: env, pool: pool, host: host, admin: admin, sess: sess, svc: svc,
		head: winDom, cls: NewAD(SessionDirectory{S: sess})}
	r, err := admin.Search(ldap.NewSearchRequest(winDom, ldap.ScopeWholeSubtree, 0, 0, 0, false,
		"(sAMAccountName=svc-activediq)", []string{"objectSid"}, nil))
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("connector account: %v", err)
	}
	l.svcSID = r.Entries[0].GetRawAttributeValue("objectSid")
	dom := l.read(winDom, nil, "objectSid")
	s, err := sid.FromBytes(dom.GetRawAttributeValue("objectSid"))
	if err != nil {
		t.Fatal(err)
	}
	l.prefix = s.String()
	return l
}

// read returns one entry by base-object search as the lab Administrator.
func (l *winLab) read(dnText string, ctl ldap.Control, attrs ...string) *ldap.Entry {
	l.t.Helper()
	var ctls []ldap.Control
	if ctl != nil {
		ctls = append(ctls, ctl)
	}
	res, err := l.admin.Search(ldap.NewSearchRequest(dnText, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", attrs, ctls))
	if err != nil || len(res.Entries) != 1 {
		l.t.Fatalf("read %s: %v", dnText, err)
	}
	return res.Entries[0]
}
