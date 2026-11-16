//go:build lab && windowslab

package read_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"google.golang.org/protobuf/proto"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1282 through the real ChangeFeed handler against the Windows lab DC (dc1). Run:
//
//	lab/windows/bin/with-dc1-lock -- go test -tags 'lab windowslab' -run TestWindowsLabFeed ./internal/connector/read
//
// From a worktree set WIN_LAB_ENV and WIN_LAB_CA to the main checkout's lab/windows files (they are
// gitignored). The DC address comes from WIN_LAB_DC_ADDR or the env file; there is no default.

const (
	winDom  = "DC=win,DC=activediq,DC=test"
	winSvc  = "svc-activediq@win.activediq.test"
	winAdm  = "Administrator@win.activediq.test"
	winName = "dc1.win.activediq.test"
)

func winLabEnv(t *testing.T) map[string]string {
	t.Helper()
	p := os.Getenv("WIN_LAB_ENV")
	if p == "" {
		p = filepath.Join("..", "..", "..", "lab", "windows", ".win-lab.env")
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("windows lab env: %v", err)
	}
	defer f.Close()
	env := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "="); ok && !strings.HasPrefix(k, "#") {
			env[k] = strings.Trim(v, `"'`)
		}
	}
	if a := os.Getenv("WIN_LAB_DC_ADDR"); a != "" {
		env["WIN_LAB_DC_ADDR"] = a
	}
	if env["WIN_LAB_DC_ADDR"] == "" {
		t.Fatal("WIN_LAB_DC_ADDR is not set")
	}
	return env
}

type winFeedLab struct {
	env  map[string]string
	pool *x509.CertPool
	adm  *ldap.Conn
}

func newWinFeedLab(t *testing.T) *winFeedLab {
	t.Helper()
	env := winLabEnv(t)
	ca := os.Getenv("WIN_LAB_CA")
	if ca == "" {
		ca = filepath.Join("..", "..", "..", "lab", "windows", ".win-lab-ca.pem")
	}
	pem, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad windows lab CA")
	}
	adm, err := ldap.DialURL("ldaps://"+env["WIN_LAB_DC_ADDR"]+":636", ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: winName, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adm.Close() })
	if err := adm.Bind(winAdm, env["WIN_LAB_ADMIN_PASSWORD"]); err != nil {
		t.Fatal(err)
	}
	return &winFeedLab{env: env, pool: pool, adm: adm}
}

func (l *winFeedLab) guidOf(t *testing.T, dn string) guid.GUID {
	t.Helper()
	r, err := l.adm.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("guid of %s: %v", dn, err)
	}
	g, err := guid.FromBytes(r.Entries[0].GetRawAttributeValue("objectGUID"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// open serves the read group over the connector identity (svc-activediq, not an administrator).
func (l *winFeedLab) open(t *testing.T) *feed {
	t.Helper()
	cfg := ad.Config{Servers: []string{l.env["WIN_LAB_DC_ADDR"] + ":636"}, ServerName: winName, RootCAs: l.pool, PageSize: 500,
		Credential: ad.Credential{BindName: winSvc, Password: secret.FromBytes([]byte(l.env["WIN_LAB_SVC_PASSWORD"]))}, Schema: ad.DefaultSchema()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	sess, err := ad.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	nc := l.guidOf(t, winDom)
	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: write.GUIDToWire(nc)}}}
	prov := write.NewADProvider(sess, nil, ident, &memPins{})
	src, err := read.NewADSource(sess, prov)
	if err != nil {
		t.Fatal(err)
	}
	return &feed{c: startFeed(t, src), src: src, prov: prov, nc: write.GUIDToWire(nc)}
}

func (l *winFeedLab) ou(t *testing.T, name string) string {
	t.Helper()
	d := "OU=" + name + ",OU=Managed," + winDom
	r := ldap.NewAddRequest(d, nil)
	r.Attribute("objectClass", []string{"top", "organizationalUnit"})
	if err := l.adm.Add(r); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = l.adm.Del(&ldap.DelRequest{DN: d, Controls: []ldap.Control{ldap.NewControlString("1.2.840.113556.1.4.805", true, "")}})
	})
	return d
}

// T-1282 AC1 (CC-FEED-11 on Windows): the DC rejects the cookie; the handler answers STALE_COOKIE with
// SERVER_REJECTED before any batch, whichever result code the DC used (protocolError for a truncated
// cookie with 0000203D in the diagnostic; unavailableCriticalExtension for garbage).
func TestWindowsLabFeedRejectedCookieIsServerRejected(t *testing.T) {
	l := newWinFeedLab(t)
	f := l.open(t)
	ck := f.prime(t, "cn").GetCookieAfter()
	if len(ck.GetProviderState()) < 8 {
		t.Fatalf("provider_state too short to truncate: %d bytes", len(ck.GetProviderState()))
	}
	for name, state := range map[string][]byte{
		"truncated": ck.GetProviderState()[:len(ck.GetProviderState())/2],
		"garbage":   []byte("not a dirsync cookie at all"),
	} {
		c := proto.Clone(ck).(*connectorv1.FeedCookie)
		c.ProviderState = state
		bs, err := f.resume(c, "cn")
		if len(bs) != 0 {
			t.Errorf("%s: %d batches before the refusal", name, len(bs))
		}
		if got := staleReason(t, err); got != connectorv1.ResyncReason_RESYNC_REASON_SERVER_REJECTED {
			t.Errorf("%s: reason %v, want SERVER_REJECTED", name, got)
		}
	}
	// The honest cookie still resumes on the same DC (the refusals did not poison the connection).
	if bs, err := f.resume(ck, "cn"); err != nil || len(bs) == 0 || !bs[len(bs)-1].GetCycleComplete() {
		t.Errorf("honest resume after rejections: %v (%d batches)", err, len(bs))
	}
}

// T-1282 AC2 (CC-FEED-21): a resume that spans several DirSync responses. Every batch but the last has
// cycle_complete false, a cookie_after and the cycle's start as issued_at; the last (held until the DC was
// seen to be the same one) is complete with an issued_at at or after it. Resuming from a mid-cycle
// cookie_after delivers exactly the objects the earlier batches had not.
func TestWindowsLabFeedMidCycleCookiesAndHeldFinalBatch(t *testing.T) {
	l := newWinFeedLab(t)
	f := l.open(t)
	ou := l.ou(t, "t1282f"+time.Now().Format("150405"))
	ck := f.prime(t, "cn").GetCookieAfter()

	const n = 1500
	want := map[string]bool{}
	for i := 0; i < n; i++ {
		d := fmt.Sprintf("CN=c%04d,%s", i, ou)
		r := ldap.NewAddRequest(d, nil)
		r.Attribute("objectClass", []string{"top", "contact"})
		if err := l.adm.Add(r); err != nil {
			t.Fatal(err)
		}
		want[string(write.GUIDToWire(l.guidOf(t, d)).GetValue())] = true
	}

	before := time.Now()
	bs, err := f.resume(ck, "cn")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("T-1282 AC2: %d objects, %d batches", n, len(bs))
	if len(bs) < 2 {
		t.Fatalf("%d batch(es) for %d objects: no mid-cycle batch to test", len(bs), n)
	}
	for i, b := range bs {
		last := i == len(bs)-1
		if b.GetCycleComplete() != last {
			t.Errorf("batch %d: cycle_complete = %v, want %v", i, b.GetCycleComplete(), last)
		}
		if b.GetSequence() != uint64(i+1) {
			t.Errorf("batch %d: sequence %d", i, b.GetSequence())
		}
		if b.GetCookieAfter() == nil || len(b.GetCookieAfter().GetProviderState()) == 0 {
			t.Errorf("batch %d: no usable cookie_after", i)
		}
		if i > 0 && !last && !b.GetCookieAfter().GetIssuedAt().AsTime().Equal(bs[0].GetCookieAfter().GetIssuedAt().AsTime()) {
			t.Errorf("batch %d: mid-cycle issued_at differs from batch 0 (must be the cycle start)", i)
		}
	}
	first, finalAt := bs[0].GetCookieAfter().GetIssuedAt().AsTime(), bs[len(bs)-1].GetCookieAfter().GetIssuedAt().AsTime()
	if first.Before(before.Add(-time.Minute)) || finalAt.Before(first) {
		t.Errorf("issued_at: first %v, final %v, test started %v", first, finalAt, before)
	}
	got := changes(bs)
	for g := range want {
		if got[g] == nil {
			t.Errorf("object %x missing from the cycle", g)
			break
		}
	}

	// Resume from the first batch's cookie_after (mid-cycle): the remainder, exactly.
	rest, err := f.resume(bs[0].GetCookieAfter(), "cn")
	if err != nil {
		t.Fatal(err)
	}
	seen, remainder := changes(bs[:1]), changes(rest)
	union := map[string]bool{}
	for g := range seen {
		union[g] = true
	}
	for g := range remainder {
		if seen[g] != nil {
			t.Errorf("object %x delivered by batch 0 and again after its cookie", g)
		}
		union[g] = true
	}
	for g := range want {
		if !union[g] {
			t.Errorf("object %x lost across the mid-cycle resume", g)
			break
		}
	}
	t.Logf("T-1282 AC2: batch 0 = %d changes, resume after it = %d changes", len(seen), len(remainder))
}
