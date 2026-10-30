//go:build lab

package ad

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
)

// LF-32 / CC-SRCH-10 against the real Samba lab through the fault proxy (T-0309): real entries come
// from the DC, the proxy plants the continuation reference after the first one. FAILURE INJECTION:
// the reference is the proxy's, because Samba cannot create referral objects.
func TestLabReferralMidStreamViaFaultProxy(t *testing.T) {
	adm, cfg := labAdmin(t)
	stamp := time.Now().Format("150405")
	ou := "OU=t0309" + stamp + "," + labBase
	adminAdd(t, adm, ou, map[string][]string{"objectClass": {"top", "organizationalUnit"}})
	users := []string{"CN=r1," + ou, "CN=r2," + ou, "CN=r3," + ou}
	for i, u := range users {
		adminAdd(t, adm, u, userAttrs("t0309u"+stamp+strconv.Itoa(i)))
	}
	t.Cleanup(func() {
		for i := len(users) - 1; i >= 0; i-- {
			_ = adm.Del(ldap.NewDelRequest(users[i], nil))
		}
		_ = adm.Del(ldap.NewDelRequest(ou, nil))
	})
	root := adminGUID(t, adm, ou)

	upstream := func() (net.Conn, error) {
		return tls.Dial("tcp", cfg.Servers[0], &tls.Config{RootCAs: cfg.RootCAs, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	}
	trap := startHoneypot(t)
	p, pool := startFaultProxy(t, upstream, injectPlan{afterEntries: 1, urls: []string{"ldaps://" + trap.ln.Addr().String() + "/DC=other"}})
	pcfg := cfg
	pcfg.Servers, pcfg.RootCAs, pcfg.ServerName = []string{p.Addr()}, pool, ""
	s := labOpen(t, pcfg)

	cls, _ := ldapfilter.ParseAttrName("objectClass", s.schema)
	req := ScopedRequest{Roots: nil, Depth: ScopeSubtree, Filter: ldapfilter.Eq(cls, ldapfilter.String("user")), Attributes: []string{"distinguishedName"}}
	req.Roots = scopedReq(t, s, root).Roots
	res, err := s.ScopedSearch(context.Background(), req, func(*Entry) error { return nil })
	if CodeOf(err) != CodeUnexpectedReferral || p.Injected() != 1 || res.RootsCompleted != 0 {
		t.Fatalf("err=%v injected=%d res=%+v", err, p.Injected(), res)
	}
	if trap.Hits() != 0 {
		t.Errorf("referral followed: %d", trap.Hits())
	}
}
