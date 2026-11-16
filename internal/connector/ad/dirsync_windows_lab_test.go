//go:build lab && windowslab

// T-1282: the ChangeFeed's DirSync behaviour that Samba cannot prove, against the Windows lab DC
// (dc1). Run through `lab/windows/bin/with-dc1-lock -- go test -tags 'lab windowslab' -run
// TestWindowsLabDirSync ./internal/connector/ad`. Writes go through the lab Administrator into a
// throwaway OU that every test deletes (subtree delete) when it finishes. Nothing here is skipped
// when the lab is missing.
package ad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad/scope"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

const winAdminBind = "Administrator@win.activediq.test"

// winDial opens a verified LDAPS connection to dc1 and binds who.
func winDial(t *testing.T, who, pw string) *ldap.Conn {
	t.Helper()
	host := os.Getenv("WIN_LAB_DC_ADDR")
	if host == "" {
		host = winEnv(t)["WIN_LAB_DC_ADDR"]
	}
	if host == "" {
		t.Fatal("WIN_LAB_DC_ADDR is not set (environment or lab env file)")
	}
	pem, err := os.ReadFile(labFile(os.Getenv("WIN_LAB_CA"), ".win-lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad windows lab CA")
	}
	c, err := ldap.DialURL("ldaps://"+host+":636", ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: winTLSName(), MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Bind(who, pw); err != nil {
		t.Fatalf("bind %s: %v", who, err)
	}
	return c
}

func winNC(t *testing.T) dn.ObjectRef {
	t.Helper()
	d, err := dn.Parse(winBase, dn.Strict)
	if err != nil {
		t.Fatal(err)
	}
	return dn.DNRef(d)
}

// winFeedSession opens the connector identity (svc-activediq, not an administrator) for the feed.
func winFeedSession(t *testing.T) *Session {
	t.Helper()
	cfg := winConfig(t, winEnv(t)["WIN_LAB_SVC_PASSWORD"], true)
	cfg.Schema = dirSyncLabSchema()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// winTestOU creates OU=<name> under OU=Managed as the Administrator and removes the subtree at the end.
func winTestOU(t *testing.T, adm *ldap.Conn, name string) string {
	t.Helper()
	d := "OU=" + name + ",OU=Managed," + winBase
	r := ldap.NewAddRequest(d, nil)
	r.Attribute("objectClass", []string{"top", "organizationalUnit"})
	if err := adm.Add(r); err != nil {
		t.Fatalf("add %s: %v", d, err)
	}
	t.Cleanup(func() {
		tree := ldap.NewControlString("1.2.840.113556.1.4.805", true, "") // tree delete
		_ = adm.Del(&ldap.DelRequest{DN: d, Controls: []ldap.Control{tree}})
	})
	return d
}

func winAdminGUID(t *testing.T, adm *ldap.Conn, d string) guid.GUID {
	t.Helper()
	res, err := adm.Search(ldap.NewSearchRequest(d, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("guid of %s: %v", d, err)
	}
	g, err := guid.FromBytes(res.Entries[0].GetRawAttributeValue("objectGUID"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func winCycle(t *testing.T, s *Session, cookie []byte) (pages []DirSyncPage, last DirSyncPage) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	last, err := s.DirSyncCycle(ctx, DirSyncRequest{NC: winNC(t), Cookie: cookie}, func(p DirSyncPage) error {
		pages = append(pages, p)
		return nil
	})
	if err != nil {
		t.Fatalf("dirsync: %v", err)
	}
	return pages, last
}

// CC-FEED-11 (Windows half, T-1282 AC1): a cookie the DC rejects. The raw LDAP result code and the
// DC's diagnostic are recorded in the log; the connector classifies on the result code alone.
func TestWindowsLabDirSyncRejectedCookie(t *testing.T) {
	s := winFeedSession(t)
	_, prime := winCycle(t, s, nil)
	if len(prime.Cookie) == 0 {
		t.Fatal("prime gave no cookie")
	}
	bad := map[string][]byte{
		"truncated":       prime.Cookie[:len(prime.Cookie)/2],
		"garbage":         []byte("not-a-dirsync-cookie-0123456789"),
		"flipped-payload": flipTail(prime.Cookie),
	}
	names := make([]string, 0, len(bad))
	for k := range bad {
		names = append(names, k)
	}
	sort.Strings(names)

	svc := winDial(t, winBind, winEnv(t)["WIN_LAB_SVC_PASSWORD"])
	for _, name := range names {
		cookie := bad[name]
		// Raw: what the DC itself answers (recorded, not asserted beyond "refused").
		_, rawErr := svc.Search(ldap.NewSearchRequest(winBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)", []string{"objectGUID"}, []ldap.Control{scope.DirSync(cookie), scope.ShowDeleted()}))
		var le *ldap.Error
		if rawErr == nil && name == "flipped-payload" {
			// Recorded: the DC does not validate the tail of a structurally intact cookie.
			t.Logf("T-1282 AC1 [%s]: the DC ACCEPTED a cookie with its last bytes flipped (no result code)", name)
			continue
		}
		if !errors.As(rawErr, &le) {
			t.Fatalf("%s: DC accepted a bad cookie or failed differently: %v", name, rawErr)
		}
		t.Logf("T-1282 AC1 [%s]: raw LDAP result code %d (%s); DC diagnostic: %q", name, le.ResultCode, ldap.LDAPResultCodeMap[le.ResultCode], le.Err)

		if le.ResultCode != ldap.LDAPResultProtocolError && le.ResultCode != resultUnavailableCriticalExtension {
			t.Errorf("%s: DC answered result %d, which cookieRejection would not classify", name, le.ResultCode)
		}
		if !cookieRejection(&Error{Code: CodeProtocol, result: int(le.ResultCode)}) {
			t.Errorf("%s: cookieRejection false for result %d", name, le.ResultCode)
		}

		// Through the primitive: classified on the result code.
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_, err := s.DirSync(ctx, DirSyncRequest{NC: winNC(t), Cookie: cookie})
		cancel()
		if CodeOf(err) != CodeCookieRejected {
			t.Errorf("%s: DirSync code = %q (%v), want %q", name, CodeOf(err), err, CodeCookieRejected)
		}
		if err != nil && strings.Contains(err.Error(), string(cookie)) {
			t.Errorf("%s: error text echoes the cookie", name)
		}
	}
}

func flipTail(b []byte) []byte {
	out := append([]byte(nil), b...)
	for i := len(out) - 1; i >= 0 && i >= len(out)-8; i-- {
		out[i] ^= 0xFF
	}
	return out
}

// CC-FEED-21 (T-1282 AC2): a cycle with MoreResults. 1,500 objects exceed the DC's per-response
// object maximum, so the cycle spans several responses; resuming from each mid-cycle cookie must
// yield exactly the objects the earlier responses had not delivered.
func TestWindowsLabDirSyncMidCycleCookies(t *testing.T) {
	adm := winDial(t, winAdminBind, winEnv(t)["WIN_LAB_ADMIN_PASSWORD"])
	s := winFeedSession(t)
	ou := winTestOU(t, adm, "t1282m"+time.Now().Format("150405"))
	_, prime := winCycle(t, s, nil)

	const n = 1500
	want := map[guid.GUID]bool{}
	for i := 0; i < n; i++ {
		d := fmt.Sprintf("CN=c%04d,%s", i, ou)
		r := ldap.NewAddRequest(d, nil)
		r.Attribute("objectClass", []string{"top", "contact"})
		if err := adm.Add(r); err != nil {
			t.Fatalf("add %s: %v", d, err)
		}
		want[winAdminGUID(t, adm, d)] = true
	}

	pages, last := winCycle(t, s, prime.Cookie)
	t.Logf("T-1282 AC2: %d objects created, cycle = %d responses; MoreResults per response: %v", n, len(pages), moreFlags(pages))
	if len(pages) < 2 {
		t.Fatalf("a %d-object cycle came back in %d response(s): MoreResults never set, mid-cycle cookies cannot be tested", n, len(pages))
	}
	for i, p := range pages {
		if wantMore := i < len(pages)-1; p.More != wantMore {
			t.Errorf("response %d: More = %v, want %v", i, p.More, wantMore)
		}
		if len(p.Cookie) == 0 {
			t.Errorf("response %d carries no cookie", i)
		}
	}
	if !equalSets(want, guidsOf(pages, want, 0, len(pages))) {
		t.Errorf("the full cycle did not deliver exactly the created objects")
	}

	// Resume from every mid-cycle cookie: earlier responses + resumed cycle == the whole set, and the
	// resumed cycle never repeats an object the earlier responses delivered.
	for i := 0; i < len(pages)-1; i++ {
		rest, _ := winCycle(t, s, pages[i].Cookie)
		before := guidsOf(pages, want, 0, i+1)
		after := guidsOf(rest, want, 0, len(rest))
		for g := range after {
			if before[g] {
				t.Errorf("cookie after response %d: %s delivered twice", i, g)
			}
		}
		union := map[guid.GUID]bool{}
		for g := range before {
			union[g] = true
		}
		for g := range after {
			union[g] = true
		}
		if !equalSets(want, union) {
			t.Errorf("cookie after response %d: %d of %d objects after resuming", i, len(union), len(want))
		}
		t.Logf("T-1282 AC2: resume after response %d: %d delivered before, %d after", i, len(before), len(after))
	}

	// The final cookie of the cycle is empty-handed: nothing more to deliver (the held final batch is safe to emit last).
	again, _ := winCycle(t, s, last.Cookie)
	for _, p := range again {
		if got := guidsOf([]DirSyncPage{p}, want, 0, 1); len(got) != 0 {
			t.Errorf("final cookie re-delivered %d created objects", len(got))
		}
	}
}

func moreFlags(ps []DirSyncPage) []bool {
	out := make([]bool, len(ps))
	for i, p := range ps {
		out[i] = p.More
	}
	return out
}

// guidsOf is the set of wanted GUIDs in pages[from:to].
func guidsOf(pages []DirSyncPage, want map[guid.GUID]bool, from, to int) map[guid.GUID]bool {
	out := map[guid.GUID]bool{}
	for _, p := range pages[from:to] {
		for _, c := range p.Changes {
			if want[c.GUID] {
				out[c.GUID] = true
			}
		}
	}
	return out
}

func equalSets(a, b map[guid.GUID]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// recycleBinOn reports whether the Recycle Bin optional feature is enabled in the forest.
func recycleBinOn(t *testing.T, adm *ldap.Conn) bool {
	t.Helper()
	res, err := adm.Search(ldap.NewSearchRequest("CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,"+winBase,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"msDS-EnabledFeatureBL"}, nil))
	return err == nil && len(res.Entries) == 1 && len(res.Entries[0].GetAttributeValues("msDS-EnabledFeatureBL")) > 0
}

// CC-FEED-20 and T-1270 (T-1282 AC3), recorded observations: does the connector identity (svc-activediq,
// not an administrator) see a tombstone after a prime, and does the feed show DELETED (Recycle Bin: isDeleted
// only) or RECYCLED (isRecycled) for a freshly deleted object? The test pins what the connector depends on:
// a delete is never reported as LIVE. What the DC does is logged for the contract.
func TestWindowsLabDirSyncNonAdminTombstone(t *testing.T) {
	adm := winDial(t, winAdminBind, winEnv(t)["WIN_LAB_ADMIN_PASSWORD"])
	s := winFeedSession(t)
	ou := winTestOU(t, adm, "t1282t"+time.Now().Format("150405"))
	rb := recycleBinOn(t, adm)
	t.Logf("T-1282 AC3: Recycle Bin enabled = %v", rb)

	_, prime := winCycle(t, s, nil)
	u := "CN=gone," + ou
	r := ldap.NewAddRequest(u, nil)
	r.Attribute("objectClass", []string{"top", "contact"})
	if err := adm.Add(r); err != nil {
		t.Fatal(err)
	}
	g := winAdminGUID(t, adm, u)
	pages, c1 := winCycle(t, s, prime.Cookie)
	if c, ok := findChange(pages, g); !ok || c.State != StateLive {
		t.Fatalf("create not seen live by the connector identity: %+v %v", c, ok)
	}
	if err := adm.Del(ldap.NewDelRequest(u, nil)); err != nil {
		t.Fatal(err)
	}
	pages, _ = winCycle(t, s, c1.Cookie)
	c, ok := findChange(pages, g)
	if !ok {
		t.Logf("T-1282 AC3 RESULT: the non-administrator connector identity does NOT see the tombstone of a deleted object (only the reconcile can find it)")
		return
	}
	names := map[ChangeState]string{StateLive: "LIVE", StateDeleted: "DELETED", StateRecycled: "RECYCLED"}
	t.Logf("T-1282 AC3 RESULT: the non-administrator connector identity SEES the tombstone; state = %s; DN = %s", names[c.State], c.DN)
	if c.State == StateLive {
		t.Errorf("a delete arrived as LIVE")
	}
	if rb && c.State != StateDeleted {
		t.Errorf("Recycle Bin on: a just-deleted object must be DELETED (isDeleted only), got %s", names[c.State])
	}
	if !rb && c.State != StateRecycled {
		t.Errorf("Recycle Bin off: a tombstone must be RECYCLED, got %s", names[c.State])
	}
}

func findChange(pages []DirSyncPage, g guid.GUID) (ObjectChange, bool) {
	for _, p := range pages {
		for _, c := range p.Changes {
			if c.GUID == g {
				return c, true
			}
		}
	}
	return ObjectChange{}, false
}
