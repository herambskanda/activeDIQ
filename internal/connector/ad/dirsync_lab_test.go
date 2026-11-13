//go:build lab

package ad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

// DirSync primitive on the Samba lab (T-1193; CC-FEED-02..05, 14, 15, 23, 25).
//
// Two identities are used on purpose. The connector identity (svc-activediq, a plain user) sees every
// live change but NOT the tombstones of deleted objects on Samba, which is the KB 892806 behaviour
// the contract warns about (§6.5 item 1, CC-FEED-20): tests that need a DELETED change bind as the
// lab Administrator, and one test records the non-administrator answer.

func labNC(t *testing.T) dn.ObjectRef {
	t.Helper()
	d, err := dn.Parse(labBase, dn.Strict)
	if err != nil {
		t.Fatal(err)
	}
	return dn.DNRef(d)
}

// dirSyncLabSchema adds the attributes these tests ask the feed for to the built-in allowlist.
func dirSyncLabSchema() *ldapfilter.Schema {
	return DefaultSchema().With(
		ldapfilter.AttrInfo{Name: "pwdLastSet", OID: "1.2.840.113556.1.4.96", Syntax: ldapfilter.SynInt64},
	)
}

// feedSession opens a session for the feed. admin selects the lab Administrator (sees tombstones).
func feedSession(t *testing.T, cfg Config, admin bool) *Session {
	t.Helper()
	cfg.Schema = dirSyncLabSchema()
	if admin {
		cfg.Credential = Credential{BindName: "Administrator@lab.activediq.test", Password: secret.FromBytes([]byte(labEnv(t)["LAB_ADMIN_PASSWORD"]))}
	}
	return labOpen(t, cfg)
}

// feedCycle runs one DirSync cycle from cookie and returns every change and the final page.
func feedCycle(t *testing.T, s *Session, cookie []byte, attrs ...string) ([]ObjectChange, DirSyncPage) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var all []ObjectChange
	last, err := s.DirSyncCycle(ctx, DirSyncRequest{NC: labNC(t), Cookie: cookie, Attributes: attrs}, func(p DirSyncPage) error {
		all = append(all, p.Changes...)
		return nil
	})
	if err != nil {
		t.Fatalf("dirsync: %v", err)
	}
	return all, last
}

func changeOf(cs []ObjectChange, g guid.GUID) (ObjectChange, bool) {
	var out ObjectChange
	found := false
	for _, c := range cs {
		if c.GUID == g {
			out, found = c, true
		}
	}
	return out, found
}

func attrOf(c ObjectChange, name string, op ChangeOp) (AttributeChange, bool) {
	for _, a := range c.Attributes {
		if strings.EqualFold(a.Name, name) && a.Op == op {
			return a, true
		}
	}
	return AttributeChange{}, false
}

// refInventory is the harness's reference applier: an idempotent upsert by GUID that is independent of
// the order changes arrive in (CC-FEED-16 shape).
type refObj struct {
	state   ChangeState
	dn      string
	display string
	members map[string]struct{}
}
type refInventory map[guid.GUID]*refObj

func (inv refInventory) apply(cs []ObjectChange) {
	for _, c := range cs {
		o := inv[c.GUID]
		if o == nil {
			o = &refObj{members: map[string]struct{}{}}
			inv[c.GUID] = o
		}
		o.state, o.dn = c.State, c.DN
		for _, a := range c.Attributes {
			switch strings.ToLower(a.Name) {
			case "displayname":
				if a.Op == OpSet {
					o.display = string(a.Values[0])
				} else if a.Op == OpCleared {
					o.display = ""
				}
			case "member":
				for _, v := range a.Values {
					k := strings.ToLower(string(v))
					if a.Op == OpValuesAdded || a.Op == OpSet {
						o.members[k] = struct{}{}
					} else if a.Op == OpValuesRemoved {
						delete(o.members, k)
					}
				}
			}
		}
	}
}

// adminState reads the truth about one object, live or deleted, as the lab Administrator.
func adminState(t *testing.T, adm *ldap.Conn, g guid.GUID) (dnStr string, display string, deleted bool, found bool) {
	t.Helper()
	req := ldap.NewSearchRequest(g.ObjectRef(), ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)",
		[]string{"displayName", "isDeleted"}, []ldap.Control{ldap.NewControlString(ldap.ControlTypeMicrosoftShowDeleted, true, "")})
	res, err := adm.Search(req)
	if err != nil || len(res.Entries) != 1 {
		return "", "", false, false
	}
	e := res.Entries[0]
	return e.DN, e.GetAttributeValue("displayName"), strings.EqualFold(e.GetAttributeValue("isDeleted"), "TRUE"), true
}

func eqDN(a, b string) bool { return strings.EqualFold(a, b) }

func newOU(t *testing.T, adm *ldap.Conn, name string) string {
	t.Helper()
	d := "OU=" + name + "," + labBase
	adminAdd(t, adm, d, map[string][]string{"objectClass": {"top", "organizationalUnit"}})
	t.Cleanup(func() { _ = adm.Del(ldap.NewDelRequest(d, nil)) })
	return d
}

func modifyReplace(t *testing.T, adm *ldap.Conn, d, attr, val string) {
	t.Helper()
	m := ldap.NewModifyRequest(d, nil)
	m.Replace(attr, []string{val})
	if err := adm.Modify(m); err != nil {
		t.Fatalf("modify %s: %v", d, err)
	}
}

// CC-FEED-02 and CC-FEED-03: create, modify, rename, move and delete a user (commas, a plus and
// Unicode in the CN) after a prime; the changes arrive LIVE then DELETED with the tombstone DN and
// GUID, applying them reproduces the directory, and the same cookie resumed twice gives the same changes.
func TestLabDirSyncLifecycle(t *testing.T) {
	adm, cfg := labAdmin(t)
	s := feedSession(t, cfg, true)
	stamp := time.Now().Format("150405.000")
	ou1 := newOU(t, adm, "t1193a"+stamp)
	ou2 := newOU(t, adm, "t1193b"+stamp)
	ou1g, ou2g := adminGUID(t, adm, ou1), adminGUID(t, adm, ou2)

	// Prime: the first cycle drains the domain and returns a cookie and no object data to the caller.
	_, prime := feedCycle(t, s, nil, "displayName")
	if len(prime.Cookie) == 0 || prime.More {
		t.Fatalf("prime page: cookie %d bytes, more=%v", len(prime.Cookie), prime.More)
	}

	u := "CN=Müller\\, Jörg\\+x," + ou1
	adminAdd(t, adm, u, userAttrs("t1193u"+strings.ReplaceAll(stamp, ".", "")))
	ug := adminGUID(t, adm, u)
	inv := refInventory{}
	step := func(label string, cookie []byte, want ChangeState, wantParent *guid.GUID) ([]byte, ObjectChange) {
		cs, last := feedCycle(t, s, cookie, "displayName")
		c, ok := changeOf(cs, ug)
		if !ok {
			t.Fatalf("%s: the user is not in the feed (%d changes)", label, len(cs))
		}
		if c.State != want {
			t.Errorf("%s: state %d, want %d", label, c.State, want)
		}
		if wantParent != nil && (!c.HasParent || c.Parent != *wantParent) {
			t.Errorf("%s: parent %v/%v, want %v", label, c.HasParent, c.Parent, *wantParent)
		}
		inv.apply(cs)
		return last.Cookie, c
	}
	check := func(label string) {
		dnStr, display, deleted, found := adminState(t, adm, ug)
		o := inv[ug]
		if !found || o == nil || !eqDN(o.dn, dnStr) || o.display != display || (o.state != StateLive) != deleted {
			t.Errorf("%s: inventory %+v does not match the directory (%q %q deleted=%v found=%v)", label, o, dnStr, display, deleted, found)
		}
	}

	c1, c := step("create", prime.Cookie, StateLive, &ou1g)
	if !eqDN(c.DN, u) {
		t.Errorf("create: DN %q, want %q", c.DN, u)
	}
	check("create")
	modifyReplace(t, adm, u, "displayName", "Jörg Müller")
	c2, _ := step("modify", c1, StateLive, nil)
	check("modify")
	if err := adm.ModifyDN(ldap.NewModifyDNRequest(u, "CN=Renamed "+stamp, true, "")); err != nil {
		t.Fatal(err)
	}
	u = "CN=Renamed " + stamp + "," + ou1
	c3, _ := step("rename", c2, StateLive, &ou1g)
	check("rename")
	if err := adm.ModifyDN(ldap.NewModifyDNRequest(u, "CN=Renamed "+stamp, true, ou2)); err != nil {
		t.Fatal(err)
	}
	u = "CN=Renamed " + stamp + "," + ou2
	c4, _ := step("move", c3, StateLive, &ou2g)
	check("move")
	if err := adm.Del(ldap.NewDelRequest(u, nil)); err != nil {
		t.Fatal(err)
	}
	// Samba (Recycle Bin off) writes isDeleted=TRUE and isRecycled=TRUE on every tombstone, so a delete
	// arrives as RECYCLED: never restorable. The restorable DELETED branch is covered by unit fixtures.
	c5, del := step("delete", c4, StateRecycled, nil)
	if !strings.Contains(del.DN, "CN=Deleted Objects") || !strings.Contains(strings.ToLower(del.DN), strings.ToLower(ug.String())) {
		t.Errorf("tombstone DN %q lacks the Deleted Objects container or the GUID", del.DN)
	}
	if del.GUID != ug {
		t.Errorf("tombstone GUID %v, want %v", del.GUID, ug)
	}
	check("delete")

	// Nothing changed: an empty cycle with a cookie (CC-FEED-03).
	quiet, qlast := feedCycle(t, s, c5)
	if _, ok := changeOf(quiet, ug); ok || len(qlast.Cookie) == 0 || qlast.More {
		t.Errorf("quiet cycle: %d changes, cookie %d bytes", len(quiet), len(qlast.Cookie))
	}

	// All of it in one resume from the prime: the changes collapse to the final state.
	all, _ := feedCycle(t, s, prime.Cookie, "displayName")
	collapsed, ok := changeOf(all, ug)
	if !ok || collapsed.State != StateRecycled || !strings.Contains(collapsed.DN, "CN=Deleted Objects") {
		t.Errorf("collapsed: %+v ok=%v", collapsed, ok)
	}

	// Replay-safe: the same cookie resumed twice gives the same changes.
	a, _ := feedCycle(t, s, prime.Cookie, "displayName")
	b, _ := feedCycle(t, s, prime.Cookie, "displayName")
	sortByGUID(a)
	sortByGUID(b)
	if !reflect.DeepEqual(a, b) || len(a) == 0 {
		t.Errorf("replay differs: %d vs %d changes", len(a), len(b))
	}
}

func sortByGUID(cs []ObjectChange) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].GUID.String() < cs[j].GUID.String() })
}

// CC-FEED-20 (recorded observation): the plain connector identity does not see a tombstone on Samba.
// The contract keeps FEED_DELETIONS UNVERIFIED and makes the reconcile pass mandatory because of this.
func TestLabDirSyncNonAdminDoesNotSeeTombstones(t *testing.T) {
	adm, cfg := labAdmin(t)
	s := feedSession(t, cfg, false)
	ou := newOU(t, adm, "t1193n"+time.Now().Format("150405.000"))
	_, prime := feedCycle(t, s, nil)
	u := "CN=gone," + ou
	adminAdd(t, adm, u, userAttrs("t1193g"+time.Now().Format("150405")))
	ug := adminGUID(t, adm, u)
	cs, c1 := feedCycle(t, s, prime.Cookie)
	if c, ok := changeOf(cs, ug); !ok || c.State != StateLive {
		t.Fatalf("create not seen live by the connector identity: %+v %v", c, ok)
	}
	if err := adm.Del(ldap.NewDelRequest(u, nil)); err != nil {
		t.Fatal(err)
	}
	cs, _ = feedCycle(t, s, c1.Cookie)
	c, ok := changeOf(cs, ug)
	t.Logf("CC-FEED-20 (Samba): non-administrator sees the tombstone = %v", ok)
	if ok && c.State == StateLive {
		t.Errorf("a delete arrived with state %d", c.State)
	}
}

// CC-FEED-04: one member added to and removed from a 3,000-member group arrives as one VALUES_ADDED and
// one VALUES_REMOVED of that single value, never a 3,000-value SET.
func TestLabDirSyncIncrementalMember(t *testing.T) {
	adm, cfg := labAdmin(t)
	s := feedSession(t, cfg, false)
	big := findOne(t, s, "sAMAccountName", "GG-Big")
	bigG, _ := big.GUID()
	bigDN := big.DN
	ou := newOU(t, adm, "t1193m"+time.Now().Format("150405.000"))
	u := "CN=member1," + ou
	adminAdd(t, adm, u, userAttrs("t1193m"+time.Now().Format("150405")))

	_, prime := feedCycle(t, s, nil, "member")
	m := ldap.NewModifyRequest(bigDN, nil)
	m.Add("member", []string{u})
	if err := adm.Modify(m); err != nil {
		t.Fatal(err)
	}
	cs, c1 := feedCycle(t, s, prime.Cookie, "member")
	c, ok := changeOf(cs, bigG)
	if !ok {
		t.Fatal("GG-Big not in the feed after a member was added")
	}
	for _, a := range c.Attributes {
		if strings.EqualFold(a.Name, "member") {
			t.Logf("add: member op=%d values=%d", a.Op, len(a.Values))
		}
		if strings.EqualFold(a.Name, "member") && a.Op == OpSet {
			t.Errorf("member arrived as a %d-value SET", len(a.Values))
		}
	}
	add, ok := attrOf(c, "member", OpValuesAdded)
	if !ok || len(add.Values) != 1 || !eqDN(string(add.Values[0]), u) {
		t.Fatalf("VALUES_ADDED: %+v ok=%v", add, ok)
	}

	m = ldap.NewModifyRequest(bigDN, nil)
	m.Delete("member", []string{u})
	if err := adm.Modify(m); err != nil {
		t.Fatal(err)
	}
	cs, _ = feedCycle(t, s, c1.Cookie, "member")
	c, ok = changeOf(cs, bigG)
	if !ok {
		t.Fatal("GG-Big not in the feed after a member was removed")
	}
	if _, set := attrOf(c, "member", OpSet); set {
		t.Error("removal arrived as a SET")
	}
	rem, ok := attrOf(c, "member", OpValuesRemoved)
	if !ok || len(rem.Values) != 1 || !eqDN(string(rem.Values[0]), u) {
		t.Fatalf("VALUES_REMOVED: %+v ok=%v (attrs %+v)", rem, ok, c.Attributes)
	}
}

// CC-FEED-05 and CC-FEED-25: a password reset after a prime changes pwdLastSet and no secret attribute
// appears in any change; naming a secret fails the call before the DC sees any request.
func TestLabDirSyncPasswordResetAndNamedSecrets(t *testing.T) {
	adm, cfg := labAdmin(t)
	px := startCaptureProxy(t, cfg)
	pcfg := cfg
	pcfg.Servers, pcfg.RootCAs, pcfg.ServerName = []string{px.Addr()}, px.pool, ""
	s := feedSession(t, pcfg, false)

	ou := newOU(t, adm, "t1193p"+time.Now().Format("150405.000"))
	u := "CN=pwuser," + ou
	adminAdd(t, adm, u, userAttrs("t1193p"+time.Now().Format("150405")))
	ug := adminGUID(t, adm, u)
	modifyReplace(t, adm, u, "unicodePwd", string(encodeUnicodePwd("Zq9!x7Lm#2vPw")))
	_, prime := feedCycle(t, s, nil, "pwdLastSet", "displayName")

	// Reset after the prime.
	modifyReplace(t, adm, u, "unicodePwd", string(encodeUnicodePwd("Hh4#kP8wQ!zr1")))
	cs, _ := feedCycle(t, s, prime.Cookie, "pwdLastSet", "displayName")
	c, ok := changeOf(cs, ug)
	if !ok {
		t.Fatal("the user is not in the feed after a password reset")
	}
	if a, ok := attrOf(c, "pwdLastSet", OpSet); !ok || len(a.Values) != 1 {
		t.Errorf("pwdLastSet did not change: %+v", c.Attributes)
	}
	for _, ch := range cs {
		for _, a := range ch.Attributes {
			if s.schema.IsSecret(a.Name) {
				t.Errorf("secret attribute %q reached a change", a.Name)
			}
		}
	}
	_, dropPage := feedCycle(t, s, prime.Cookie, "pwdLastSet")
	t.Logf("secret_attributes_dropped on the reset cycle (Samba does not send unrequested secrets): %d", dropPage.SecretAttributesDropped)

	// Named secrets: unicodePwd, the lab's 0x200-only attribute and a LAPS attribute.
	for _, name := range []string{"unicodePwd", "activediqLabConfidential", "ms-Mcs-AdmPwd"} {
		n := px.searchCount()
		_, err := s.DirSync(context.Background(), DirSyncRequest{NC: labNC(t), Cookie: prime.Cookie, Attributes: []string{"displayName", name}})
		if CodeOf(err) != CodeSecretAttribute {
			t.Errorf("%s: %v, want SECRET_ATTRIBUTE", name, err)
		}
		if _, err := s.DirSyncCycle(context.Background(), DirSyncRequest{NC: labNC(t), Cookie: prime.Cookie, Attributes: []string{name}}, nil); CodeOf(err) != CodeSecretAttribute {
			t.Errorf("cycle %s: %v", name, err)
		}
		if got := px.searchCount(); got != n {
			t.Errorf("%s: %d requests reached the DC before the refusal", name, got-n)
		}
	}
	// The same request without the secret succeeds.
	if _, err := s.DirSync(context.Background(), DirSyncRequest{NC: labNC(t), Cookie: prime.Cookie, Attributes: []string{"displayName"}}); err != nil {
		t.Errorf("clean request: %v", err)
	}
}

// CC-FEED-14 (cut-off stream) as a property over random operation sequences: the union of an
// interrupted run (a batch applied, the stream cut, resumed from the last committed cookie) equals an
// uninterrupted run, and both equal the directory. Samba never sets MoreResults, so a cycle is one
// batch here; mid-cycle cookies are CC-FEED-21 on Windows.
func TestLabDirSyncCutOffPropertyAndParentRename(t *testing.T) {
	adm, cfg := labAdmin(t)
	s := feedSession(t, cfg, true)
	for seed := int64(1); seed <= 3; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			stamp := time.Now().Format("150405.000")
			ou := newOU(t, adm, fmt.Sprintf("t1193c%d%s", seed, stamp))
			type user struct {
				dn   string
				g    guid.GUID
				live bool
			}
			var users []*user
			mutate := func(n int) {
				for i := 0; i < n; i++ {
					switch op := rng.Intn(4); {
					case op == 0 || len(users) == 0:
						d := fmt.Sprintf("CN=u%d-%d,%s", seed, len(users), ou)
						adminAdd(t, adm, d, userAttrs(fmt.Sprintf("t1193c%d_%d_%s", seed, len(users), strings.ReplaceAll(stamp, ".", ""))))
						users = append(users, &user{dn: d, g: adminGUID(t, adm, d), live: true})
					default:
						u := users[rng.Intn(len(users))]
						if !u.live {
							continue
						}
						if op == 3 {
							if err := adm.Del(ldap.NewDelRequest(u.dn, nil)); err != nil {
								t.Fatal(err)
							}
							u.live = false
						} else {
							modifyReplace(t, adm, u.dn, "displayName", fmt.Sprintf("dn-%d", rng.Int()))
						}
					}
				}
			}
			_, prime := feedCycle(t, s, nil, "displayName")
			mutate(3 + rng.Intn(4))
			// Run 1: one batch is delivered and committed ...
			interrupted := refInventory{}
			first, committed := feedCycle(t, s, prime.Cookie, "displayName")
			interrupted.apply(first)
			// ... then a stream is cut off before it completes: the callback fails after the page.
			cut := errors.New("cut off")
			mutate(2 + rng.Intn(4))
			if _, err := s.DirSyncCycle(context.Background(), DirSyncRequest{NC: labNC(t), Cookie: committed.Cookie, Attributes: []string{"displayName"}},
				func(DirSyncPage) error { return cut }); !errors.Is(err, cut) {
				t.Fatalf("cut-off error not propagated: %v", err)
			}
			// Resume from the last COMMITTED cookie (the cut-off page was never committed).
			rest, _ := feedCycle(t, s, committed.Cookie, "displayName")
			interrupted.apply(rest)

			uninterrupted := refInventory{}
			all, _ := feedCycle(t, s, prime.Cookie, "displayName")
			uninterrupted.apply(all)

			for _, u := range users {
				a, b := interrupted[u.g], uninterrupted[u.g]
				if a == nil || b == nil || a.state != b.state || a.display != b.display || !eqDN(a.dn, b.dn) {
					t.Errorf("%s: interrupted %+v != uninterrupted %+v", u.dn, a, b)
					continue
				}
				dnStr, display, deleted, found := adminState(t, adm, u.g)
				if !found || deleted == u.live || (u.live && (!eqDN(dnStr, b.dn) || display != b.display)) {
					t.Errorf("%s: inventory %+v does not match the directory (%q %q deleted=%v)", u.dn, b, dnStr, display, deleted)
				}
			}
		})
	}

	// CC-FEED-15 / DM-19.I5: renaming a parent OU does not report its children; the reference applier
	// re-derives their DNs from the parent.
	t.Run("parent-rename", func(t *testing.T) {
		stamp := time.Now().Format("150405.000")
		ou := newOU(t, adm, "t1193r"+stamp)
		kid := "CN=kid," + ou
		adminAdd(t, adm, kid, userAttrs("t1193r"+strings.ReplaceAll(stamp, ".", "")))
		kidG, ouG := adminGUID(t, adm, kid), adminGUID(t, adm, ou)
		_, prime := feedCycle(t, s, nil, "displayName")
		if err := adm.ModifyDN(ldap.NewModifyDNRequest(ou, "OU=t1193r2"+stamp, true, "")); err != nil {
			t.Fatal(err)
		}
		newOUdn := "OU=t1193r2" + stamp + "," + labBase
		t.Cleanup(func() {
			_ = adm.Del(ldap.NewDelRequest("CN=kid,"+newOUdn, nil))
			_ = adm.Del(ldap.NewDelRequest(newOUdn, nil))
		})
		cs, _ := feedCycle(t, s, prime.Cookie, "displayName")
		p, ok := changeOf(cs, ouG)
		if !ok || !eqDN(p.DN, newOUdn) {
			t.Fatalf("renamed OU: %+v ok=%v", p, ok)
		}
		if _, ok := changeOf(cs, kidG); ok {
			t.Error("the child of a renamed OU was reported (DM-19.I5 says it is not)")
		}
		// Re-derive the child's DN from the parent's new DN, as the harness's reference applier does.
		derived := "CN=kid," + p.DN
		if actual, _, _, found := adminState(t, adm, kidG); !found || !eqDN(actual, derived) {
			t.Errorf("derived child DN %q != directory %q", derived, actual)
		}
	})
}

// ---- wire capture (CC-FEED-23) --------------------------------------------------------------------

type wireControl struct {
	oid      string
	critical bool
	value    []byte
}
type wireSearch struct {
	base     string
	scope    int64
	controls []wireControl
}

// captureProxy relays a session's LDAPS traffic to the lab and records every search request it sees.
type captureProxy struct {
	ln   net.Listener
	pool *x509.CertPool
	mu   sync.Mutex
	seen []wireSearch
}

func (p *captureProxy) Addr() string { return p.ln.Addr().String() }
func (p *captureProxy) searchCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.seen)
}
func (p *captureProxy) searches() []wireSearch {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]wireSearch(nil), p.seen...)
}

func startCaptureProxy(t *testing.T, cfg Config) *captureProxy {
	t.Helper()
	cert, pool := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	p := &captureProxy{ln: ln, pool: pool}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := tls.Dial("tcp", cfg.Servers[0], &tls.Config{RootCAs: cfg.RootCAs, ServerName: "localhost", MinVersion: tls.VersionTLS12})
				if err != nil {
					return
				}
				defer up.Close()
				go func() { // upstream -> client verbatim
					defer c.Close()
					buf := make([]byte, 32*1024)
					for {
						n, err := up.Read(buf)
						if n > 0 {
							if _, werr := c.Write(buf[:n]); werr != nil {
								return
							}
						}
						if err != nil {
							return
						}
					}
				}()
				for { // client -> upstream, recording searches
					pkt, err := ber.ReadPacket(c)
					if err != nil {
						return
					}
					if ws, ok := parseSearch(pkt); ok {
						p.mu.Lock()
						p.seen = append(p.seen, ws)
						p.mu.Unlock()
					}
					if _, err := up.Write(pkt.Bytes()); err != nil {
						return
					}
				}
			}()
		}
	}()
	return p
}

func parseSearch(pkt *ber.Packet) (wireSearch, bool) {
	if len(pkt.Children) < 2 {
		return wireSearch{}, false
	}
	body := pkt.Children[1]
	if body.ClassType != ber.ClassApplication || body.Tag != 3 || len(body.Children) < 2 {
		return wireSearch{}, false
	}
	ws := wireSearch{}
	ws.base, _ = body.Children[0].Value.(string)
	ws.scope, _ = body.Children[1].Value.(int64)
	if len(pkt.Children) > 2 && pkt.Children[2].ClassType == ber.ClassContext {
		for _, c := range pkt.Children[2].Children {
			wc := wireControl{}
			wc.oid, _ = c.Children[0].Value.(string)
			for _, f := range c.Children[1:] {
				switch v := f.Value.(type) {
				case bool:
					wc.critical = v
				default:
					wc.value = f.Data.Bytes()
				}
			}
			ws.controls = append(ws.controls, wc)
		}
	}
	return ws, true
}

// CC-FEED-23: the DirSync request on the wire carries exactly the DirSync control (critical, flags
// 0x1|0x80000000) and the show-deleted control (critical), is based at the NC root, and no other search
// the session sends carries either control.
func TestLabDirSyncOnTheWire(t *testing.T) {
	_, cfg := labAdmin(t)
	px := startCaptureProxy(t, cfg)
	pcfg := cfg
	pcfg.Servers, pcfg.RootCAs, pcfg.ServerName = []string{px.Addr()}, px.pool, ""
	s := feedSession(t, pcfg, false)
	_, last := feedCycle(t, s, nil, "displayName")
	feedCycle(t, s, last.Cookie, "displayName")

	const dirSyncOID, showDeletedOID = "1.2.840.113556.1.4.841", "1.2.840.113556.1.4.417"
	dirsyncs := 0
	for _, w := range px.searches() {
		has := map[string]wireControl{}
		for _, c := range w.controls {
			has[c.oid] = c
		}
		_, hasDS := has[dirSyncOID]
		_, hasSD := has[showDeletedOID]
		if !hasDS {
			if hasSD {
				t.Errorf("show-deleted sent without DirSync on base %q", w.base)
			}
			continue
		}
		dirsyncs++
		if len(w.controls) != 2 || !hasSD {
			t.Errorf("DirSync request controls = %d (%v), want exactly DirSync and show-deleted", len(w.controls), w.controls)
		}
		for _, c := range w.controls {
			if !c.critical {
				t.Errorf("control %s is not critical", c.oid)
			}
		}
		if !strings.EqualFold(w.base, labBase) || w.scope != 2 {
			t.Errorf("base %q scope %d, want the NC root, whole subtree", w.base, w.scope)
		}
		v, err := ber.DecodePacketErr(has[dirSyncOID].value)
		if err != nil || len(v.Children) != 3 {
			t.Fatalf("dirsync value: %v", err)
		}
		if got := v.Children[0].Data.Bytes(); len(got) != 4 || got[0] != 0x80 || got[1] != 0 || got[2] != 0 || got[3] != 0x01 {
			t.Errorf("flags % x, want 80 00 00 01", got)
		}
	}
	if dirsyncs != 2 {
		t.Errorf("%d DirSync requests captured, want 2", dirsyncs)
	}
}
