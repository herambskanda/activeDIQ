//go:build lab

package read_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1194 on Samba: `make lab-up && go test -tags lab ./internal/connector/read -run TestLabFeed`.
// CC-FEED-01, 07..13, 17, 18 through the real handler, a real Session and the Samba lab.
//
// Two identities, as in the DirSync primitive's tests: svc-activediq sees live changes but NOT the
// tombstones on Samba (KB 892806 behaviour, CC-FEED-20), so the lifecycle test binds as the lab
// Administrator. FAILURE INJECTION: the relay below rewrites DirSync responses (a DC that never
// finishes) and is closed to take the DC away; Samba cannot do either.

type feedLab struct {
	env  map[string]string
	pool *x509.CertPool
	adm  *ldap.Conn
}

func newFeedLab(t *testing.T) *feedLab {
	t.Helper()
	env := labEnv(t)
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	adm, err := ldap.DialURL("ldaps://localhost:"+env["LAB_LDAPS_PORT"], ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "localhost"}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adm.Close() })
	if err := adm.Bind("Administrator@lab.activediq.test", env["LAB_ADMIN_PASSWORD"]); err != nil {
		t.Fatal(err)
	}
	return &feedLab{env: env, pool: pool, adm: adm}
}

func (l *feedLab) guidOf(t *testing.T, dn string) guid.GUID {
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

// feed is one connector over one Session: the client of the in-process gRPC hop, the source and the
// provider (for the DC identity the tests compare with).
type feed struct {
	c    connectorv1.ConnectorClient
	src  *read.ADSource
	prov *write.ADProvider
	nc   *connectorv1.Guid
}

// open binds a session (admin or the service account; servers/pool override the address for the
// relay) and serves the read group over it.
func (l *feedLab) open(t *testing.T, admin bool, servers string, pool *x509.CertPool, opts ...read.Option) *feed {
	t.Helper()
	cred := ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(l.env["LAB_SVC_PASSWORD"]))}
	if admin {
		cred = ad.Credential{BindName: "Administrator@lab.activediq.test", Password: secret.FromBytes([]byte(l.env["LAB_ADMIN_PASSWORD"]))}
	}
	cfg := ad.Config{Servers: []string{"localhost:" + l.env["LAB_LDAPS_PORT"]}, RootCAs: l.pool, PageSize: 500, Credential: cred,
		Schema: ad.DefaultSchema()}
	if servers != "" {
		cfg.Servers, cfg.RootCAs = []string{servers}, pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sess, err := ad.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	nc := l.guidOf(t, labDom)
	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: write.GUIDToWire(nc)}}}
	prov := write.NewADProvider(sess, nil, ident, &memPins{})
	src, err := read.NewADSource(sess, prov)
	if err != nil {
		t.Fatal(err)
	}
	return &feed{c: startFeed(t, src, opts...), src: src, prov: prov, nc: write.GUIDToWire(nc)}
}

func (f *feed) req(attrs ...string) *connectorv1.ChangeFeedRequest {
	return &connectorv1.ChangeFeedRequest{
		Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: f.prov.Identity()},
		Partition:  &connectorv1.FeedPartition{Partition: &connectorv1.FeedPartition_AdNcGuid{AdNcGuid: f.nc}},
		Attributes: attrs,
	}
}

func (f *feed) prime(t *testing.T, attrs ...string) *connectorv1.ChangeBatch {
	t.Helper()
	r := f.req(attrs...)
	r.Start = &connectorv1.ChangeFeedRequest_Prime{Prime: &connectorv1.FeedPrime{}}
	bs, err := feedAll(f.c, r)
	if err != nil || len(bs) != 1 {
		t.Fatalf("prime: %v (%d batches)", err, len(bs))
	}
	return bs[0]
}

func (f *feed) resume(c *connectorv1.FeedCookie, attrs ...string) ([]*connectorv1.ChangeBatch, error) {
	r := f.req(attrs...)
	r.Start = &connectorv1.ChangeFeedRequest_Resume{Resume: &connectorv1.FeedResume{Cookie: c}}
	return feedAll(f.c, r)
}

func changes(bs []*connectorv1.ChangeBatch) map[string]*connectorv1.ObjectChange {
	out := map[string]*connectorv1.ObjectChange{}
	for _, b := range bs {
		for _, c := range b.GetChanges() {
			out[string(c.GetObjectGuid().GetValue())] = c
		}
	}
	return out
}

// CC-FEED-01, 07..12.
func TestLabFeedPrimeAndTheCookiePreChecks(t *testing.T) {
	l := newFeedLab(t)
	f := l.open(t, false, "", nil)
	ctx := context.Background()
	dc, err := f.prov.BoundDC(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// CC-FEED-01: one batch, complete, no object data, a cookie that names the DC Describe would.
	b := f.prime(t, "cn")
	ck := b.GetCookieAfter()
	if !b.GetCycleComplete() || len(b.GetChanges()) != 0 || b.GetSequence() != 1 {
		t.Fatalf("prime batch: complete=%v changes=%d seq=%d", b.GetCycleComplete(), len(b.GetChanges()), b.GetSequence())
	}
	if !proto.Equal(ck.GetIssuer().GetDsaGuid(), dc.GetDsaGuid()) || !proto.Equal(ck.GetIssuer().GetInvocationId(), dc.GetInvocationId()) {
		t.Fatalf("issuer %v is not the bound DC %v", ck.GetIssuer(), dc)
	}
	if ck.HighestCommittedUsnBefore == nil || ck.GetHighestCommittedUsnBefore() == 0 || ck.GetIssuedAt() == nil || len(ck.GetProviderState()) == 0 {
		t.Fatalf("cookie incomplete: %v", ck)
	}

	// The honest cookie resumes: an empty, complete batch with a newer issued_at (CC-FEED-03).
	bs, err := f.resume(ck, "cn")
	if err != nil || len(bs) != 1 || !bs[0].GetCycleComplete() {
		t.Fatalf("resume: %v %d", err, len(bs))
	}
	if !bs[0].GetCookieAfter().GetIssuedAt().AsTime().After(ck.GetIssuedAt().AsTime()) {
		t.Error("issued_at did not advance")
	}

	edit := func(f func(*connectorv1.FeedCookie)) *connectorv1.FeedCookie {
		c := proto.Clone(ck).(*connectorv1.FeedCookie)
		f(c)
		return c
	}
	tooOld := func(age time.Duration) *connectorv1.FeedCookie {
		return edit(func(c *connectorv1.FeedCookie) { c.IssuedAt = timestamppb.New(time.Now().Add(-age)) })
	}
	life, err := f.src.DeletionLifetime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	boundary := life - max(24*time.Hour, life/10)
	t.Logf("deletion lifetime %v, boundary %v", life, boundary)

	for _, c := range []struct {
		id   string
		name string
		ck   *connectorv1.FeedCookie
		want connectorv1.ResyncReason
	}{
		{"CC-FEED-07", "invocation_id", edit(func(c *connectorv1.FeedCookie) {
			c.Issuer.InvocationId = write.GUIDToWire(guid.GUID{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6})
		}), connectorv1.ResyncReason_RESYNC_REASON_INVOCATION_ID_CHANGED},
		{"CC-FEED-08", "usn", edit(func(c *connectorv1.FeedCookie) {
			u := ck.GetHighestCommittedUsnBefore() + 1_000_000
			c.HighestCommittedUsnBefore = &u
		}),
			connectorv1.ResyncReason_RESYNC_REASON_USN_ROLLBACK},
		{"CC-FEED-09", "dsa_guid", edit(func(c *connectorv1.FeedCookie) {
			c.Issuer.DsaGuid = write.GUIDToWire(guid.GUID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1})
		}), connectorv1.ResyncReason_RESYNC_REASON_ISSUER_MISMATCH},
		{"CC-FEED-10", "at the boundary", tooOld(boundary + time.Minute), connectorv1.ResyncReason_RESYNC_REASON_COOKIE_TOO_OLD},
		{"CC-FEED-10", "far beyond", tooOld(2 * life), connectorv1.ResyncReason_RESYNC_REASON_COOKIE_TOO_OLD},
		{"CC-FEED-11", "provider_state", edit(func(c *connectorv1.FeedCookie) { c.ProviderState = []byte("not a dirsync cookie at all") }),
			connectorv1.ResyncReason_RESYNC_REASON_SERVER_REJECTED},
		{"CC-FEED-12", "format_version", edit(func(c *connectorv1.FeedCookie) { c.FormatVersion = 99 }),
			connectorv1.ResyncReason_RESYNC_REASON_COOKIE_FORMAT_UNKNOWN},
	} {
		bs, err := f.resume(c.ck, "cn")
		if len(bs) != 0 {
			t.Errorf("%s %s: %d batches before the refusal", c.id, c.name, len(bs))
		}
		if got := staleReason(t, err); got != c.want {
			t.Errorf("%s %s: reason %v, want %v", c.id, c.name, got, c.want)
		}
	}

	// CC-FEED-10: just inside the margin is a normal batch.
	bs, err = f.resume(tooOld(boundary-time.Minute), "cn")
	if err != nil || len(bs) == 0 || !bs[len(bs)-1].GetCycleComplete() {
		t.Errorf("CC-FEED-10 just inside: %v %d", err, len(bs))
	}
}

// CC-FEED-17, 18 and the mandatory set on live and deleted objects.
func TestLabFeedRefusalsAndTheMandatorySet(t *testing.T) {
	l := newFeedLab(t)
	f := l.open(t, true, "", nil)

	full := f.req("cn")
	full.Start = &connectorv1.ChangeFeedRequest_Full{Full: &connectorv1.FeedFull{}}
	if _, err := feedAll(f.c, full); code(err) != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Errorf("CC-FEED-17: %v", err)
	}
	for _, a := range [][]string{{"*"}, {"+"}, {"cn", "*"}} {
		r := f.req(a...)
		r.Start = &connectorv1.ChangeFeedRequest_Prime{Prime: &connectorv1.FeedPrime{}}
		if _, err := feedAll(f.c, r); code(err) != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
			t.Errorf("CC-FEED-18 %v: %v", a, err)
		}
	}
	// Configuration and Schema are NC heads DirSync would follow; this connection does not manage them.
	r := f.req("cn")
	r.Partition = &connectorv1.FeedPartition{Partition: &connectorv1.FeedPartition_AdNcGuid{AdNcGuid: write.GUIDToWire(l.guidOf(t, "CN=Configuration,"+labDom))}}
	r.Start = &connectorv1.ChangeFeedRequest_Prime{Prime: &connectorv1.FeedPrime{}}
	if _, err := feedAll(f.c, r); code(err) != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
		t.Errorf("Configuration NC accepted: %v", err)
	}

	// Mandatory set on every change: a live user with a comma and a non-ASCII letter, and a deleted one.
	stamp := time.Now().UnixNano() % 1_000_000
	mk := func(name, sam string) string {
		d := "CN=" + strings.ReplaceAll(name, ",", `\,`) + ",CN=Users," + labDom
		add := ldap.NewAddRequest(d, nil)
		add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
		add.Attribute("sAMAccountName", []string{sam})
		if err := l.adm.Add(add); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.adm.Del(ldap.NewDelRequest(d, nil)) })
		return d
	}
	prime := f.prime(t, "cn", "sAMAccountName")
	live := mk(fmt.Sprintf("Müller, F%d", stamp), fmt.Sprintf("t1194a%d", stamp))
	gone := mk(fmt.Sprintf("Gone, F%d", stamp), fmt.Sprintf("t1194b%d", stamp))
	liveG, goneG := l.guidOf(t, live), l.guidOf(t, gone)
	if err := l.adm.Del(ldap.NewDelRequest(gone, nil)); err != nil {
		t.Fatal(err)
	}
	bs, err := f.resume(prime.GetCookieAfter(), "cn", "sAMAccountName")
	if err != nil || len(bs) == 0 || !bs[len(bs)-1].GetCycleComplete() {
		t.Fatalf("resume: %v", err)
	}
	cs := changes(bs)
	for _, c := range []struct {
		g    guid.GUID
		name string
	}{{liveG, "live"}, {goneG, "deleted"}} {
		oc := cs[string(write.GUIDToWire(c.g).GetValue())]
		if oc == nil {
			t.Fatalf("%s user is not in the feed", c.name)
		}
		have := map[string]bool{}
		for _, a := range oc.GetAttributes() {
			have[a.GetName()] = true
		}
		// Samba's DirSync never sends cn (the RDN arrives as name); a requested ordinary attribute does
		// arrive. Whether Windows sends cn is for the Windows lab (T-1282); consumers key on name.
		t.Logf("%s change attributes: %v (cn sent: %v)", c.name, have, have["cn"])
		for _, m := range []string{"objectclass", "name", "samaccountname"} {
			if !have[m] {
				t.Errorf("CC-FEED-18 %s change lacks %s (has %v)", c.name, m, have)
			}
		}
		if oc.GetDn().GetDisplayDn() == "" {
			t.Errorf("%s change without a DN", c.name)
		}
	}
	if st := cs[string(write.GUIDToWire(liveG).GetValue())].GetState(); st != connectorv1.ObjectState_OBJECT_STATE_LIVE {
		t.Errorf("live user state %v", st)
	}
	del := cs[string(write.GUIDToWire(goneG).GetValue())]
	if del.GetState() == connectorv1.ObjectState_OBJECT_STATE_LIVE || !strings.Contains(del.GetDn().GetDisplayDn(), "Deleted Objects") {
		t.Errorf("deleted user: state %v dn %q", del.GetState(), del.GetDn().GetDisplayDn())
	}
	hasLKP := false
	for _, a := range del.GetAttributes() {
		hasLKP = hasLKP || a.GetName() == "lastknownparent"
	}
	t.Logf("tombstone state %v, lastKnownParent present: %v", del.GetState(), hasLKP)
	if !hasLKP {
		t.Error("CC-FEED-18 the deleted object lacks lastKnownParent")
	}
}

// ---- failure injection: a relay in front of the lab -----------------------------------------------

type relay struct {
	ln    net.Listener
	pool  *x509.CertPool
	stuck atomic.Bool // answer every DirSync search "more results" with a new cookie and no entries

	mu     sync.Mutex
	conns  []net.Conn
	dirIDs map[int64]bool // message ids of DirSync searches in flight
	seq    atomic.Uint32
}

func (r *relay) Addr() string { return r.ln.Addr().String() }

// Kill closes the listener and every connection: the DC is gone.
func (r *relay) Kill() {
	r.ln.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conns {
		c.Close()
	}
}

const oidDirSyncWire = "1.2.840.113556.1.4.841"

func startRelay(t *testing.T, l *feedLab) *relay {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "feed-relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{ln: ln, pool: pool, dirIDs: map[int64]bool{}}
	t.Cleanup(r.Kill)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(t, l, c)
		}
	}()
	return r
}

func (r *relay) serve(t *testing.T, l *feedLab, client net.Conn) {
	up, err := tls.Dial("tcp", "localhost:"+l.env["LAB_LDAPS_PORT"], &tls.Config{RootCAs: l.pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err != nil {
		client.Close()
		return
	}
	r.mu.Lock()
	r.conns = append(r.conns, client, up)
	r.mu.Unlock()
	defer client.Close()
	defer up.Close()
	go func() { // upstream -> client, rewriting DirSync answers while stuck
		defer client.Close()
		for {
			pkt, err := ber.ReadPacket(up)
			if err != nil {
				return
			}
			out := pkt.Bytes()
			if r.stuck.Load() && len(pkt.Children) >= 2 {
				id, _ := pkt.Children[0].Value.(int64)
				op := pkt.Children[1]
				r.mu.Lock()
				dir := r.dirIDs[id]
				r.mu.Unlock()
				if dir && op.ClassType == ber.ClassApplication {
					switch op.Tag {
					case 4, 19: // entry, continuation: drop
						continue
					case 5: // done: more results, a new cookie each time
						out = stuckDone(id, r.seq.Add(1))
					}
				}
			}
			if _, err := client.Write(out); err != nil {
				return
			}
		}
	}()
	for { // client -> upstream, noting DirSync searches
		pkt, err := ber.ReadPacket(client)
		if err != nil {
			return
		}
		if len(pkt.Children) >= 3 && pkt.Children[1].ClassType == ber.ClassApplication && pkt.Children[1].Tag == 3 && pkt.Children[2].ClassType == ber.ClassContext {
			for _, c := range pkt.Children[2].Children {
				if oid, _ := c.Children[0].Value.(string); oid == oidDirSyncWire {
					id, _ := pkt.Children[0].Value.(int64)
					r.mu.Lock()
					r.dirIDs[id] = true
					r.mu.Unlock()
				}
			}
		}
		if _, err := up.Write(pkt.Bytes()); err != nil {
			return
		}
	}
}

// stuckDone is a SearchResultDone (success) with a DirSync response control: MoreData set, a cookie
// that differs every time.
func stuckDone(id int64, n uint32) []byte {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "DirSync Control Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "MoreData"))
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "MaxAttributeCount"))
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, fmt.Sprintf("stuck-%d", n), "Cookie"))
	val := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")
	val.Data.Write(seq.Bytes())
	ctrl := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	ctrl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, oidDirSyncWire, "Control Type"))
	ctrl.AppendChild(val)
	ctrls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	ctrls.AppendChild(ctrl)
	done := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "Search Result Done")
	done.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "Result Code"))
	done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Diagnostic"))
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "Message ID"))
	msg.AppendChild(done)
	msg.AppendChild(ctrls)
	return msg.Bytes()
}

// CC-FEED-13: the issuing DC goes away. The answer is UNREACHABLE_DC for the same DC, never a stale
// cookie, and the connector does not try another DC for the cookie.
func TestLabFeedIssuerDownIsUnreachableNeverStale(t *testing.T) {
	l := newFeedLab(t)
	rl := startRelay(t, l)
	f := l.open(t, false, rl.Addr(), rl.pool)
	ck := f.prime(t, "cn").GetCookieAfter()
	if bs, err := f.resume(ck, "cn"); err != nil || len(bs) == 0 {
		t.Fatalf("resume before the outage: %v", err)
	}
	rl.Kill()
	bs, err := f.resume(ck, "cn")
	if len(bs) != 0 {
		t.Fatalf("%d batches from a dead DC", len(bs))
	}
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_UNREACHABLE_DC {
		t.Fatalf("issuer down: %v", err)
	}
	if retryOf(err) != connectorv1.RetryAdvice_RETRY_ADVICE_SAME_DC_AFTER_BACKOFF {
		t.Errorf("retry advice %v, want the same DC", retryOf(err))
	}
}

// A DC that keeps saying "more results" with a new cookie and no changes ends at the page bound,
// with LIMIT_EXCEEDED, instead of looping (T-1193 security review (b)).
func TestLabFeedStuckDCIsBounded(t *testing.T) {
	l := newFeedLab(t)
	rl := startRelay(t, l)
	f := l.open(t, false, rl.Addr(), rl.pool, read.WithFeedLimits(25, time.Minute))
	ck := f.prime(t, "cn").GetCookieAfter()
	rl.stuck.Store(true)
	start := time.Now()
	bs, err := f.resume(ck, "cn")
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED {
		t.Fatalf("stuck DC: %v (%d batches)", err, len(bs))
	}
	for _, b := range bs {
		if b.GetCycleComplete() {
			t.Fatal("a stuck cycle was reported complete")
		}
	}
	if n := rl.seq.Load(); n < 25 || n > 27 {
		t.Errorf("the connector sent %d DirSync requests for a bound of 25", n)
	}
	t.Logf("stopped after %d responses in %v", len(bs), time.Since(start))
	// The prime is bounded the same way.
	r := f.req("cn")
	r.Start = &connectorv1.ChangeFeedRequest_Prime{Prime: &connectorv1.FeedPrime{}}
	if _, err := feedAll(f.c, r); code(err) != connectorv1.ErrorCode_ERROR_CODE_LIMIT_EXCEEDED {
		t.Fatalf("stuck prime: %v", err)
	}
}

func retryOf(err error) connectorv1.RetryAdvice {
	var re *client.RemoteError
	if errors.As(client.FromStatus(err), &re) {
		return re.Err.GetRetry()
	}
	return connectorv1.RetryAdvice_RETRY_ADVICE_UNSPECIFIED
}
