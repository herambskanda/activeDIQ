//go:build lab

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
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-0433 on Samba: `make lab-up && go test -tags lab ./internal/connector/read -run TestLab`.
// Samba proves the read, the pin and the classifier over one session. Windows-only behaviour
// (ranging at MaxValRange, a second DC) stays a Windows-lab ticket.

const labDom = "DC=lab,DC=activediq,DC=test"

type memPins struct {
	mu sync.Mutex
	g  []guid.GUID
}

func (m *memPins) PinnedC13(context.Context) ([]guid.GUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]guid.GUID(nil), m.g...), nil
}
func (m *memPins) PinC13(_ context.Context, gs []guid.GUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.g = append(m.g, gs...)
	return nil
}

type sink struct{ ms []*connectorv1.ReadResponse }

func (s *sink) Send(m *connectorv1.ReadResponse) error { s.ms = append(s.ms, m); return nil }

func labEnv(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "..", "lab", ".lab.env"))
	if err != nil {
		t.Fatalf("lab not up (make lab-up): %v", err)
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
	return env
}

func TestLabReadPinnedWithVerdict(t *testing.T) {
	env := labEnv(t)
	pem, err := os.ReadFile(filepath.Join("..", "..", "..", "lab", ".lab-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	port := env["LAB_LDAPS_PORT"]
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	sess, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + port}, RootCAs: pool, PageSize: 500,
		Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(env["LAB_SVC_PASSWORD"]))}})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	admin, err := ldap.DialURL("ldaps://localhost:"+port, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: "localhost"}))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := admin.Bind("Administrator@lab.activediq.test", env["LAB_ADMIN_PASSWORD"]); err != nil {
		t.Fatal(err)
	}
	guidOf := func(dn string) *connectorv1.Guid {
		r, err := admin.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"objectGUID"}, nil))
		if err != nil || len(r.Entries) != 1 {
			t.Fatalf("guid of %s: %v", dn, err)
		}
		g, err := guid.FromBytes(r.Entries[0].GetRawAttributeValue("objectGUID"))
		if err != nil {
			t.Fatal(err)
		}
		return write.GUIDToWire(g)
	}

	// An ordinary user with a comma and a non-ASCII letter in its name.
	name := fmt.Sprintf("Müller, T%d", time.Now().UnixNano()%1_000_000)
	userDN := "CN=" + strings.ReplaceAll(name, ",", `\,`) + ",CN=Users," + labDom
	add := ldap.NewAddRequest(userDN, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{fmt.Sprintf("t0433%d", time.Now().UnixNano()%1_000_000)})
	if err := admin.Add(add); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Del(ldap.NewDelRequest(userDN, nil)) })

	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: guidOf(labDom)}}}
	prov := write.NewADProvider(sess, nil, ident, &memPins{})
	adsrc, err := read.NewADSource(sess, prov)
	if err != nil {
		t.Fatal(err)
	}
	h, err := read.New(adsrc)
	if err != nil {
		t.Fatal(err)
	}
	dc, err := prov.BoundDC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	do := func(id *connectorv1.Guid, pin *connectorv1.Guid, tier0 bool) (*sink, error) {
		s := &sink{}
		r := &connectorv1.ReadRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: ident},
			Guid: id, Attributes: []string{"cn", "member", "userAccountControl", "whenCreated"}, IncludeTier0: tier0}
		if pin != nil {
			r.Dc = &connectorv1.DcSelection{PinnedDsaGuid: pin}
		}
		return s, h.Read(ctx, r, s)
	}

	// Ordinary user: served by the pinned DC, verdict false, parent is CN=Users.
	s, err := do(guidOf(userDN), dc.GetDsaGuid(), true)
	if err != nil {
		t.Fatal(err)
	}
	hd := s.ms[0].GetHeader()
	if hd.GetTier0() == nil || hd.GetTier0().GetTier0() {
		t.Fatalf("ordinary user verdict %v", hd.GetTier0())
	}
	if string(hd.GetObserved().GetDc().GetDsaGuid().GetValue()) != string(dc.GetDsaGuid().GetValue()) {
		t.Fatal("served by another DC")
	}
	if string(hd.GetEntry().GetParentGuid().GetValue()) != string(guidOf("CN=Users,"+labDom).GetValue()) {
		t.Fatal("parent GUID")
	}
	if !strings.Contains(hd.GetEntry().GetDn().GetDisplayDn(), "Müller") {
		t.Fatalf("dn %q", hd.GetEntry().GetDn().GetDisplayDn())
	}

	// Naming-context heads have no parent; the container above an ordinary object is its parent.
	for _, head := range []string{labDom, "CN=Configuration," + labDom} {
		s, err := do(guidOf(head), dc.GetDsaGuid(), false)
		if err != nil {
			t.Fatalf("%s: %v", head, err)
		}
		if s.ms[0].GetHeader().GetEntry().GetParentGuid() != nil {
			t.Fatalf("%s reported a parent", head)
		}
	}

	// Domain Admins: tier0 with a basis.
	s, err = do(guidOf("CN=Domain Admins,CN=Users,"+labDom), dc.GetDsaGuid(), true)
	if err != nil {
		t.Fatal(err)
	}
	if v := s.ms[0].GetHeader().GetTier0(); !v.GetTier0() || len(v.GetBasis()) == 0 {
		t.Fatalf("Domain Admins verdict %v", v)
	}

	// A pin to another DSA fails with no stream; a missing object is OBJECT_NOT_FOUND.
	other := write.GUIDToWire(guid.GUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	if s, err = do(guidOf(userDN), other, true); err == nil || len(s.ms) != 0 {
		t.Fatalf("foreign pin served: %v", err)
	}
	if _, err = do(write.GUIDToWire(guid.GUID{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}), dc.GetDsaGuid(), true); err == nil {
		t.Fatal("missing object read")
	}
}
