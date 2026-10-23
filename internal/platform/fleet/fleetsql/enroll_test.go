package fleetsql_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// keySource gives each tenant a fixed DEK. A real source loads the wrapped DEK from DM-02.
type keySource struct {
	mu   sync.Mutex
	fail bool
	deks map[tenant.ID][]byte
}

func (k *keySource) DEK(_ context.Context, _ store.Tx, id tenant.ID, version uint32) (keys.DEK, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail {
		return keys.DEK{}, &keys.Error{Code: keys.ProviderUnavailable}
	}
	if k.deks == nil {
		k.deks = map[tenant.ID][]byte{}
	}
	if k.deks[id] == nil {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		k.deks[id] = b
	}
	if version == 0 {
		version = 1
	}
	return keys.DEKFromBytes(version, append([]byte(nil), k.deks[id]...)) // Destroy zeroes what it was given
}

func (k *keySource) setFail(f bool) { k.mu.Lock(); k.fail = f; k.mu.Unlock() }

type alerts struct {
	mu   sync.Mutex
	list []fleetsql.AlertKind
}

func (a *alerts) Raise(_ context.Context, al fleetsql.Alert) {
	a.mu.Lock()
	a.list = append(a.list, al.Kind)
	a.mu.Unlock()
}

func (a *alerts) has(k fleetsql.AlertKind) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, x := range a.list {
		if x == k {
			return true
		}
	}
	return false
}

type sink struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (s *sink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
	return nil
}

type enrollEnv struct {
	*env
	ks   *keySource
	al   *alerts
	sink *sink
	enr  *fleetsql.Enroller
	svc  *fleetsql.Enrollment
}

func setupEnroll(t *testing.T, s *storetest.Server) *enrollEnv {
	t.Helper()
	e := setup(t, s)
	svc := e.svc(true, true, fleetsql.NewMemoryLimiter(fleetsql.MemoryLimiterConfig{Burst: 1000}))
	ee := &enrollEnv{env: e, ks: &keySource{}, al: &alerts{}, sink: &sink{}, svc: svc}
	ee.enr = &fleetsql.Enroller{Enrollment: svc, Keys: ee.ks, Alerts: ee.al, Audit: ee.sink,
		Endpoints: []fleetsql.Endpoint{{Host: "fleet.example.test", Port: 8443}}}
	return ee
}

func (e *enrollEnv) issue(t *testing.T, tid tenant.ID, kind fleetsql.Kind) fleetsql.Issued {
	t.Helper()
	iss, err := e.svc.Issue(context.Background(), tid, admin, fleetsql.NewComponent{Kind: kind, Name: "host-1"})
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func csrFor(t *testing.T, tmpl *x509.CertificateRequest) ([]byte, any) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl == nil {
		tmpl = &x509.CertificateRequest{}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, k)
	if err != nil {
		t.Fatal(err)
	}
	return der, k
}

const peerIP = "192.0.2.10:5555"

func (e *enrollEnv) state(t *testing.T, tid tenant.ID, id string) (state string, serial *string) {
	t.Helper()
	err := e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, cert_serial FROM public.components WHERE id = $1::uuid`, id).Scan(&state, &serial)
	})
	if err != nil {
		t.Fatal(err)
	}
	return
}

// strictBundle is the component's parse (TM-D24 D3), written here as the oracle.
func strictBundle(t *testing.T, b []byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	rest := bytes.TrimSpace(b)
	for len(rest) > 0 {
		blk, r := pem.Decode(rest)
		if blk == nil || blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
			t.Fatalf("bundle has a non-CERTIFICATE or headered block: %q", rest)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil || !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0 {
			t.Fatalf("bundle certificate is not a CA: %v", err)
		}
		out = append(out, c)
		rest = bytes.TrimSpace(r)
	}
	if len(out) == 0 || len(out) > 8 || len(b) > 64<<10 {
		t.Fatalf("bundle size: %d certs, %d bytes", len(out), len(b))
	}
	return out
}

// AC1, AC3, AC4 (the audit part), pin, bundle content.
func TestEnroll(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnroll(t, s)
		ctx := context.Background()
		iss := e.issue(t, e.a, fleetsql.KindConnector)

		// The request tries to name another tenant and component, and to add DNS/IP/e-mail names and a
		// subject: none of it reaches the certificate (AC3).
		other := e.issue(t, e.b, fleetsql.KindAgent)
		u, _ := url.Parse("urn:activediq:tenant:" + e.b.String())
		csr, key := csrFor(t, &x509.CertificateRequest{
			Subject:        pkix.Name{CommonName: "tenant " + e.b.String(), Organization: []string{other.ComponentID}},
			DNSNames:       []string{"evil.example"},
			IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
			EmailAddresses: []string{"a@b.example"},
			URIs:           []*url.URL{u},
		})
		got, err := e.enr.Enroll(ctx, peerIP, iss.Token.String(), csr)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(got.LeafDER)
		if err != nil {
			t.Fatal(err)
		}
		if len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 2 || leaf.Subject.String() != "" || leaf.IsCA {
			t.Fatalf("leaf carries more than tenant+component in the SAN: %v subject %q", leaf.URIs, leaf.Subject)
		}
		id, err := fleet.IdentityOf(leaf)
		if err != nil || id.Tenant != e.a || id.ComponentID != iss.ComponentID || id.Kind != "connector" {
			t.Fatalf("identity %+v err %v, want tenant A component %s", id, err, iss.ComponentID)
		}
		if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.(*ecdsa.PrivateKey).PublicKey) {
			t.Fatal("leaf does not certify the CSR key")
		}
		// The response verifies against the bundle it returns, as a client certificate.
		roots := x509.NewCertPool()
		cas := strictBundle(t, got.CABundlePEM)
		for _, c := range cas {
			roots.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Fatalf("leaf does not verify against the returned bundle: %v", err)
		}
		if !got.NotAfter.Equal(leaf.NotAfter) || len(got.Endpoints) != 1 || got.Endpoints[0].Port != 8443 {
			t.Fatalf("response: %+v", got)
		}
		// Component is enrolled with the serial; the token is spent; one audit event names the component.
		st, serial := e.state(t, e.a, iss.ComponentID)
		if st != "enrolled" || serial == nil || *serial != leaf.SerialNumber.Text(16) {
			t.Fatalf("component state %q serial %v", st, serial)
		}
		if len(e.sink.evs) != 1 || e.sink.evs[0].Kind != "fleet.component.enrolled" || e.sink.evs[0].Target.GUID != iss.ComponentID {
			t.Fatalf("audit: %+v", e.sink.evs)
		}
		if _, err := e.enr.Enroll(ctx, peerIP, iss.Token.String(), csr); !errors.Is(err, fleetsql.ErrTokenInvalid) {
			t.Fatalf("second use: %v", err)
		}
		// The pin shown to the admin is the SPKI hash of the bundle's CA.
		var pin string
		if err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			var err error
			pin, err = e.enr.CAPin(ctx, tx, e.a)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(cas[0].RawSubjectPublicKeyInfo)
		if pin != "sha256:"+hex.EncodeToString(h[:]) {
			t.Fatalf("pin %s", pin)
		}
		// Tenant B's CA is another CA.
		resp, err := e.enr.Enroll(ctx, peerIP, other.Token.String(), csr)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(strictBundle(t, resp.CABundlePEM)[0].Raw, cas[0].Raw) {
			t.Fatal("two tenants share a CA certificate")
		}
	})
}

// AC2: every bad token gets the same answer; a bad CSR is its own answer and burns nothing.
func TestEnrollRefusals(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnroll(t, s)
		ctx := context.Background()
		csr, _ := csrFor(t, nil)

		unknown := e.issue(t, e.a, fleetsql.KindAgent)
		forged := unknown.Token.String()[:len(unknown.Token.String())-2] + "AA"
		expired := e.issue(t, e.a, fleetsql.KindAgent)
		// Test-only: superuser with the guard trigger off ages the row (the database is this test's own).
		adm, err := e.d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer adm.Close(ctx)
		if _, err := adm.Exec(ctx, `ALTER TABLE public.enrollment_tokens DISABLE TRIGGER enrollment_tokens_guard`); err != nil {
			t.Fatal(err)
		}
		if tag, err := adm.Exec(ctx, `UPDATE public.enrollment_tokens SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = $1::uuid`, expired.TokenID); err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("age token: %v %v", tag, err)
		}
		used := e.issue(t, e.a, fleetsql.KindAgent)
		if _, err := e.enr.Enroll(ctx, peerIP, used.Token.String(), csr); err != nil {
			t.Fatal(err)
		}
		var msgs []string
		for name, tok := range map[string]string{"forged": forged, "expired": expired.Token.String(), "used": used.Token.String(), "empty": "", "junk": "enr1.x.y"} {
			_, err := e.enr.Enroll(ctx, peerIP, tok, csr)
			if !errors.Is(err, fleetsql.ErrTokenInvalid) {
				t.Fatalf("%s: %v", name, err)
			}
			msgs = append(msgs, err.Error())
		}
		for _, m := range msgs {
			if m != msgs[0] {
				t.Fatalf("refusals differ: %q vs %q", m, msgs[0])
			}
		}

		// A bad CSR: refused with ErrCSR, the token is not burned.
		fresh := e.issue(t, e.a, fleetsql.KindAgent)
		small, _ := rsa.GenerateKey(rand.Reader, 2048)
		weak, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, small)
		bad := map[string][]byte{"empty": nil, "garbage": []byte("nope"), "trailing": append(append([]byte{}, csr...), 0), "rsa2048": weak, "huge": make([]byte, 9<<10)}
		for name, b := range bad {
			if _, err := e.enr.Enroll(ctx, peerIP, fresh.Token.String(), b); !errors.Is(err, fleetsql.ErrCSR) {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if _, err := e.enr.Enroll(ctx, peerIP, fresh.Token.String(), csr); err != nil {
			t.Fatalf("token burned by a bad CSR: %v", err)
		}
		// Ed25519 is accepted.
		_, edk, _ := ed25519.GenerateKey(rand.Reader)
		edcsr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, edk)
		if _, err := e.enr.Enroll(ctx, peerIP, e.issue(t, e.a, fleetsql.KindAgent).Token.String(), edcsr); err != nil {
			t.Fatalf("ed25519: %v", err)
		}
	})
}

// (2) of the T-0153 review: a failure after redemption rolls the redemption back.
func TestEnrollIsAtomicWithRedeem(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnroll(t, s)
		ctx := context.Background()
		csr, _ := csrFor(t, nil)
		iss := e.issue(t, e.a, fleetsql.KindConnector)
		e.ks.setFail(true)
		if _, err := e.enr.Enroll(ctx, peerIP, iss.Token.String(), csr); err == nil || errors.Is(err, fleetsql.ErrTokenInvalid) {
			t.Fatalf("with the key provider down: %v", err)
		}
		if st, serial := e.state(t, e.a, iss.ComponentID); st != "pending" || serial != nil {
			t.Fatalf("component %q %v after a failed enrolment", st, serial)
		}
		if len(e.sink.evs) != 0 {
			t.Fatal("audit event for a failed enrolment")
		}
		e.ks.setFail(false)
		if _, err := e.enr.Enroll(ctx, peerIP, iss.Token.String(), csr); err != nil {
			t.Fatalf("token burned by a server-side failure: %v", err)
		}
	})
}

func TestEnrollConcurrentOneWinner(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnroll(t, s)
		csr, _ := csrFor(t, nil)
		iss := e.issue(t, e.a, fleetsql.KindConnector)
		var ok, invalid atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := e.enr.Enroll(context.Background(), peerIP, iss.Token.String(), csr)
				switch {
				case err == nil:
					ok.Add(1)
				case errors.Is(err, fleetsql.ErrTokenInvalid):
					invalid.Add(1)
				default:
					t.Errorf("unexpected: %v", err)
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 1 || invalid.Load() != 7 {
			t.Fatalf("winners %d, refused %d", ok.Load(), invalid.Load())
		}
	})
}

// AC4: the CA key at rest is sealed, bound to its place, and nowhere in plaintext.
func TestCAKeyIsSealed(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnroll(t, s)
		ctx := context.Background()
		for _, tid := range []tenant.ID{e.a, e.b} {
			if err := e.db.WithTenant(ctx, tid, func(ctx context.Context, tx store.Tx) error { return e.enr.InitTenant(ctx, tx, tid) }); err != nil {
				t.Fatal(err)
			}
		}
		var rowID string
		var sealed []byte
		var version int32
		var leaks bool
		err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT id::text, sealed_key, key_version,
				position('PRIVATE KEY'::bytea IN sealed_key) > 0 OR position('PRIVATE KEY'::bytea IN cert_der) > 0
				FROM public.fleet_ca f`).Scan(&rowID, &sealed, &version, &leaks)
		})
		if err != nil || leaks || version != 1 {
			t.Fatalf("row: %v leaks %v version %d", err, leaks, version)
		}
		dek, _ := e.ks.DEK(ctx, nil, e.a, 1)
		defer dek.Destroy()
		pt, err := keys.Open(dek, keys.Context{Tenant: e.a, Table: "fleet_ca", Row: rowID, Column: "sealed_key", Version: 1}, sealed)
		if err != nil {
			t.Fatalf("sealed under the tenant DEK and its own place: %v", err)
		}
		if _, err := x509.ParsePKCS8PrivateKey(pt); err != nil {
			t.Fatal(err)
		}
		// Bound to tenant, table and column: the same blob opens in none of the others.
		dekB, _ := e.ks.DEK(ctx, nil, e.b, 1)
		defer dekB.Destroy()
		for name, c := range map[string]struct {
			dek keys.DEK
			ctx keys.Context
		}{
			"other tenant key": {dekB, keys.Context{Tenant: e.a, Table: "fleet_ca", Row: rowID, Column: "sealed_key", Version: 1}},
			"other tenant":     {dek, keys.Context{Tenant: e.b, Table: "fleet_ca", Row: rowID, Column: "sealed_key", Version: 1}},
			"other column":     {dek, keys.Context{Tenant: e.a, Table: "fleet_ca", Row: rowID, Column: "cert_der", Version: 1}},
			"other row":        {dek, keys.Context{Tenant: e.a, Table: "fleet_ca", Row: "00000000-0000-0000-0000-000000000000", Column: "sealed_key", Version: 1}},
		} {
			if _, err := keys.Open(c.dek, c.ctx, sealed); err == nil {
				t.Fatalf("%s: opened", name)
			}
		}
		// Tenant B cannot see tenant A's CA row.
		var n int
		_ = e.db.WithTenant(ctx, e.b, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.fleet_ca WHERE id = $1::uuid`, rowID).Scan(&n)
		})
		if n != 0 {
			t.Fatal("tenant B reads tenant A's CA")
		}
		// The row cannot be rewritten, and cannot be deleted by the runtime role.
		for name, sql := range map[string]string{
			"swap key":  `UPDATE public.fleet_ca SET sealed_key = sealed_key || '\x00'::bytea`,
			"swap cert": `UPDATE public.fleet_ca SET cert_der = cert_der || '\x00'::bytea`,
			"delete":    `DELETE FROM public.fleet_ca`,
		} {
			if n, err := e.raw(e.a, sql); err == nil && n > 0 {
				t.Fatalf("%s succeeded", name)
			}
		}
	})
}

// TM-D24 D2: the bundle is built from parsed certificates; bad stored material is never served.
func TestBundleIsNeverServedFromBadMaterial(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		csr, _ := csrFor(t, nil)

		// A real CA's certificate, a leaf (not a CA), and a CA certificate with trailing bytes.
		goodEnv := setupEnroll(t, s)
		first := goodEnv.issue(t, goodEnv.a, fleetsql.KindConnector)
		got, err := goodEnv.enr.Enroll(ctx, peerIP, first.Token.String(), csr)
		if err != nil {
			t.Fatal(err)
		}
		caDER := strictBundle(t, got.CABundlePEM)[0].Raw
		nonCA := got.LeafDER
		privBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bytes.Repeat([]byte{7}, 48)})
		certBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
		cases := map[string]struct {
			der      []byte
			exposure bool
		}{
			"private key block":         {privBlock, true},
			"cert then private key":     {append(append([]byte{}, certBlock...), privBlock...), true},
			"pem certificate (not der)": {certBlock, false},
			"non-CA certificate":        {nonCA, false},
			"trailing bytes":            {append(append([]byte{}, caDER...), 0, 0), false},
			"garbage":                   {bytes.Repeat([]byte{1}, 100), false},
		}
		for name, c := range cases {
			t.Run(name, func(t *testing.T) {
				e := setupEnroll(t, s)
				tok := e.issue(t, e.a, fleetsql.KindConnector)
				if err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error { return e.enr.InitTenant(ctx, tx, e.a) }); err != nil {
					t.Fatal(err)
				}
				// The runtime role under the tenant's own context: the only way a row gets in.
				if _, err := e.raw(e.a, `INSERT INTO public.fleet_ca (tenant_id, cert_der, spki_sha256, sealed_key, key_version, not_after, state)
					VALUES (NULLIF(current_setting('app.tenant_id', true), '')::uuid, $1, $2, $3, 1, now() + interval '1 year', 'retired')`,
					c.der, bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{3}, 40)); err != nil {
					t.Fatal(err)
				}
				resp, err := e.enr.Enroll(ctx, peerIP, tok.Token.String(), csr)
				if !errors.Is(err, fleetsql.ErrTokenInvalid) || len(resp.CABundlePEM) != 0 || len(resp.LeafDER) != 0 {
					t.Fatalf("served despite bad stored material: %v", err)
				}
				if !e.al.has(fleetsql.AlertCAMaterial) || e.al.has(fleetsql.AlertCAKeyExposure) != c.exposure {
					t.Fatalf("alerts %v, want material alert and exposure=%v", e.al.list, c.exposure)
				}
				if st, _ := e.state(t, e.a, tok.ComponentID); st != "pending" {
					t.Fatalf("component %q", st)
				}
			})
		}
	})
}

// AC5, DM-12.I3.
func TestRotateKeepsIdentity(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupEnroll(t, s)
		ctx := context.Background()
		csr, _ := csrFor(t, nil)
		iss := e.issue(t, e.a, fleetsql.KindAgent)
		first, err := e.enr.Enroll(ctx, peerIP, iss.Token.String(), csr)
		if err != nil {
			t.Fatal(err)
		}
		cur, _ := x509.ParseCertificate(first.LeafDER)
		peer, err := fleet.IdentityOf(cur)
		if err != nil {
			t.Fatal(err)
		}

		csr2, _ := csrFor(t, nil)
		second, err := e.enr.Rotate(ctx, peer, csr2)
		if err != nil {
			t.Fatal(err)
		}
		next, _ := x509.ParseCertificate(second.LeafDER)
		nid, _ := fleet.IdentityOf(next)
		if nid.ComponentID != peer.ComponentID || nid.Tenant != peer.Tenant || nid.Kind != peer.Kind || nid.Serial == peer.Serial {
			t.Fatalf("rotation changed identity or kept the serial: %+v -> %+v", peer, nid)
		}
		var rows int
		_ = e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.components`).Scan(&rows)
		})
		if st, serial := e.state(t, e.a, peer.ComponentID); rows != 1 || st != "enrolled" || *serial != nid.Serial {
			t.Fatalf("rows %d state %q serial %v", rows, st, serial)
		}
		// The superseded certificate cannot rotate again; another tenant's context cannot rotate it.
		if _, err := e.enr.Rotate(ctx, peer, csr2); !errors.Is(err, fleetsql.ErrRotateRefused) {
			t.Fatalf("old certificate: %v", err)
		}
		cross := nid
		cross.Tenant = e.b
		if _, err := e.enr.Rotate(ctx, cross, csr2); !errors.Is(err, fleetsql.ErrRotateRefused) {
			t.Fatalf("cross-tenant: %v", err)
		}
		wrongKind := nid
		wrongKind.Kind = "connector"
		if _, err := e.enr.Rotate(ctx, wrongKind, csr2); !errors.Is(err, fleetsql.ErrRotateRefused) {
			t.Fatalf("wrong kind: %v", err)
		}
		// A revoked component cannot rotate.
		if _, err := e.raw(e.a, `UPDATE public.components SET state = 'revoked' WHERE id = $1::uuid`, peer.ComponentID); err != nil {
			t.Fatal(err)
		}
		if _, err := e.enr.Rotate(ctx, nid, csr2); !errors.Is(err, fleetsql.ErrRotateRefused) {
			t.Fatalf("revoked: %v", err)
		}
		if got := len(e.sink.evs); got != 2 || e.sink.evs[1].Kind != "fleet.component.certificate_rotated" {
			t.Fatalf("audit events: %d", got)
		}
	})
}

func TestEnrollerNotConfigured(t *testing.T) {
	csr, _ := csrFor(t, nil)
	var e *fleetsql.Enroller
	if _, err := e.Enroll(context.Background(), peerIP, "x", csr); !errors.Is(err, fleetsql.ErrNotConfigured) {
		t.Fatal(err)
	}
	if _, err := (&fleetsql.Enroller{}).Rotate(context.Background(), fleet.Identity{}, csr); !errors.Is(err, fleetsql.ErrNotConfigured) {
		t.Fatal(err)
	}
}
