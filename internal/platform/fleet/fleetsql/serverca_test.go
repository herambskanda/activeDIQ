package fleetsql_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// instAuditor records installation-key events (what keys.InstallationAuditor gets in production).
type instAuditor struct {
	mu  sync.Mutex
	evs []keys.InstallationEvent
}

func (a *instAuditor) RecordInstallationKey(_ context.Context, ev keys.InstallationEvent) error {
	a.mu.Lock()
	a.evs = append(a.evs, ev)
	a.mu.Unlock()
	return nil
}

func (a *instAuditor) unseals() (n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.evs {
		if e.Action == keys.ActionUnseal && e.Outcome == keys.UnsealOK {
			n++
		}
	}
	return
}

type certAuditor struct {
	mu   sync.Mutex
	evs  []fleetsql.ServerCertEvent
	fail bool
}

func (c *certAuditor) RecordServerCert(_ context.Context, ev fleetsql.ServerCertEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return errors.New("audit down")
	}
	c.evs = append(c.evs, ev)
	return nil
}

type serverEnv struct {
	*enrollEnv
	kms  *keystest.KMS
	ia   *instAuditor
	ca   *certAuditor
	keys *keys.InstallationKeys
}

func setupServer(t *testing.T, s *storetest.Server) *serverEnv {
	t.Helper()
	e := setupEnroll(t, s)
	kms := keystest.New("kek-1")
	ia := &instAuditor{}
	ik, err := keys.NewInstallationKeys(kms, ia)
	if err != nil {
		t.Fatal(err)
	}
	ca := &certAuditor{}
	e.enr.InstallationKeys, e.enr.ServerAudit = ik, ca
	e.enr.Endpoints = []fleetsql.Endpoint{{Host: "Fleet.Example.Test", Port: 8443}, {Host: "203.0.113.7", Port: 8443}}
	return &serverEnv{enrollEnv: e, kms: kms, ia: ia, ca: ca, keys: ik}
}

func (e *serverEnv) pin(t *testing.T, tid tenant.ID) string {
	t.Helper()
	var pin string
	if err := e.db.WithTenant(context.Background(), tid, func(ctx context.Context, tx store.Tx) error {
		var err error
		pin, err = e.enr.ServerPin(ctx, tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return pin
}

// AC1 and AC3: the schema has no tenant_id, the CA has the ADR-0008 shape, and two tenants get one pin.
func TestServerCASchemaAndPin(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupServer(t, s)
		ctx := context.Background()
		pa, pb := e.pin(t, e.a), e.pin(t, e.b)
		if pa != pb || !strings.HasPrefix(pa, "sha256:") {
			t.Fatalf("pins differ across tenants: %q vs %q", pa, pb)
		}
		if again := e.pin(t, e.a); again != pa {
			t.Fatalf("pin changed on second call")
		}
		cols, err := e.d.OwnerStrings(ctx, `SELECT column_name FROM information_schema.columns WHERE table_name = 'fleet_server_ca'`)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cols {
			if c == "tenant_id" {
				t.Fatal("fleet_server_ca has a tenant_id column")
			}
		}
		rows, err := e.d.OwnerStrings(ctx, `SELECT encode(cert_der, 'hex') FROM public.fleet_server_ca WHERE state = 'active'`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("active rows %v err %v", rows, err)
		}
		der := make([]byte, len(rows[0])/2)
		for i := range der {
			var b byte
			for _, h := range rows[0][2*i : 2*i+2] {
				b <<= 4
				b |= byte(strings.IndexRune("0123456789abcdef", h))
			}
			der[i] = b
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if !c.IsCA || c.MaxPathLen != 0 || !c.MaxPathLenZero || c.KeyUsage != x509.KeyUsageCertSign ||
			len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
			c.PublicKey.(*ecdsa.PublicKey).Curve != elliptic.P384() {
			t.Fatalf("server CA shape: %+v", c)
		}
		if fleetsql.PinOf(c) != pa {
			t.Fatal("pin is not the CA's SPKI hash")
		}
		// The server CA is not a tenant CA: TenantCAs never returns it.
		tcas, err := e.enr.TenantCAs(ctx, e.a)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range tcas {
			if fleetsql.PinOf(tc) == pa {
				t.Fatal("server CA is in TenantCAs")
			}
		}
	})
}

// Obligation 7 / TM-D29 (a) and (b) at installation scope: a retired row holds no key, a blob cannot be
// replayed into it, and it cannot become active again.
func TestServerCARetireRollback(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupServer(t, s)
		ctx := context.Background()
		e.pin(t, e.a)
		mustFail := func(what, sql string) {
			t.Helper()
			if err := e.d.ExecOwner(ctx, sql); err == nil {
				t.Fatalf("%s: accepted", what)
			}
		}
		mustFail("retire keeping the key", `UPDATE public.fleet_server_ca SET state = 'retired'`)
		mustFail("change the sealed key in place", `UPDATE public.fleet_server_ca SET sealed_key = decode(repeat('ab', 40), 'hex')`)
		mustFail("change the certificate", `UPDATE public.fleet_server_ca SET cert_der = decode(repeat('ab', 80), 'hex')`)
		mustFail("second active row", `INSERT INTO public.fleet_server_ca (cert_der, spki_sha256, sealed_key, key_version, not_after)
			VALUES (decode(repeat('ab', 80), 'hex'), decode(repeat('cd', 32), 'hex'), decode(repeat('ab', 40), 'hex'), 1, now())`)
		app, err := e.d.App(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer app.Close(ctx)
		if _, err := app.Exec(ctx, `DELETE FROM public.fleet_server_ca`); err == nil {
			t.Fatal("the runtime role can delete the server CA")
		}
		if err := e.d.ExecOwner(ctx, `UPDATE public.fleet_server_ca SET state = 'retired', sealed_key = NULL`); err != nil {
			t.Fatalf("retire: %v", err)
		}
		mustFail("replay a blob into the retired row", `UPDATE public.fleet_server_ca SET sealed_key = decode(repeat('ab', 40), 'hex')`)
		mustFail("reactivate", `UPDATE public.fleet_server_ca SET state = 'active'`)
		mustFail("reactivate with a key", `UPDATE public.fleet_server_ca SET state = 'active', sealed_key = decode(repeat('ab', 40), 'hex')`)
		// With no active CA nothing is signed and nothing is created silently: a new server CA changes the pin
		// of the whole installation, so it is the rollover's step-up action (RotateServerCA), not a side effect.
		if _, err := e.enr.SignServerLeaf(ctx, []string{"fleet.example.test"}); !errors.Is(err, fleetsql.ErrServerCAUnavailable) {
			t.Fatalf("no active CA: %v", err)
		}
	})
}

func signOK(t *testing.T, e *serverEnv, names ...string) tls.Certificate {
	t.Helper()
	c, err := e.enr.SignServerLeaf(context.Background(), names)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// AC2: the output of SignServerLeaf, table-tested.
func TestSignServerLeafOutput(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupServer(t, s)
		now := time.Now()
		cases := []struct {
			name  string
			names []string
			dns   []string
			ips   []net.IP
		}{
			{"dns, case-folded", []string{"FLEET.example.test"}, []string{"fleet.example.test"}, nil},
			{"ip", []string{"203.0.113.7"}, nil, []net.IP{net.ParseIP("203.0.113.7")}},
			{"both, duplicate dropped", []string{"fleet.example.test", "203.0.113.7", "fleet.example.test"}, []string{"fleet.example.test"}, []net.IP{net.ParseIP("203.0.113.7")}},
		}
		pin := e.pin(t, e.a)
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cert := signOK(t, e, tc.names...)
				if len(cert.Certificate) != 2 {
					t.Fatalf("chain length %d, want 2 (leaf, server CA)", len(cert.Certificate))
				}
				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				ca, err := x509.ParseCertificate(cert.Certificate[1])
				if err != nil {
					t.Fatal(err)
				}
				if fleetsql.PinOf(ca) != pin {
					t.Fatal("chain CA is not the pinned server CA")
				}
				if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0 {
					t.Fatalf("EKU %v", leaf.ExtKeyUsage)
				}
				if leaf.IsCA || len(leaf.URIs) != 0 || len(leaf.EmailAddresses) != 0 || leaf.Subject.String() != "" || leaf.KeyUsage != x509.KeyUsageDigitalSignature {
					t.Fatalf("leaf shape: ca=%v uris=%v subject=%q ku=%v", leaf.IsCA, leaf.URIs, leaf.Subject, leaf.KeyUsage)
				}
				if len(leaf.DNSNames) != len(tc.dns) || len(leaf.IPAddresses) != len(tc.ips) {
					t.Fatalf("SAN %v %v", leaf.DNSNames, leaf.IPAddresses)
				}
				for i, d := range tc.dns {
					if leaf.DNSNames[i] != d {
						t.Fatalf("dns %v", leaf.DNSNames)
					}
				}
				for i, ip := range tc.ips {
					if !leaf.IPAddresses[i].Equal(ip) {
						t.Fatalf("ip %v", leaf.IPAddresses)
					}
				}
				if d := leaf.NotAfter.Sub(now); d > fleetsql.ServerLeafTTL+time.Minute || d <= 0 || leaf.NotAfter.After(ca.NotAfter) {
					t.Fatalf("lifetime %v", d)
				}
				if now.Sub(leaf.NotBefore) > 5*time.Minute+time.Minute {
					t.Fatalf("NotBefore backdated %v", now.Sub(leaf.NotBefore))
				}
				if leaf.SignatureAlgorithm != x509.ECDSAWithSHA384 || len(leaf.SubjectKeyId) == 0 || string(leaf.AuthorityKeyId) != string(ca.SubjectKeyId) {
					t.Fatalf("sig %v ski %x aki %x", leaf.SignatureAlgorithm, leaf.SubjectKeyId, leaf.AuthorityKeyId)
				}
				k, ok := leaf.PublicKey.(*ecdsa.PublicKey)
				if !ok || k.Curve != elliptic.P256() || !k.Equal(&cert.PrivateKey.(*ecdsa.PrivateKey).PublicKey) {
					t.Fatal("leaf key is not the P-256 key returned with it")
				}
				if leaf.SerialNumber.Sign() <= 0 || leaf.SerialNumber.BitLen() > 128 {
					t.Fatalf("serial %v", leaf.SerialNumber)
				}
				// It verifies as a server certificate for each name, and not as a client one.
				roots := x509.NewCertPool()
				roots.AddCert(ca)
				for _, n := range tc.names {
					if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: n, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
						t.Fatalf("verify %s: %v", n, err)
					}
				}
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
					t.Fatal("server leaf verifies for ClientAuth")
				}
				// Each leaf has its own key and serial.
				other := signOK(t, e, tc.names...)
				ol, _ := x509.ParseCertificate(other.Certificate[0])
				if ol.SerialNumber.Cmp(leaf.SerialNumber) == 0 || ol.PublicKey.(*ecdsa.PublicKey).Equal(leaf.PublicKey) {
					t.Fatal("two leaves share a serial or key")
				}
			})
		}
		// Each issuance is audited with names, serial, not_after and the CA pin.
		e.ca.mu.Lock()
		defer e.ca.mu.Unlock()
		if len(e.ca.evs) == 0 {
			t.Fatal("no issuance audit")
		}
		ev := e.ca.evs[0]
		if ev.Kind != "fleet.server_cert.issued" || ev.Serial == "" || ev.NotAfter.IsZero() || ev.CASPKIPin != pin || len(ev.Names) == 0 {
			t.Fatalf("audit event %+v", ev)
		}
	})
}

// AC2: every refusal of ADR-0008 item 7 and obligation 3.
func TestSignServerLeafRefusals(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupServer(t, s)
		ctx := context.Background()
		e.enr.Endpoints = append(e.enr.Endpoints,
			fleetsql.Endpoint{Host: "127.0.0.1", Port: 1}, fleetsql.Endpoint{Host: "169.254.1.1", Port: 1},
			fleetsql.Endpoint{Host: "0.0.0.0", Port: 1}, fleetsql.Endpoint{Host: "*.example.test", Port: 1},
			fleetsql.Endpoint{Host: "fleet.example.test.", Port: 1}, fleetsql.Endpoint{Host: "::1", Port: 1})
		long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".test"
		e.enr.Endpoints = append(e.enr.Endpoints, fleetsql.Endpoint{Host: long, Port: 1})
		names := map[string][]string{
			"nil":                     nil,
			"empty list":              {},
			"empty name":              {""},
			"not in the endpoint set": {"evil.example.test"},
			"ip not in set":           {"203.0.113.8"},
			"wildcard":                {"*.example.test"},
			"trailing dot":            {"fleet.example.test."},
			"loopback":                {"127.0.0.1"},
			"loopback v6":             {"::1"},
			"link-local":              {"169.254.1.1"},
			"unspecified":             {"0.0.0.0"},
			"too long":                {long},
			"one bad among good":      {"fleet.example.test", "evil.example.test"},
			"space":                   {" fleet.example.test"},
			"too many":                {"a", "b", "c", "d", "e", "f", "g", "h", "i"},
		}
		for n, in := range names {
			t.Run(n, func(t *testing.T) {
				if _, err := e.enr.SignServerLeaf(ctx, in); !errors.Is(err, fleetsql.ErrServerNames) {
					t.Fatalf("got %v, want ErrServerNames", err)
				}
			})
		}
		if len(e.ca.evs) != 0 {
			t.Fatal("a refused request was audited as issued")
		}
	})
}

func TestSignServerLeafCAConditions(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		good := []string{"fleet.example.test"}

		t.Run("near expiry is refused and alerted", func(t *testing.T) {
			e := setupServer(t, s)
			e.pin(t, e.a)
			base := time.Now()
			e.enr.Clock = func() time.Time { return base.Add(10*365*24*time.Hour - 80*24*time.Hour) }
			if _, err := e.enr.SignServerLeaf(ctx, good); !errors.Is(err, fleetsql.ErrServerCAExpiring) {
				t.Fatalf("got %v", err)
			}
			if !e.al.has(fleetsql.AlertServerCAExpiring) {
				t.Fatal("no expiry alert")
			}
		})
		t.Run("within a year alerts but issues, clamped", func(t *testing.T) {
			e := setupServer(t, s)
			e.pin(t, e.a)
			base := time.Now()
			e.enr.Clock = func() time.Time { return base.Add(10*365*24*time.Hour - 200*24*time.Hour) }
			c, err := e.enr.SignServerLeaf(ctx, good)
			if err != nil {
				t.Fatal(err)
			}
			leaf, _ := x509.ParseCertificate(c.Certificate[0])
			ca, _ := x509.ParseCertificate(c.Certificate[1])
			if leaf.NotAfter.After(ca.NotAfter) {
				t.Fatal("leaf outlives the CA")
			}
			if !e.al.has(fleetsql.AlertServerCAExpiring) {
				t.Fatal("no one-year alert")
			}
		})
		t.Run("tampered sealed key", func(t *testing.T) {
			e := setupServer(t, s)
			e.pin(t, e.a)
			// Moving a blob between cells: seal the same plaintext key under another row id is impossible
			// from here, so corrupt the blob in place (owner role, guard off), as a database attacker would.
			if err := e.d.ExecOwner(ctx, `ALTER TABLE public.fleet_server_ca DISABLE TRIGGER fleet_server_ca_guard`); err != nil {
				t.Fatal(err)
			}
			if err := e.d.ExecOwner(ctx, `UPDATE public.fleet_server_ca SET sealed_key = set_byte(sealed_key, length(sealed_key) - 3, get_byte(sealed_key, length(sealed_key) - 3) # 255)`); err != nil {
				t.Fatal(err)
			}
			_, err := e.enr.SignServerLeaf(ctx, good)
			if !errors.Is(err, fleetsql.ErrServerCAUnavailable) {
				t.Fatalf("got %v", err)
			}
		})
		t.Run("stored certificate that is not a server CA", func(t *testing.T) {
			e := setupServer(t, s)
			e.pin(t, e.a)
			if err := e.d.ExecOwner(ctx, `ALTER TABLE public.fleet_server_ca DISABLE TRIGGER fleet_server_ca_guard`); err != nil {
				t.Fatal(err)
			}
			if err := e.d.ExecOwner(ctx, `UPDATE public.fleet_server_ca SET cert_der = decode(repeat('ab', 80), 'hex')`); err != nil {
				t.Fatal(err)
			}
			if _, err := e.enr.SignServerLeaf(ctx, good); !errors.Is(err, fleetsql.ErrServerCAUnavailable) {
				t.Fatalf("got %v", err)
			}
			if !e.al.has(fleetsql.AlertServerCAMaterial) {
				t.Fatal("no material alert")
			}
		})
		t.Run("installation key outage", func(t *testing.T) {
			e := setupServer(t, s)
			e.pin(t, e.a)
			e.kms.SetDown(true)
			if _, err := e.enr.SignServerLeaf(ctx, good); !errors.Is(err, fleetsql.ErrServerCAUnavailable) {
				t.Fatalf("got %v", err)
			}
		})
		t.Run("audit failure returns no certificate", func(t *testing.T) {
			e := setupServer(t, s)
			e.ca.fail = true
			c, err := e.enr.SignServerLeaf(ctx, good)
			if err == nil || len(c.Certificate) != 0 || c.PrivateKey != nil {
				t.Fatalf("got %v / %v", c, err)
			}
		})
		t.Run("rate cap per node", func(t *testing.T) {
			e := setupServer(t, s)
			var last error
			n := 0
			for ; n < 40; n++ {
				if _, last = e.enr.SignServerLeaf(ctx, good); last != nil {
					break
				}
			}
			if !errors.Is(last, fleetsql.ErrServerLeafRate) || n != 12 {
				t.Fatalf("after %d issuances: %v", n, last)
			}
		})
		t.Run("not configured", func(t *testing.T) {
			e := setupServer(t, s)
			e.enr.InstallationKeys = nil
			if _, err := e.enr.SignServerLeaf(ctx, good); !errors.Is(err, fleetsql.ErrNotConfigured) {
				t.Fatalf("got %v", err)
			}
		})
	})
}

// FCS-1 behaviour: only SignServerLeaf (and the creation of the CA) unseals the installation key. Pin
// reads, tenant CA reads and component enrolment never do.
func TestServerCAKeyUsedOnlyBySignServerLeaf(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupServer(t, s)
		ctx := context.Background()
		e.pin(t, e.a) // creates the CA: one unseal for sealing the new key
		base := e.ia.unseals()
		e.pin(t, e.b)
		e.initCA(t, e.a)
		if _, err := e.enr.TenantCAs(ctx, e.a); err != nil {
			t.Fatal(err)
		}
		iss := e.issue(t, e.a, fleetsql.KindConnector)
		csr, _ := csrFor(t, nil)
		if _, err := e.enr.Enroll(ctx, peerIP, iss.Token.String(), csr); err != nil {
			t.Fatal(err)
		}
		if got := e.ia.unseals(); got != base {
			t.Fatalf("installation key unsealed %d times by pin, tenant CA and enrol paths", got-base)
		}
		signOK(t, e, "fleet.example.test")
		if got := e.ia.unseals(); got != base+1 {
			t.Fatalf("one issuance made %d unseals, want 1", got-base)
		}
		for _, ev := range e.ia.evs {
			if ev.Reason != "fleet.server_ca" {
				t.Fatalf("unseal reason %q", ev.Reason)
			}
		}
	})
}
