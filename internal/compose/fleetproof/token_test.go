package fleetproof

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/fleet/fleetsql"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type allowAll struct{}

func (allowAll) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}

type fresh struct{}

func (fresh) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }

type dekSource struct{ b []byte }

func (d dekSource) DEK(_ context.Context, _ store.Tx, _ tenant.ID, version uint32) (keys.DEK, error) {
	if version == 0 {
		version = 1
	}
	return keys.DEKFromBytes(version, append([]byte(nil), d.b...))
}

type quietAlerts struct{}

func (quietAlerts) Raise(context.Context, fleetsql.Alert) {}

type auditSink struct{}

func (auditSink) Append(_ context.Context, _ store.Tx, ev audit.Event) error { return ev.Validate() }

type tokenEnv struct {
	d   *storetest.Database
	tid tenant.ID
	enr *fleetsql.Enroller
	svc *fleetsql.Enrollment
}

func setupTokens(t *testing.T, s *storetest.Server) *tokenEnv {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	tid := tenanttest.Seed(t, d.ExecOwner, "A")
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	dek := make([]byte, 32)
	_, _ = rand.Read(dek)
	svc := &fleetsql.Enrollment{DB: db, Authz: allowAll{}, StepUp: fresh{},
		Limiter: fleetsql.NewMemoryLimiter(fleetsql.MemoryLimiterConfig{Burst: 1000})}
	enr := &fleetsql.Enroller{Enrollment: svc, Keys: dekSource{dek}, Alerts: quietAlerts{}, Audit: auditSink{},
		Endpoints: []fleetsql.Endpoint{{Host: "fleet.example.test", Port: 8443}}}
	return &tokenEnv{d: d, tid: tid, enr: enr, svc: svc}
}

func (e *tokenEnv) issue(t *testing.T) fleetsql.Issued {
	t.Helper()
	iss, err := e.svc.Issue(context.Background(), e.tid, apihost.Principal{ID: "human-1", Kind: apihost.KindSession, Tenant: e.tid.String()},
		fleetsql.NewComponent{Kind: fleetsql.KindConnector, Name: "branch-1"})
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func csr(t *testing.T) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

const source = "192.0.2.10:5555"

// TestEnrollmentTokenIsSingleUseAndExpires: TM-TB6-T1, TM-TB12-T1. Through Enroll itself, the call
// that mints the identity: a second use, sixteen racing uses and a use after expiry all fail with the
// one token-invalid answer, and issue no certificate.
func TestEnrollmentTokenIsSingleUseAndExpires(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setupTokens(t, s)
		ctx := context.Background()

		iss := e.issue(t)
		if _, err := e.enr.Enroll(ctx, source, iss.Token.String(), csr(t)); err != nil {
			t.Fatalf("first use: %v", err)
		}
		if got, err := e.enr.Enroll(ctx, source, iss.Token.String(), csr(t)); !errors.Is(err, fleetsql.ErrTokenInvalid) || len(got.LeafDER) != 0 {
			t.Fatalf("second use: %v (leaf %d bytes), want ErrTokenInvalid and no certificate", err, len(got.LeafDER))
		}

		iss = e.issue(t)
		var wins, losses atomic.Int32
		var wg sync.WaitGroup
		for i := range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := e.enr.Enroll(ctx, fmt.Sprintf("192.0.2.%d:1", i+1), iss.Token.String(), csr(t))
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, fleetsql.ErrTokenInvalid):
					losses.Add(1)
				default:
					t.Errorf("enroll: %v", err)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 || losses.Load() != 15 {
			t.Fatalf("racing uses: %d succeeded, %d refused; want exactly 1 and 15", wins.Load(), losses.Load())
		}

		iss = e.issue(t)
		adm, err := e.d.Admin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer adm.Close(ctx)
		// The database guard forbids writing expires_at; this test owns its database, so it ages the row
		// as the superuser.
		if _, err := adm.Exec(ctx, `ALTER TABLE public.enrollment_tokens DISABLE TRIGGER enrollment_tokens_guard`); err != nil {
			t.Fatal(err)
		}
		if tag, err := adm.Exec(ctx, `UPDATE public.enrollment_tokens SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = $1::uuid`, iss.TokenID); err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("age token: %v %v", tag, err)
		}
		if got, err := e.enr.Enroll(ctx, source, iss.Token.String(), csr(t)); !errors.Is(err, fleetsql.ErrTokenInvalid) || len(got.LeafDER) != 0 {
			t.Fatalf("expired token: %v, want ErrTokenInvalid and no certificate", err)
		}
	})
}
