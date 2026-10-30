package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 default HMAC for authenticator apps
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

// testKeys is a tenant DEK source over an in-memory KEK, for composition tests that never reach a key.
func testKeys() authn.KeySource { return keys.NewStore(keystest.New("kek-1")).KeySource() }

func totpCode(seed []byte, at time.Time) string {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(at.Unix()/30))
	m := hmac.New(sha1.New, seed)
	m.Write(c[:])
	h := m.Sum(nil)
	o := h[len(h)-1] & 0x0f
	v := (binary.BigEndian.Uint32(h[o:o+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", v)
}

// The composed server-role console stack verifies a TOTP code in StepUp.Reverify through the store-backed
// tenant DEK source, and fails closed, with no key detail, for a failed unwrap. A shredded DEK or an
// unavailable KEK provider under a live enrolment is pinned by TestReverifyFailsClosedWithoutUsableDEK.
func TestReverifyInTheServerRoleUsesTheTenantDEK(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		d := s.NewDatabase(t)
		d.Migrate(t)
		db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		kms := keystest.New("kek-1")
		ks := keys.NewStore(kms)
		console, err := buildConsole(db, nopSink{}, ks.KeySource(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if console.StepUp.TOTP == nil || console.StepUp.TOTP.Keys == nil || console.StepUp.TOTP.Failures == nil {
			t.Fatalf("TOTP service not composed: %+v", console.StepUp.TOTP)
		}
		withKey, noKey := tenanttest.Seed(t, d.ExecOwner, "A"), tenanttest.Seed(t, d.ExecOwner, "B")
		if err := db.WithTenant(ctx, withKey, func(ctx context.Context, tx store.Tx) error { return ks.Provision(ctx, tx, withKey) }); err != nil {
			t.Fatal(err)
		}

		accts, err := authn.NewAccounts(db, console.Sessions, rbac.Owners{})
		if err != nil {
			t.Fatal(err)
		}
		sys := authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}
		session := func(tn tenant.ID) (authn.CreateResult, string) {
			a, err := accts.Create(ctx, authn.NewAccount{Tenant: tn, Kind: authn.KindLocal, DisplayName: "u", CreatedBy: "system"})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := accts.SetState(ctx, tn, a.ID, authn.AccountActive, sys); err != nil {
				t.Fatal(err)
			}
			ep, err := console.Sessions.Epoch(ctx, tn, a.ID)
			if err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-time.Hour)
			res, err := console.Sessions.Create(ctx, authn.CreateInput{Tenant: tn, Account: a.ID, Methods: []string{"password", "totp"},
				MFAAt: &old, AuthorityFactorAt: &old, ClientIP: netip.MustParseAddr("192.0.2.7"), Epoch: ep})
			if err != nil {
				t.Fatal(err)
			}
			return res, a.ID
		}
		mfaAt := func(tn tenant.ID, id string) (at time.Time) {
			if err := db.WithTenant(ctx, tn, func(ctx context.Context, tx store.Tx) error {
				return tx.QueryRow(ctx, `SELECT mfa_at FROM public.authn_sessions WHERE id = $1::uuid`, id).Scan(&at)
			}); err != nil {
				t.Fatal(err)
			}
			return at
		}

		// Enrolled user: Enroll + Activate seal and open the seed under the tenant DEK.
		res, acct := session(withKey)
		var seed []byte
		var eid string
		if err := db.WithTenant(ctx, withKey, func(ctx context.Context, tx store.Tx) error {
			p, err := console.StepUp.TOTP.Enroll(ctx, tx, withKey, authn.Subject{AccountID: acct}, "phone")
			if err != nil {
				return err
			}
			eid = p.ID
			p.Seed.Expose(func(b []byte) { seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(b)) })
			return err
		}); err != nil {
			t.Fatal(err)
		}
		activation := time.Now()
		if err := db.WithTenant(ctx, withKey, func(ctx context.Context, tx store.Tx) error {
			return console.StepUp.TOTP.Activate(ctx, tx, withKey, eid, totpCode(seed, activation))
		}); err != nil {
			t.Fatal(err)
		}

		// A wrong code is refused; the right code of a later step re-verifies and moves mfa_at.
		before := mfaAt(withKey, res.Session.ID)
		if _, err := console.StepUp.Reverify(ctx, res.Token, "000000"); !errors.Is(err, authn.ErrStepUpRefused) {
			t.Fatalf("wrong code = %v, want ErrStepUpRefused", err)
		}
		next := activation.Add(30 * time.Second)
		if time.Now().Before(next) {
			// Same step as Activate would be a replay; use the following step's code only once it is
			// acceptable (the verifier allows one step of skew ahead).
			next = time.Now().Add(30 * time.Second)
		}
		got, err := console.StepUp.Reverify(ctx, res.Token, totpCode(seed, next))
		if err != nil {
			t.Fatalf("Reverify with a good code in the server role: %v", err)
		}
		if got.MFAAt == nil || !got.MFAAt.After(before) {
			t.Fatalf("mfa_at not advanced: %v -> %v", before, got.MFAAt)
		}

		// A failed unwrap (another KEK behind the same key id) fails closed with no key detail.
		other, err := buildConsole(db, nopSink{}, keys.NewStore(keystest.New("kek-1")).KeySource(), nil)
		if err != nil {
			t.Fatal(err)
		}
		mid := mfaAt(withKey, res.Session.ID)
		_, err = other.StepUp.Reverify(ctx, res.Token, totpCode(seed, next.Add(30*time.Second)))
		if err == nil {
			t.Fatal("Reverify succeeded although the DEK could not be unwrapped")
		}
		if !mfaAt(withKey, res.Session.ID).Equal(mid) {
			t.Error("mfa_at moved on an unwrap failure")
		}
		for _, leak := range []string{withKey.String(), eid, string(base32.StdEncoding.EncodeToString(seed)), "kek-1"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("error leaks %q: %v", leak, err)
			}
		}

		// A tenant with no key and therefore no enrolment: Reverify refuses before KeySource.DEK is ever
		// called, so this case does not exercise key failure (see TestReverifyFailsClosedWithoutUsableDEK).
		res2, _ := session(noKey)
		before2 := mfaAt(noKey, res2.Session.ID)
		if _, err = console.StepUp.Reverify(ctx, res2.Token, "123456"); err == nil {
			t.Fatal("Reverify succeeded for a tenant with no key")
		}
		if strings.Contains(err.Error(), noKey.String()) || !mfaAt(noKey, res2.Session.ID).Equal(before2) {
			t.Errorf("no-key tenant: %v", err)
		}
	})
}

// Under a live TOTP enrolment, a shredded tenant_keys row or an unavailable KEK provider makes the composed
// StepUp.Reverify fail closed with a bare keys code: mfa_at is unchanged and no tenant, enrolment or KEK id leaks.
func TestReverifyFailsClosedWithoutUsableDEK(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		for _, tc := range []struct {
			name, code string
			break_     func(t *testing.T, d *storetest.Database, kms *keystest.KMS)
		}{
			{"shredded", keys.KeyShredded, func(t *testing.T, d *storetest.Database, _ *keystest.KMS) {
				if err := d.ExecOwner(context.Background(), `ALTER TABLE public.tenant_keys NO FORCE ROW LEVEL SECURITY; UPDATE public.tenant_keys SET state = 'shredded', shredded_at = now(), wrapped_dek = '' WHERE true`); err != nil {
					t.Fatal(err)
				}
			}},
			{"provider down", keys.ProviderUnavailable, func(_ *testing.T, _ *storetest.Database, kms *keystest.KMS) { kms.SetDown(true) }},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				d := s.NewDatabase(t)
				d.Migrate(t)
				db, err := store.Open(ctx, store.Config{DSN: d.AppDSN()})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(db.Close)
				kms := keystest.New("kek-1")
				ks := keys.NewStore(kms)
				console, err := buildConsole(db, nopSink{}, ks.KeySource(), nil)
				if err != nil {
					t.Fatal(err)
				}
				tn := tenanttest.Seed(t, d.ExecOwner, "A")
				if err := db.WithTenant(ctx, tn, func(ctx context.Context, tx store.Tx) error { return ks.Provision(ctx, tx, tn) }); err != nil {
					t.Fatal(err)
				}
				accts, err := authn.NewAccounts(db, console.Sessions, rbac.Owners{})
				if err != nil {
					t.Fatal(err)
				}
				a, err := accts.Create(ctx, authn.NewAccount{Tenant: tn, Kind: authn.KindLocal, DisplayName: "u", CreatedBy: "system"})
				if err != nil {
					t.Fatal(err)
				}
				sys := authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}
				if _, err := accts.SetState(ctx, tn, a.ID, authn.AccountActive, sys); err != nil {
					t.Fatal(err)
				}
				ep, err := console.Sessions.Epoch(ctx, tn, a.ID)
				if err != nil {
					t.Fatal(err)
				}
				old := time.Now().Add(-time.Hour)
				res, err := console.Sessions.Create(ctx, authn.CreateInput{Tenant: tn, Account: a.ID, Methods: []string{"password", "totp"},
					MFAAt: &old, AuthorityFactorAt: &old, ClientIP: netip.MustParseAddr("192.0.2.7"), Epoch: ep})
				if err != nil {
					t.Fatal(err)
				}
				var seed []byte
				var eid string
				if err := db.WithTenant(ctx, tn, func(ctx context.Context, tx store.Tx) error {
					p, err := console.StepUp.TOTP.Enroll(ctx, tx, tn, authn.Subject{AccountID: a.ID}, "phone")
					if err != nil {
						return err
					}
					eid = p.ID
					p.Seed.Expose(func(b []byte) { seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(b)) })
					return err
				}); err != nil {
					t.Fatal(err)
				}
				activation := time.Now()
				if err := db.WithTenant(ctx, tn, func(ctx context.Context, tx store.Tx) error {
					return console.StepUp.TOTP.Activate(ctx, tx, tn, eid, totpCode(seed, activation))
				}); err != nil {
					t.Fatal(err)
				}
				mfaAt := func() (at time.Time) {
					if err := db.WithTenant(ctx, tn, func(ctx context.Context, tx store.Tx) error {
						return tx.QueryRow(ctx, `SELECT mfa_at FROM public.authn_sessions WHERE id = $1::uuid`, res.Session.ID).Scan(&at)
					}); err != nil {
						t.Fatal(err)
					}
					return at
				}

				tc.break_(t, d, kms)
				before := mfaAt()
				_, err = console.StepUp.Reverify(ctx, res.Token, totpCode(seed, activation.Add(30*time.Second)))
				if err == nil {
					t.Fatal("Reverify succeeded without a usable DEK")
				}
				if errors.Is(err, authn.ErrStepUpRefused) {
					t.Fatalf("refused as a wrong code, so the key path was never reached: %v", err)
				}
				if got := keys.Code(err); got != tc.code {
					t.Errorf("key code = %q, want %q (err %v)", got, tc.code, err)
				}
				if !mfaAt().Equal(before) {
					t.Error("mfa_at moved although the DEK was unusable")
				}
				for _, leak := range []string{tn.String(), eid, a.ID, "kek-1"} {
					if strings.Contains(err.Error(), leak) {
						t.Errorf("error leaks %q: %v", leak, err)
					}
				}
			})
		}
	})
}
