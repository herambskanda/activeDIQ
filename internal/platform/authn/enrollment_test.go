package authn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type keySource struct {
	mu   sync.Mutex
	deks map[tenant.ID][]byte
}

func (k *keySource) DEK(_ context.Context, _ store.Tx, id tenant.ID, version uint32) (keys.DEK, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.deks == nil {
		k.deks = map[tenant.ID][]byte{}
	}
	if k.deks[id] == nil {
		b := make([]byte, keys.DEKSize)
		_, _ = rand.Read(b)
		k.deks[id] = b
	}
	if version == 0 {
		version = 1
	}
	return keys.DEKFromBytes(version, append([]byte(nil), k.deks[id]...))
}

type env struct {
	db   *store.DB
	d    *storetest.Database
	a, b tenant.ID
	svc  *Service
	now  time.Time
}

func setup(t *testing.T, s *storetest.Server) *env {
	t.Helper()
	d := s.NewDatabase(t)
	d.Migrate(t)
	db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	e := &env{db: db, d: d, now: time.Now().Truncate(time.Second)}
	e.a = tenanttest.Seed(t, d.ExecOwner, "A")
	e.b = tenanttest.Seed(t, d.ExecOwner, "B")
	e.svc = &Service{Keys: &keySource{}, Failures: db, Now: func() time.Time { return e.now }}
	return e
}

func (e *env) tx(t *testing.T, tid tenant.ID, fn func(ctx context.Context, tx store.Tx) error) error {
	t.Helper()
	return e.db.WithTenant(context.Background(), tid, fn)
}

const acct = "0b3f2f9e-6a1c-4c53-9a53-3a7a3f5f1c01"

// enrol creates an active enrollment and returns its id and seed bytes.
func (e *env) enrol(t *testing.T, tid tenant.ID) (string, []byte) {
	t.Helper()
	var id string
	var seed []byte
	err := e.tx(t, tid, func(ctx context.Context, tx store.Tx) error {
		p, err := e.svc.Enroll(ctx, tx, tid, Subject{AccountID: acct}, "phone")
		if err != nil {
			return err
		}
		id = p.ID
		p.Seed.Expose(func(b []byte) {
			seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(b))
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// Its own transaction: the attempt is charged in a separate one, which sees only committed rows.
	if err := e.tx(t, tid, func(ctx context.Context, tx store.Tx) error {
		return e.svc.Activate(ctx, tx, tid, id, hotp(seed, stepAt(e.now)))
	}); err != nil {
		t.Fatal(err)
	}
	return id, seed
}

// exec runs one statement as the application role inside the tenant's transaction.
func (e *env) exec(t *testing.T, tid tenant.ID, sql string, args ...any) (int64, error) {
	t.Helper()
	var n int64
	err := e.tx(t, tid, func(ctx context.Context, tx store.Tx) error {
		tag, err := tx.Exec(ctx, sql, args...)
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

func (e *env) verify(t *testing.T, tid tenant.ID, id, code string) error {
	t.Helper()
	var got error
	err := e.tx(t, tid, func(ctx context.Context, tx store.Tx) error {
		got = e.svc.Verify(ctx, tx, tid, id, code)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func Test_totp_code_not_reusable(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, seed := e.enrol(t, e.a) // the activation code spent the current step
		cur := stepAt(e.now)

		// The activation code itself cannot be replayed as a login.
		if err := e.verify(t, e.a, id, hotp(seed, cur)); !errors.Is(err, ErrCodeReplayed) {
			t.Fatalf("activation code reused: %v", err)
		}
		// A next-step code verifies once, then never again, now or later in its window.
		next := hotp(seed, cur+1)
		if err := e.verify(t, e.a, id, next); err != nil {
			t.Fatalf("fresh code: %v", err)
		}
		if err := e.verify(t, e.a, id, next); !errors.Is(err, ErrCodeReplayed) {
			t.Fatalf("same code twice: %v", err)
		}
		e.now = e.now.Add(StepSeconds * time.Second)
		if err := e.verify(t, e.a, id, next); !errors.Is(err, ErrCodeReplayed) {
			t.Fatalf("same code in the next step: %v", err)
		}
		// An older in-window code is also spent once a later step was used.
		if err := e.verify(t, e.a, id, hotp(seed, cur)); !errors.Is(err, ErrCodeReplayed) {
			t.Fatalf("older code after a later one: %v", err)
		}
		// A genuinely later code still works.
		if err := e.verify(t, e.a, id, hotp(seed, cur+2)); err != nil {
			t.Fatalf("later code: %v", err)
		}
	})
}

func Test_totp_code_not_reusable_concurrent(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, seed := e.enrol(t, e.a)
		code := hotp(seed, stepAt(e.now)+1)
		const n = 8
		var wg sync.WaitGroup
		res := make([]error, n)
		for i := range res {
			wg.Add(1)
			go func() { defer wg.Done(); res[i] = e.verify(t, e.a, id, code) }()
		}
		wg.Wait()
		ok := 0
		for _, err := range res {
			if err == nil {
				ok++
			}
		}
		if ok != 1 {
			t.Fatalf("%d of %d concurrent submissions of one code verified: %v", ok, n, res)
		}
	})
}

func Test_totp_window_through_store(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, seed := e.enrol(t, e.a)
		cur := stepAt(e.now)
		for _, off := range []int64{-3, -2, 2, 3} {
			if err := e.verify(t, e.a, id, hotp(seed, cur+off)); !errors.Is(err, ErrCodeRejected) {
				t.Errorf("offset %d: %v", off, err)
			}
		}
		if err := e.verify(t, e.a, id, "12345"); !errors.Is(err, ErrCodeRejected) {
			t.Errorf("short code: %v", err)
		}
		if err := e.verify(t, e.a, id, hotp(seed, cur+1)); err != nil { // +1 is inside the window
			t.Errorf("offset +1: %v", err)
		}
	})
}

func Test_totp_pending_cannot_login_and_revoked_cannot_verify(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		var id string
		var seed []byte
		_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			p, err := e.svc.Enroll(ctx, tx, e.a, Subject{AccountID: acct}, "phone")
			if err != nil {
				t.Fatal(err)
			}
			id = p.ID
			p.Seed.Expose(func(b []byte) { seed, _ = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(b)) })
			return nil
		})
		if err := e.verify(t, e.a, id, hotp(seed, stepAt(e.now))); !errors.Is(err, ErrCodeRejected) {
			t.Fatalf("pending enrollment verified a login: %v", err)
		}
		for _, st := range []string{"active", "revoked"} {
			if n, err := e.exec(t, e.a, `UPDATE public.authn_authenticator_enrollments SET state = $2 WHERE id = $1::uuid`, id, st); err != nil || n != 1 {
				t.Fatalf("-> %s: %d rows, %v", st, n, err)
			}
		}
		if err := e.verify(t, e.a, id, hotp(seed, stepAt(e.now))); !errors.Is(err, ErrCodeRejected) {
			t.Fatalf("revoked enrollment verified: %v", err)
		}
		if _, err := e.exec(t, e.a, `UPDATE public.authn_authenticator_enrollments SET state = 'active' WHERE id = $1::uuid`, id); err == nil {
			t.Fatal("revoked -> active was allowed")
		}
	})
}

func Test_totp_seed_sealed_never_returned(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		id, seed := e.enrol(t, e.a)

		// Nothing readable carries the seed: Get has no field for it, and printing Info (every verb)
		// shows no seed text.
		var in Info
		_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			var err error
			in, err = e.svc.Get(ctx, tx, id)
			return err
		})
		b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
		for _, out := range []string{fmt.Sprintf("%v", in), fmt.Sprintf("%+v", in), fmt.Sprintf("%#v", in)} {
			if strings.Contains(out, b32) || strings.Contains(out, string(seed)) {
				t.Fatalf("Info shows the seed: %s", out)
			}
		}
		if in.State != StateActive || in.Method != "totp" || in.Subject.AccountID != acct || in.LastUsed == nil {
			t.Fatalf("Info = %+v", in)
		}

		// The Provisioned seed prints redacted.
		var p Provisioned
		_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			var err error
			p, err = e.svc.Enroll(ctx, tx, e.a, Subject{AccountID: acct}, "second")
			return err
		})
		if got := fmt.Sprintf("%v %+v %#v", p, p, p); strings.Contains(got, "=") && !strings.Contains(got, "REDACTED") {
			t.Fatalf("seed not redacted: %s", got)
		}

		// The stored value is sealed: it is not the seed, contains no seed bytes, and does not open
		// under another tenant, row or column.
		var blob []byte
		var ver int32
		_ = e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT sealed_secret, key_version FROM public.authn_authenticator_enrollments WHERE id = $1::uuid`, id).Scan(&blob, &ver)
		})
		if bytes.Contains(blob, seed) || bytes.Contains(blob, []byte(b32)) {
			t.Fatal("the stored value contains the seed in clear")
		}
		ks := e.svc.Keys
		dek, _ := ks.DEK(context.Background(), nil, e.a, uint32(ver))
		defer dek.Destroy()
		if got, err := keys.Open(dek, rowContext(e.a, id, uint32(ver)), blob); err != nil || !bytes.Equal(got, seed) {
			t.Fatalf("own context does not open: %v", err)
		}
		other := "0b3f2f9e-6a1c-4c53-9a53-3a7a3f5f1c02"
		for name, c := range map[string]keys.Context{
			"row":    rowContext(e.a, other, uint32(ver)),
			"tenant": rowContext(e.b, id, uint32(ver)),
			"column": {Tenant: e.a, Table: enrollTable, Row: id, Column: "label", Version: uint32(ver)},
			"table":  {Tenant: e.a, Table: "fleet_ca", Row: id, Column: sealedColumn, Version: uint32(ver)},
		} {
			if _, err := keys.Open(dek, c, blob); err == nil {
				t.Errorf("blob opened under another %s", name)
			}
		}

		// The sealed column cannot be rewritten (a blob moved between rows would not open anyway).
		id2 := p.ID
		if _, err := e.exec(t, e.a, `UPDATE public.authn_authenticator_enrollments SET sealed_secret = $2 WHERE id = $1::uuid`, id2, blob); err == nil {
			t.Fatal("the seed column is not immutable")
		}

		// Tenant isolation: tenant B cannot see or verify tenant A's enrollment.
		if err := e.verify(t, e.b, id, hotp(seed, stepAt(e.now)+1)); !errors.Is(err, ErrCodeRejected) {
			t.Fatalf("cross-tenant verify: %v", err)
		}
	})
}

func Test_totp_enroll_input(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		for name, sub := range map[string]Subject{
			"empty":       {},
			"both":        {AccountID: acct, ConnectionID: acct, ObjectGUID: acct},
			"dn":          {ConnectionID: acct, ObjectGUID: "CN=x,DC=y"},
			"conn only":   {ConnectionID: acct},
			"bad account": {AccountID: "nope"},
			"nil account": {AccountID: "00000000-0000-0000-0000-000000000000"},
		} {
			err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
				_, err := e.svc.Enroll(ctx, tx, e.a, sub, "x")
				return err
			})
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("%s: %v", name, err)
			}
		}
		// A directory user subject is accepted.
		err := e.tx(t, e.a, func(ctx context.Context, tx store.Tx) error {
			_, err := e.svc.Enroll(ctx, tx, e.a, Subject{ConnectionID: acct, ObjectGUID: "0b3f2f9e-6a1c-4c53-9a53-3a7a3f5f1c09"}, "x")
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}
