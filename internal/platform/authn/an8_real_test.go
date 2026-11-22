package authn

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/apihost/apitypes"
	"github.com/skenzeriq/activediq/internal/platform/authn/api"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// an8Cap is the key table cap of the real target: small enough for FillTable to reach it in a few requests.
const an8Cap = 12

// passwordCookie adapts LocalCredentials to the handler's PasswordCookieBeginner the way
// httpx/authnhttp.PasswordCookies does (authn tests cannot import it: it imports authn).
type passwordCookie struct{ l *LocalCredentials }

func (p passwordCookie) BeginPasswordCookie(ctx context.Context, username string, pw secret.Secret, from netip.Addr) (string, error) {
	h, err := p.l.BeginPassword(ctx, username, pw, from)
	if err != nil {
		return "", err
	}
	return "__Host-adiq_pending=" + h.Reveal(), nil
}

// realAN8 is the real AN-8 handler (Handlers.SignInBreakGlassPassword over LocalCredentials) behind the
// an8Target seam: the shared store is a real PostgreSQL database (the store's port is *store.DB, which only
// PostgreSQL can stand behind), the clock is fixed, the key table is capped at an8Cap.
type realAN8 struct {
	t   *testing.T
	h   Handlers
	l   *LocalCredentials
	db  *store.DB
	ten tenant.ID
	mu  sync.Mutex
	now time.Time
	snk *recSink
}

// realAN8Target builds the real AN-8 handler behind the an8Target seam: the shared store faked only at
// its port (a throwaway PostgreSQL database), the clock fixed, the seed accounts present (Known active
// local with Password, NonLocal not local, Disabled local and disabled), the key table capped small
// enough for FillTable. It never returns ok=false: the handler exists.
func realAN8Target(t *testing.T, seed an8Seed) (an8Target, bool) {
	t.Helper()
	e := setup(t, storetest.One(t))
	r := &realAN8{t: t, db: e.db, ten: e.a, now: time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)}
	clock := func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
	sink := &recSink{}
	sess, err := New(Config{DB: e.db, Audit: sink, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	// The pending row's own trigger demands a created_at within 5 minutes of the database clock, so the
	// pending store keeps the real clock; everything the throttle decides runs on the fixed one.
	pend, err := NewPendingStore(e.db, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.snk = sink
	r.l = &LocalCredentials{DB: e.db, Sessions: sess, Pending: pend, Keys: e.svc.Keys, Audit: sink,
		Tenant: func() (tenant.ID, bool) { return e.a, true }, MaxKeys: an8Cap, LatencyFloor: -1, Clock: clock}
	r.h = Handlers{Password: passwordCookie{r.l}}

	ctx := context.Background()
	by := authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}
	mk := func(kind AccountKind, name string) string {
		var id string
		err := e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
			in := NewAccount{Tenant: e.a, Kind: kind, DisplayName: name, CreatedBy: "system", MFARequired: true}
			if kind == KindSSO {
				in.MFARequired = false
				in.SSOIssuer, in.SSOSubject = "https://idp.example", name
			}
			a, err := CreateIn(ctx, tx, in)
			id = a.ID
			return err
		})
		if err != nil {
			t.Fatalf("seed account %s: %v", name, err)
		}
		return id
	}
	pw := secret.FromBytes([]byte(seed.Password))
	known, disabled, nonLocal := mk(KindLocal, "Known"), mk(KindLocal, "Disabled"), mk(KindSSO, "NonLocal")
	err = e.db.WithTenant(ctx, e.a, func(ctx context.Context, tx store.Tx) error {
		if err := r.l.SetPassword(ctx, tx, e.a, known, seed.Known, pw, by); err != nil {
			return err
		}
		if err := r.l.SetPassword(ctx, tx, e.a, disabled, seed.Disabled, pw, by); err != nil {
			return err
		}
		h, err := hashPassword([]byte(seed.Password)) // a credential row on a non-local account
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.authn_local_credentials (tenant_id, account_id, username_norm, password_hash) VALUES ($1::uuid, $2::uuid, $3, $4)`,
			e.a.String(), nonLocal, seed.NonLocal, h); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE public.authn_accounts SET state = CASE WHEN id = $2::uuid THEN 'disabled' ELSE 'active' END WHERE tenant_id = $1::uuid AND id = ANY($3::uuid[])`,
			e.a.String(), disabled, []string{known, disabled, nonLocal})
		return err
	})
	if err != nil {
		t.Fatalf("seed credentials: %v", err)
	}
	return r, true
}

func (r *realAN8) Do(name, password, ip string) an8Resp {
	r.t.Helper()
	out, err := r.h.SignInBreakGlassPassword(context.Background(), api.SignInBreakGlassPasswordInput{
		PeerIP: ip, Body: api.BreakGlassPasswordRequest{Username: name, Password: secret.FromBytes([]byte(password))}})
	if err == nil {
		o, ok := out.(api.SignInBreakGlassPassword204)
		if !ok {
			r.t.Fatalf("unexpected success output %T", out)
		}
		return an8Resp{Status: 204, Headers: map[string][]string{"Set-Cookie": {o.SetCookie}}}
	}
	var p *apitypes.Problem
	if !errors.As(err, &p) {
		r.t.Fatalf("the handler returned a non-problem error: %v", err)
	}
	body, jerr := json.Marshal(p)
	if jerr != nil {
		r.t.Fatal(jerr)
	}
	return an8Resp{Status: int(p.Status), Body: string(body), Headers: map[string][]string{
		"Content-Type": {"application/problem+json"}, "Content-Length": {strconv.Itoa(len(body))}}}
}

func (r *realAN8) Advance(d time.Duration) { r.mu.Lock(); r.now = r.now.Add(d); r.mu.Unlock() }

func (r *realAN8) count(sql string) int {
	r.t.Helper()
	var n int
	err := r.db.WithTenant(context.Background(), r.ten, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, sql).Scan(&n)
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return n
}

func (r *realAN8) Pending() int { return r.count(`SELECT count(*) FROM public.authn_pending_signins`) }

func (r *realAN8) HashVerifications() int { return r.l.Verifications() }

func (r *realAN8) Keys() []string {
	r.t.Helper()
	var out []string
	err := r.db.WithTenant(context.Background(), r.ten, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, `SELECT encode(key_hash, 'hex') FROM public.authn_signin_throttle`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				return err
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

// FillTable makes unrelated names until the table holds an8Cap live keys.
func (r *realAN8) FillTable() {
	r.t.Helper()
	for i := 0; len(r.Keys()) < an8Cap; i++ {
		if i > 4*an8Cap {
			r.t.Fatal("the key table did not fill")
		}
		r.Do(fmt.Sprintf("filler-%d", i), an8Wrong, "192.0.2.77")
	}
}
