package authn

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type pendEnv struct {
	*env
	ten     tenant.ID
	pending *PendingStore
	sf      *SecondFactor
	sess    *Store
	accts   *Accounts
	account string
	seed    []byte
	sink    *recSink
}

func eachPending(t *testing.T, fn func(t *testing.T, e *pendEnv)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		base := setup(t, s)
		clock := func() time.Time { return base.now }
		sink := &recSink{}
		sess, err := New(Config{DB: base.db, Audit: sink, Clock: clock})
		if err != nil {
			t.Fatal(err)
		}
		ps, err := NewPendingStore(base.db, sink, clock)
		if err != nil {
			t.Fatal(err)
		}
		accts, err := NewAccounts(base.db, sess, rbac.Owners{})
		if err != nil {
			t.Fatal(err)
		}
		e := &pendEnv{env: base, ten: base.a, pending: ps, sess: sess, accts: accts, sink: sink,
			sf: &SecondFactor{DB: base.db, Pending: ps, Sessions: sess, TOTP: base.svc, Audit: sink}}
		a, err := accts.Create(context.Background(), NewAccount{Tenant: e.ten, Kind: KindLocal, DisplayName: "bg", CreatedBy: "system"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := accts.SetState(context.Background(), e.ten, a.ID, AccountActive, authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}); err != nil {
			t.Fatal(err)
		}
		e.account = a.ID
		e.enrolFor(t)
		fn(t, e)
	})
}

// enrolFor enrols and activates a TOTP factor for the account, then moves the clock past that code's
// step so the tests' own codes are fresh.
func (e *pendEnv) enrolFor(t *testing.T) {
	t.Helper()
	var id string
	err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
		p, err := e.svc.Enroll(ctx, tx, e.ten, Subject{AccountID: e.account}, "phone")
		if err != nil {
			return err
		}
		id = p.ID
		p.Seed.Expose(func(b []byte) { e.seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(b)) })
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
		return e.svc.Activate(ctx, tx, e.ten, id, hotp(e.seed, stepAt(e.now)))
	}); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(StepSeconds * time.Second)
}

func (e *pendEnv) begin(t *testing.T) PendingHandle {
	t.Helper()
	h, err := e.pending.Begin(context.Background(), BeginInput{Tenant: e.ten, Account: e.account, FirstFactor: FirstPassword, ClientIP: netip.MustParseAddr("192.0.2.7"), Epoch: epochOf(t, e.sess, e.ten, e.account)})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (e *pendEnv) good() string { return hotp(e.seed, stepAt(e.now)) }
func (e *pendEnv) bad() string  { return hotp(e.seed, stepAt(e.now)+1000) }

func (e *pendEnv) row(t *testing.T, col string) string {
	t.Helper()
	r := e.query(t, `SELECT `+col+`::text FROM public.authn_pending_signins`)
	if len(r) != 1 {
		t.Fatalf("read %s: %v", col, r)
	}
	return r[0]
}

// query reads through the tenant's RLS context, as the product does.
func (e *pendEnv) query(t *testing.T, sql string) []string {
	t.Helper()
	var out []string
	err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.Query(ctx, sql)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *pendEnv) sessions(t *testing.T) int {
	t.Helper()
	return mustInt(e.query(t, `SELECT count(*)::text FROM public.authn_sessions`)[0])
}

func mustInt(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func Test_pending_expires_5m(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		e.now = e.now.Add(PendingSignInTTL)
		if _, err := e.sf.VerifyTOTP(context.Background(), h, e.good(), netip.Addr{}); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("a correct code after 5 minutes: got %v, want ErrPendingInvalid", err)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions exist, want none", n)
		}
		if got := e.row(t, "state"); got != "dead" {
			t.Fatalf("state = %s, want dead", got)
		}
		// Inside the window it works (4 minutes: the session table refuses rows dated more than 5
		// minutes from the database clock, which this fake clock is ahead of).
		e.now = e.now.Add(-PendingSignInTTL)
		h2 := e.begin(t)
		e.now = e.now.Add(4 * time.Minute)
		if _, err := e.sf.VerifyTOTP(context.Background(), h2, e.good(), netip.Addr{}); err != nil {
			t.Fatalf("4m: %v", err)
		}
	})
}

func Test_pending_max_5_attempts(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		for i := 0; i < MaxSignInAttempts; i++ {
			if _, err := e.sf.VerifyTOTP(context.Background(), h, e.bad(), netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
				t.Fatalf("wrong code %d: got %v", i+1, err)
			}
		}
		if _, err := e.sf.VerifyTOTP(context.Background(), h, e.good(), netip.Addr{}); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("6th (correct) code: got %v, want ErrPendingInvalid", err)
		}
		if got := e.row(t, "state"); got != "dead" {
			t.Fatalf("state = %s, want dead", got)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions exist, want none", n)
		}
		// Dead stays dead.
		if _, err := e.sf.VerifyTOTP(context.Background(), h, e.good(), netip.Addr{}); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("after dead: %v", err)
		}
	})
}

func Test_pending_fifth_attempt_may_succeed(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		for i := 0; i < MaxSignInAttempts-1; i++ {
			_, _ = e.sf.VerifyTOTP(context.Background(), h, e.bad(), netip.Addr{})
		}
		if _, err := e.sf.VerifyTOTP(context.Background(), h, e.good(), netip.Addr{}); err != nil {
			t.Fatalf("5th attempt: %v", err)
		}
	})
}

func Test_pending_consumed_new_session_id(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		h := e.begin(t)
		res, err := e.sf.VerifyTOTP(ctx, h, e.good(), netip.Addr{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Token.Reveal() == h.Reveal() {
			t.Fatal("the session token equals the pending handle")
		}
		if res.Session.Account != e.account || len(res.Session.Methods) != 2 || res.Session.Methods[0] != "password" || res.Session.Methods[1] != "totp" || res.Session.MFAAt == nil {
			t.Fatalf("session = %+v", res.Session)
		}
		if _, err := e.sess.Lookup(ctx, res.Token); err != nil {
			t.Fatalf("the new session does not resolve: %v", err)
		}
		if _, err := e.sess.Lookup(ctx, h.tok); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("the pending handle resolved as a session: %v", err)
		}
		if got := e.row(t, "state"); got != "consumed" {
			t.Fatalf("state = %s, want consumed", got)
		}
		// Replay of the handle, with a fresh valid code, makes nothing.
		e.now = e.now.Add(StepSeconds * time.Second)
		if _, err := e.sf.VerifyTOTP(ctx, h, e.good(), netip.Addr{}); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("replay: got %v, want ErrPendingInvalid", err)
		}
		if n := e.sessions(t); n != 1 {
			t.Fatalf("%d sessions, want 1", n)
		}
		// A second sign-in gets a different session ID.
		h2 := e.begin(t)
		res2, err := e.sf.VerifyTOTP(ctx, h2, e.good(), netip.Addr{})
		if err != nil {
			t.Fatal(err)
		}
		if res2.Session.ID == res.Session.ID || res2.Token.Reveal() == res.Token.Reveal() {
			t.Fatal("two sign-ins share a session ID")
		}
	})
}

func Test_pending_stored_hashed_and_redacted(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		var raw []string
		for _, col := range []string{"handle_hash", "id", "account_id", "first_factor", "client_ip"} {
			raw = append(raw, e.row(t, col))
		}
		secretPart := h.Reveal()[37:]
		for _, v := range raw {
			if strings.Contains(v, secretPart) {
				t.Fatalf("a column holds the handle: %s", v)
			}
		}
		if strings.Contains(h.String(), secretPart) || strings.Contains(strings.TrimSpace(fmtSharp(h)), secretPart) {
			t.Fatal("handle prints its secret")
		}
	})
}

func fmtSharp(h PendingHandle) string { return h.GoString() }

func Test_pending_refused_when_account_not_active_or_unenrolled(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		h := e.begin(t)
		if _, err := e.accts.SetState(ctx, e.ten, e.account, AccountDisabled, authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.sf.VerifyTOTP(ctx, h, e.good(), netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("disabled account: %v", err)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions", n)
		}
	})
}

func Test_pending_double_submit_one_session(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		code := e.good()
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := e.sf.VerifyTOTP(context.Background(), h, code, netip.Addr{}); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 || e.sessions(t) != 1 {
			t.Fatalf("wins=%d sessions=%d, want 1 and 1", wins, e.sessions(t))
		}
	})
}

func Test_pending_table_guards(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		_, _ = e.sf.VerifyTOTP(context.Background(), h, e.bad(), netip.Addr{}) // one attempt charged
		for name, sql := range map[string]string{
			"lifetime over 5m": `UPDATE public.authn_pending_signins SET expires_at = expires_at + interval '1 hour'`,
			"attempts reset":   `UPDATE public.authn_pending_signins SET attempts = 0`,
			"attempts over 5":  `UPDATE public.authn_pending_signins SET attempts = 6`,
			"rebind account":   `UPDATE public.authn_pending_signins SET account_id = gen_random_uuid()`,
			"delete":           `DELETE FROM public.authn_pending_signins`,
			"minted over 5m":   `INSERT INTO public.authn_pending_signins (tenant_id, handle_hash, account_id, first_factor, created_at, expires_at) SELECT tenant_id, decode(repeat('ab', 32), 'hex'), account_id, 'password', now(), now() + interval '1 hour' FROM public.authn_pending_signins`,
			"minted consumed":  `INSERT INTO public.authn_pending_signins (tenant_id, handle_hash, account_id, first_factor, created_at, expires_at, state, ended_at) SELECT tenant_id, decode(repeat('cd', 32), 'hex'), account_id, 'password', now(), now() + interval '1 minute', 'consumed', now() FROM public.authn_pending_signins`,
		} {
			if _, err := e.exec(t, e.ten, sql); err == nil {
				t.Errorf("%s: the runtime role was allowed", name)
			}
		}
	})
}

// An end-user (AN-5) TOTP enrolment, keyed by the account's directory object, is gated only by the AD
// password. It must never satisfy the console second factor (TM §7.6 rule 1, DM-04.I2).
func Test_pending_refuses_end_user_enrolment(t *testing.T) {
	const conn, guid = "00000000-0000-4000-8000-0000000000c1", "11111111-2222-4333-8444-555555555555"
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		if err := fixtureAs(e.db, e.ten, `INSERT INTO public.connections (tenant_id, id, kind, display_name, credential_id, transport_security)
			VALUES ($1::uuid, $2::uuid, 'ad_forest', 'c', $3::uuid, 'ldaps')`, e.ten.String(), conn, conn); err != nil {
			t.Fatal(err)
		}
		a, err := e.accts.Create(ctx, NewAccount{Tenant: e.ten, Kind: KindDirectory, DisplayName: "ad", CreatedBy: "system",
			Ref: &DirectoryRef{ConnectionID: conn, ObjectGUID: guid}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.accts.SetState(ctx, e.ten, a.ID, AccountActive, authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}); err != nil {
			t.Fatal(err)
		}
		var id string
		var seed []byte
		if err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
			p, err := e.svc.Enroll(ctx, tx, e.ten, Subject{ConnectionID: conn, ObjectGUID: guid}, "phone")
			if err != nil {
				return err
			}
			id = p.ID
			p.Seed.Expose(func(b []byte) { seed, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(b)) })
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
			return e.svc.Activate(ctx, tx, e.ten, id, hotp(seed, stepAt(e.now)))
		}); err != nil {
			t.Fatal(err)
		}
		e.now = e.now.Add(StepSeconds * time.Second)
		h, err := e.pending.Begin(ctx, BeginInput{Tenant: e.ten, Account: a.ID, FirstFactor: FirstKerberos, ClientIP: netip.MustParseAddr("192.0.2.7"), Epoch: epochOf(t, e.sess, e.ten, a.ID)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.sf.VerifyTOTP(ctx, h, hotp(seed, stepAt(e.now)), netip.Addr{}); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatalf("end-user enrolment accepted as console second factor: %v", err)
		}
		if n := e.sessions(t); n != 0 {
			t.Fatalf("%d sessions", n)
		}
		if got := e.row(t, "attempts"); got != "1" {
			t.Fatalf("attempts = %s, want 1 (charged)", got)
		}
	})
}

func detailsOf(ev audit.Event) map[string]string {
	m := map[string]string{}
	for _, d := range ev.Details {
		m[d.Key] = d.Value
	}
	return m
}

var attackerIP = netip.MustParseAddr("198.51.100.9")

// T-0418 acceptance 1: five wrong codes are each audited, and the sixth records the dead pending
// sign-in with account, first factor and addresses.
func Test_pending_refusals_audited(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		h := e.begin(t)
		for i := 0; i < MaxSignInAttempts; i++ {
			if _, err := e.sf.VerifyTOTP(ctx, h, e.bad(), attackerIP); !errors.Is(err, ErrSecondFactorRefused) {
				t.Fatalf("wrong code %d: %v", i+1, err)
			}
		}
		evs := e.sink.of(KindSecondFactorRefused)
		if len(evs) != MaxSignInAttempts {
			t.Fatalf("%d refusal events after 5 wrong codes, want 5", len(evs))
		}
		if evs[0].Reason != RefusedWrongCode || evs[0].Outcome != audit.Denied {
			t.Errorf("first event = %+v", evs[0])
		}
		if _, err := e.sf.VerifyTOTP(ctx, h, e.good(), attackerIP); !errors.Is(err, ErrPendingInvalid) {
			t.Fatalf("6th: %v", err)
		}
		evs = e.sink.of(KindSecondFactorRefused)
		if len(evs) != MaxSignInAttempts+1 {
			t.Fatalf("%d events, want 6", len(evs))
		}
		dead := evs[len(evs)-1]
		d := detailsOf(dead)
		if dead.Reason != RefusedAttemptsExhausted || d["account"] != e.account || d["first_factor"] != "password" ||
			d["source_ip"] != attackerIP.String() || d["first_factor_ip"] != "192.0.2.7" || dead.Outcome != audit.Denied {
			t.Errorf("dead event = %+v %v", dead, d)
		}
		// Later submissions to the dead row add nothing.
		_, _ = e.sf.VerifyTOTP(ctx, h, e.good(), attackerIP)
		if n := len(e.sink.of(KindSecondFactorRefused)); n != MaxSignInAttempts+1 {
			t.Errorf("a dead pending sign-in was audited again: %d events", n)
		}
		for _, ev := range evs {
			for _, v := range detailsOf(ev) {
				if strings.Contains(v, e.good()) || strings.Contains(v, e.bad()) {
					t.Errorf("event carries a code: %+v", ev)
				}
			}
		}
	})
}

func Test_pending_expiry_and_disabled_audited(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		h := e.begin(t)
		e.now = e.now.Add(PendingSignInTTL)
		_, _ = e.sf.VerifyTOTP(ctx, h, e.good(), attackerIP)
		evs := e.sink.of(KindSecondFactorRefused)
		if len(evs) != 1 || evs[0].Reason != RefusedPendingExpired {
			t.Fatalf("expiry events = %+v", evs)
		}
		e.now = e.now.Add(-PendingSignInTTL)
		h2 := e.begin(t)
		if _, err := e.accts.SetState(ctx, e.ten, e.account, AccountDisabled, authority.Chain{Requester: authority.Principal{ID: "system", Kind: authority.System}}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.sf.VerifyTOTP(ctx, h2, e.good(), attackerIP); !errors.Is(err, ErrSecondFactorRefused) {
			t.Fatal(err)
		}
		evs = e.sink.of(KindSecondFactorRefused)
		if len(evs) != 2 || evs[1].Reason != RefusedAccountDisabled {
			t.Fatalf("disabled events = %+v", evs)
		}
	})
}

// T-0418 acceptance 2: the owner-role purge removes ended pending rows past retention and audits the count.
func Test_pending_retention_purge(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ctx := context.Background()
		// The INSERT guard bounds created_at by the database clock; this test moves the fake clock months.
		if err := e.d.ExecOwner(ctx, `ALTER TABLE public.authn_pending_signins DISABLE TRIGGER authn_pending_signins_insert_guard`); err != nil {
			t.Fatal(err)
		}
		dead := e.begin(t)
		for i := 0; i <= MaxSignInAttempts; i++ {
			_, _ = e.sf.VerifyTOTP(ctx, dead, e.bad(), attackerIP)
		}
		_ = e.begin(t) // still active and unexpired: must survive
		e.now = e.now.Add(91 * 24 * time.Hour)
		fresh := e.begin(t)
		_, _ = e.sf.VerifyTOTP(ctx, fresh, e.bad(), attackerIP) // live, recent: survives

		if err := e.tx(t, e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `DELETE FROM public.authn_pending_signins WHERE tenant_id = $1::uuid`, e.ten.String())
			return err
		}); err == nil {
			t.Fatal("the runtime role deleted pending sign-ins")
		}
		owner, err := store.OpenMaintenance(ctx, store.Config{DSN: e.d.OwnerDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(owner.Close)
		psink := &recSink{}
		p, err := NewPurger(owner, psink, 90*24*time.Hour, func() time.Time { return e.now })
		if err != nil {
			t.Fatal(err)
		}
		human := authority.Chain{Requester: authority.Principal{ID: "ops", Kind: authority.Human}}
		n, err := p.PurgePending(ctx, e.ten, human)
		// dead (ended 91d ago) and the abandoned active row (expired 91d ago) go; the recent one stays.
		if err != nil || n != 2 {
			t.Fatalf("PurgePending = %d, %v; want 2", n, err)
		}
		if got := e.query(t, `SELECT count(*)::text FROM public.authn_pending_signins`); got[0] != "1" {
			t.Errorf("%s rows remain, want 1", got[0])
		}
		evs := psink.of(KindPendingPurged)
		if len(evs) != 1 || detailsOf(evs[0])["pending_signins"] != "2" {
			t.Fatalf("purge events = %+v", evs)
		}
		if n, err := p.PurgePending(ctx, e.ten, human); err != nil || n != 0 || len(psink.of(KindPendingPurged)) != 1 {
			t.Errorf("second purge = %d, %v", n, err)
		}
	})
}

// failSink refuses every append.
type failSink struct{}

func (failSink) Append(context.Context, store.Tx, audit.Event) error { return errors.New("audit down") }

// T-0439 acceptance 1: Begin commits authn.pending.begun with account, first factor and client IP, and
// neither the handle nor its hash.
func Test_pending_begin_audited(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		h := e.begin(t)
		evs := e.sink.of(KindPendingBegun)
		if len(evs) != 1 {
			t.Fatalf("%d begun events, want 1", len(evs))
		}
		d := detailsOf(evs[0])
		if evs[0].Outcome != audit.Success || d["account"] != e.account || d["first_factor"] != "password" || d["client_ip"] != "192.0.2.7" {
			t.Errorf("begun event = %+v %v", evs[0], d)
		}
		if evs[0].Target.GUID != e.row(t, "id") {
			t.Errorf("target %q is not the pending row", evs[0].Target.GUID)
		}
		hash := fmt.Sprintf("%x", h.hash())
		vals := []string{evs[0].ID, evs[0].Target.GUID}
		for _, v := range d {
			vals = append(vals, v)
		}
		for _, v := range vals {
			if strings.Contains(v, h.Reveal()) || strings.Contains(v, hash) {
				t.Errorf("event carries the handle or hash: %q", v)
			}
		}
	})
}

// T-0439 acceptance 2: an audit failure leaves no pending row.
func Test_pending_begin_fails_closed_without_audit(t *testing.T) {
	eachPending(t, func(t *testing.T, e *pendEnv) {
		ps, err := NewPendingStore(e.db, failSink{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ps.Begin(context.Background(), BeginInput{Tenant: e.ten, Account: e.account, FirstFactor: FirstPassword, Epoch: epochOf(t, e.sess, e.ten, e.account)})
		if err == nil {
			t.Fatal("Begin succeeded with a failing audit sink")
		}
		if n := e.query(t, "SELECT count(*)::text FROM public.authn_pending_signins"); len(n) != 1 || n[0] != "0" {
			t.Errorf("pending rows after failed audit: %v", n)
		}
		if _, err := NewPendingStore(e.db, nil, nil); err == nil {
			t.Error("NewPendingStore accepted a nil sink")
		}
	})
}
