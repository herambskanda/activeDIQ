package delivery_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/egress"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	nm "github.com/skenzeriq/activediq/internal/platform/notify/mail"
	"github.com/skenzeriq/activediq/internal/platform/notify/mailtest"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
	"github.com/skenzeriq/activediq/internal/platform/tenant/tenanttest"
)

func TestMain(m *testing.M) { os.Exit(storetest.Main(m)) }

type sink struct {
	mu  sync.Mutex
	evs []audit.Event
}

func (s *sink) Append(_ context.Context, _ store.Tx, ev audit.Event) error {
	if err := ev.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, ev)
	return nil
}

func (s *sink) kinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.evs {
		out = append(out, fmt.Sprintf("%s/%s", e.Kind, e.Reason))
	}
	return out
}

type renderer struct{ fail bool }

func (r renderer) Render(_ context.Context, _ store.Tx, d delivery.Delivery) (delivery.Content, error) {
	if r.fail {
		return delivery.Content{}, errors.New("source gone")
	}
	return delivery.Content{Subject: "Report " + d.Variables["report"], Text: "SECRET-BODY-MARKER for " + d.Variables["report"]}, nil
}

type accounts map[string]string

func (a accounts) MailAddress(_ context.Context, _ store.Tx, id string) (string, error) {
	if m, ok := a[id]; ok {
		return m, nil
	}
	return "", delivery.ErrNoAddress
}

var human = authority.Chain{Requester: authority.Principal{ID: "owner-1", Kind: authority.Human}}

const (
	acctA = "11111111-1111-4111-8111-111111111111"
	acctB = "22222222-2222-4222-8222-222222222222"
)

type env struct {
	t     *testing.T
	db    *store.DB
	ten   tenant.ID
	other tenant.ID
	snk   *sink
	dl    *delivery.Deliveries
	srv   *mailtest.Server
	disp  *delivery.Dispatcher
}

func each(t *testing.T, mode mailtest.Mode, security string, fn func(t *testing.T, e *env)) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		d := s.NewDatabase(t)
		d.Migrate(t)
		ten := tenanttest.Seed(t, d.ExecOwner, "t1")
		other := tenanttest.Seed(t, d.ExecOwner, "t2")
		db, err := store.Open(context.Background(), store.Config{DSN: d.AppDSN()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(db.Close)
		snk := &sink{}
		dl, err := delivery.New(snk)
		if err != nil {
			t.Fatal(err)
		}
		srv := mailtest.Start(t, mode)
		eg, err := egress.New(egress.Config{Allow: mailtest.Loopback(), RootCAs: srv.CA()})
		if err != nil {
			t.Fatal(err)
		}
		e := &env{t: t, db: db, ten: ten, other: other, snk: snk, dl: dl, srv: srv}
		e.disp = &delivery.Dispatcher{DB: db, Deliveries: dl, Sender: &nm.Sender{Dialer: eg},
			Renderers: map[string]delivery.Renderer{"test.report": renderer{}},
			Accounts:  accounts{acctA: "alice@ok.example", acctB: "bob@elsewhere.example"},
			Backoff:   func(int) time.Duration { return 0 }}
		if security != "" {
			e.configure(ten, security, "ok.example")
		}
		fn(t, e)
	})
}

// configure writes the tenant's settings the way the Action would have left them.
func (e *env) configure(ten tenant.ID, security string, domains ...string) {
	e.t.Helper()
	err := e.db.WithTenant(context.Background(), ten, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO public.notify_settings (tenant_id, allowed_domains, smtp_host, smtp_port, smtp_security, smtp_from, plaintext_opt_in)
			VALUES ($1::uuid, $2, $3, $4, $5, 'noreply@ok.example', $6)`, ten.String(), append([]string{}, domains...), e.srv.Host(), e.srv.Port(), security, security == "none")
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) enqueue(key string, r delivery.Recipient, src delivery.SourceRef, reqInternal bool) delivery.Delivery {
	e.t.Helper()
	var out delivery.Delivery
	err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		var err error
		out, err = e.dl.Enqueue(ctx, tx, delivery.NewDelivery{DedupKey: key, Purpose: "test.report", TemplateVersion: 1,
			Variables: map[string]string{"report": "usr-01"}, Recipient: r, Source: src, RequireInternal: reqInternal, MaxAttempts: 3}, human)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *env) get(id string) delivery.Delivery {
	e.t.Helper()
	var out delivery.Delivery
	err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		var err error
		out, err = e.dl.Get(ctx, tx, id)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

var src = delivery.SourceRef{Kind: "report_export", ID: "exp-1"}

// AC 1 (AC-36): three recipients, one induced SMTP failure. Each has its own state; the failing one
// retries, then ends with a reason; the other two are sent.
func TestPerRecipientStateAndRetry(t *testing.T) {
	each(t, mailtest.STARTTLS, "starttls", func(t *testing.T, e *env) {
		e.srv.RejectRcpt("carol@ok.example", 451) // transient: carol's mailbox is busy
		a := e.enqueue("fire-1:a", delivery.Recipient{Address: "alice@ok.example"}, src, false)
		b := e.enqueue("fire-1:b", delivery.Recipient{Address: "BOB@Ok.Example"}, src, false)
		c := e.enqueue("fire-1:c", delivery.Recipient{Address: "carol@ok.example"}, src, false)

		sum, err := e.disp.DispatchDue(context.Background(), e.ten, 50)
		if err != nil {
			t.Fatal(err)
		}
		if sum.Sent != 2 || sum.Retrying != 1 || sum.GivenUp != 0 {
			t.Fatalf("first pass = %+v, want 2 sent, 1 retrying", sum)
		}
		if got := e.get(a.ID); got.State != delivery.Sent || got.Attempts != 1 || got.ProviderMessageID == "" || got.SentAt == nil {
			t.Fatalf("alice = %+v", got)
		}
		if got := e.get(b.ID); got.State != delivery.Sent {
			t.Fatalf("bob = %+v", got)
		}
		got := e.get(c.ID)
		if got.State != delivery.Failed || got.Attempts != 1 || got.LastErrorCode != nm.CodeRecipientDeferred || got.NextAttemptAt == nil {
			t.Fatalf("carol after one attempt = %+v", got)
		}

		// Retries: the failing one is tried again, the sent ones never are.
		for i := 0; i < 2; i++ {
			if _, err := e.disp.DispatchDue(context.Background(), e.ten, 50); err != nil {
				t.Fatal(err)
			}
		}
		got = e.get(c.ID)
		if got.State != delivery.GivenUp || got.Attempts != 3 || got.LastErrorCode != nm.CodeRecipientDeferred || got.NextAttemptAt != nil {
			t.Fatalf("carol at the end = %+v, want given_up after 3 attempts with a reason", got)
		}
		if msgs := e.srv.Messages(); len(msgs) != 2 {
			t.Fatalf("relay got %d messages, want exactly alice and bob", len(msgs))
		}
		if sum, _ := e.disp.DispatchDue(context.Background(), e.ten, 50); sum != (delivery.Summary{}) {
			t.Fatalf("nothing is due any more, got %+v", sum)
		}
		for _, m := range e.srv.Messages() {
			if !m.TLS {
				t.Fatal("delivered over plaintext")
			}
		}
	})
}

// AC 5: no message body (or subject, variable value, address) in any audit event.
func TestAuditCarriesNoBodyOrAddress(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		e.srv.RejectRcpt("bad@ok.example", 550)
		e.enqueue("k1", delivery.Recipient{Address: "good@ok.example"}, src, false)
		e.enqueue("k2", delivery.Recipient{Address: "bad@ok.example"}, src, false)
		e.enqueue("k3", delivery.Recipient{Address: "who@external.example"}, src, false)
		if _, err := e.disp.DispatchDue(context.Background(), e.ten, 50); err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{"notify.delivery.queued/queued": false, "notify.delivery.sent/sent": false, "notify.delivery.given_up/recipient_rejected": false}
		for _, k := range e.snk.kinds() {
			if _, ok := want[k]; ok {
				want[k] = true
			}
		}
		for k, seen := range want {
			if !seen {
				t.Errorf("missing audit event %s in %v", k, e.snk.kinds())
			}
		}
		e.snk.mu.Lock()
		defer e.snk.mu.Unlock()
		for _, ev := range e.snk.evs {
			dump := fmt.Sprintf("%+v", ev)
			for _, forbidden := range []string{"SECRET-BODY-MARKER", "Report usr-01", "usr-01", "@ok.example", "@external.example", "good@", "who@"} {
				if strings.Contains(dump, forbidden) {
					t.Errorf("audit event %s carries %q: %s", ev.Kind, forbidden, dump)
				}
			}
			if ev.Kind == delivery.KindQueued && ev.Actor.Requester.ID != "owner-1" {
				t.Errorf("queued event actor = %+v, want the requesting human", ev.Actor)
			}
		}
		// The external recipient is identified by domain and class.
		var found bool
		for _, ev := range e.snk.evs {
			for _, d := range ev.Details {
				if d.Key == "recipient_domain" && d.Value == "external.example" {
					found = true
				}
			}
		}
		if !found {
			t.Error("no event names the external recipient's domain")
		}
		// And the table itself holds no body.
		var cols string
		err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
			return tx.QueryRow(ctx, `SELECT string_agg(t::text, ' ') FROM public.notify_deliveries t`).Scan(&cols)
		})
		if err != nil || strings.Contains(cols, "SECRET-BODY-MARKER") {
			t.Fatalf("stored rows carry the body: %v", err)
		}
	})
}

// AC 4: an SMTP destination egress does not allow is refused, the Delivery gives up at once with the
// code, and the refusal is audited. No connection is made.
func TestEgressRefusalIsFinalAndAudited(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		strict, err := egress.New(egress.Config{}) // loopback is not allow-listed
		if err != nil {
			t.Fatal(err)
		}
		e.disp.Sender = &nm.Sender{Dialer: strict}
		d := e.enqueue("k", delivery.Recipient{Address: "alice@ok.example"}, src, false)
		sum, err := e.disp.DispatchDue(context.Background(), e.ten, 10)
		if err != nil {
			t.Fatal(err)
		}
		if sum.GivenUp != 1 {
			t.Fatalf("summary = %+v", sum)
		}
		got := e.get(d.ID)
		if got.State != delivery.GivenUp || got.LastErrorCode != nm.CodeDestinationDenied || got.Attempts != 1 {
			t.Fatalf("delivery = %+v", got)
		}
		if e.srv.Connections() != 0 {
			t.Fatal("egress must refuse before connecting")
		}
		if ks := e.snk.kinds(); !contains(ks, "notify.delivery.given_up/destination_denied") {
			t.Fatalf("refusal not audited: %v", ks)
		}
	})
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// AC 2: ForSource returns exactly the Delivery for that account and nothing for another account, another
// source or another tenant.
func TestForSource(t *testing.T) {
	each(t, mailtest.Plain, "", func(t *testing.T, e *env) {
		d := e.enqueue("k1", delivery.Recipient{Account: acctA}, src, false)
		e.enqueue("k2", delivery.Recipient{Account: acctB}, delivery.SourceRef{Kind: "report_export", ID: "exp-2"}, false)
		e.enqueue("k3", delivery.Recipient{Address: "x@ok.example"}, src, false)
		lookup := func(ten tenant.ID, s delivery.SourceRef, r delivery.Recipient) (delivery.Delivery, bool) {
			var got delivery.Delivery
			var ok bool
			err := e.db.WithTenant(context.Background(), ten, func(ctx context.Context, tx store.Tx) error {
				var err error
				got, ok, err = e.dl.ForSource(ctx, tx, s, r)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			return got, ok
		}
		if got, ok := lookup(e.ten, src, delivery.Recipient{Account: acctA}); !ok || got.ID != d.ID || got.Recipient.Account != acctA || got.Source != src {
			t.Fatalf("ForSource = %+v, %v", got, ok)
		}
		if _, ok := lookup(e.ten, src, delivery.Recipient{Account: acctB}); ok {
			t.Fatal("another account must get nothing for this source")
		}
		if _, ok := lookup(e.ten, delivery.SourceRef{Kind: "report_export", ID: "exp-3"}, delivery.Recipient{Account: acctA}); ok {
			t.Fatal("another source must get nothing")
		}
		if _, ok := lookup(e.ten, src, delivery.Recipient{Address: "x@ok.example"}); ok {
			t.Fatal("an address recipient is not an account")
		}
		if _, ok := lookup(e.ten, src, delivery.Recipient{}); ok {
			t.Fatal("an empty recipient matches nothing")
		}
		if _, ok := lookup(e.other, src, delivery.Recipient{Account: acctA}); ok {
			t.Fatal("another tenant must not see the delivery (RLS)")
		}
	})
}

// A delivery that was given up never sent the link, so it authorises nothing.
func TestForSourceIgnoresGivenUp(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		e.srv.RejectRcpt("alice@ok.example", 550)
		e.enqueue("k1", delivery.Recipient{Account: acctA}, src, false)
		if _, err := e.disp.DispatchDue(context.Background(), e.ten, 10); err != nil {
			t.Fatal(err)
		}
		err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
			_, ok, err := e.dl.ForSource(ctx, tx, src, delivery.Recipient{Account: acctA})
			if ok {
				t.Error("a given-up delivery authorised a download")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestEnqueueIsIdempotentAndValidates(t *testing.T) {
	each(t, mailtest.Plain, "", func(t *testing.T, e *env) {
		a := e.enqueue("same", delivery.Recipient{Address: "Alice@OK.example"}, src, false)
		b := e.enqueue("same", delivery.Recipient{Address: "Alice@Ok.Example"}, src, false)
		if a.ID != b.ID || a.Recipient.Address != "Alice@ok.example" {
			t.Fatalf("a=%+v b=%+v", a, b)
		}
		if n := len(e.snk.kinds()); n != 1 {
			t.Fatalf("a repeated enqueue appended events: %v", e.snk.kinds())
		}
		err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := e.dl.Enqueue(ctx, tx, delivery.NewDelivery{DedupKey: "same", Purpose: "test.report", TemplateVersion: 1,
				Recipient: delivery.Recipient{Address: "other@ok.example"}, Source: src}, human)
			if !errors.Is(err, delivery.ErrConflict) {
				t.Errorf("reused key for a different delivery: %v", err)
			}
			for _, bad := range []delivery.Recipient{{}, {Address: `"a"@ok.example`}, {Address: "a@ok.example", Account: acctA}, {Account: "not-a-uuid"}, {Address: "a@ok.example\r\nBcc: x@evil.example"}} {
				_, err := e.dl.Enqueue(ctx, tx, delivery.NewDelivery{DedupKey: "k-" + bad.Address, Purpose: "test.report", TemplateVersion: 1, Recipient: bad, Source: src}, human)
				if !errors.Is(err, delivery.ErrInvalid) {
					t.Errorf("recipient %+v accepted: %v", bad, err)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

// SX-5: a message that must stay inside the organisation is not sent to an external address, even to
// an account's own address, and the others are unaffected.
func TestRequireInternal(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		in := e.enqueue("a", delivery.Recipient{Account: acctA}, src, true)  // alice@ok.example
		out := e.enqueue("b", delivery.Recipient{Account: acctB}, src, true) // bob@elsewhere.example
		free := e.enqueue("c", delivery.Recipient{Address: "z@elsewhere.example"}, src, false)
		sum, err := e.disp.DispatchDue(context.Background(), e.ten, 10)
		if err != nil {
			t.Fatal(err)
		}
		if sum.Sent != 2 || sum.GivenUp != 1 {
			t.Fatalf("summary = %+v", sum)
		}
		if g := e.get(in.ID); g.State != delivery.Sent {
			t.Fatalf("internal = %+v", g)
		}
		if g := e.get(out.ID); g.State != delivery.GivenUp || g.LastErrorCode != delivery.CodeRecipientExternal {
			t.Fatalf("external with RequireInternal = %+v", g)
		}
		if g := e.get(free.ID); g.State != delivery.Sent {
			t.Fatalf("external without the rule = %+v", g)
		}
	})
}

// AC 3 (list empty): the dispatcher classifies against the tenant's list as it is at send time; an
// empty list makes everything external.
func TestEmptyListMakesEverythingExternal(t *testing.T) {
	each(t, mailtest.Plain, "", func(t *testing.T, e *env) {
		e.configure(e.ten, "none") // relay, and no allowed domain
		d := e.enqueue("a", delivery.Recipient{Address: "alice@ok.example"}, src, true)
		if _, err := e.disp.DispatchDue(context.Background(), e.ten, 10); err != nil {
			t.Fatal(err)
		}
		if g := e.get(d.ID); g.State != delivery.GivenUp || g.LastErrorCode != delivery.CodeRecipientExternal {
			t.Fatalf("delivery = %+v", g)
		}
	})
}

func TestNoRelayRetriesThenGivesUp(t *testing.T) {
	each(t, mailtest.Plain, "", func(t *testing.T, e *env) {
		d := e.enqueue("a", delivery.Recipient{Address: "alice@ok.example"}, src, false)
		for i := 0; i < 3; i++ {
			if _, err := e.disp.DispatchDue(context.Background(), e.ten, 10); err != nil {
				t.Fatal(err)
			}
		}
		if g := e.get(d.ID); g.State != delivery.GivenUp || g.LastErrorCode != nm.CodeNoRelay || g.Attempts != 3 {
			t.Fatalf("delivery = %+v", g)
		}
	})
}

func TestRendererFailureAndMissingRenderer(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		e.disp.Renderers = map[string]delivery.Renderer{"test.report": renderer{fail: true}}
		a := e.enqueue("a", delivery.Recipient{Address: "alice@ok.example"}, src, false)
		if _, err := e.disp.DispatchDue(context.Background(), e.ten, 10); err != nil {
			t.Fatal(err)
		}
		if g := e.get(a.ID); g.State != delivery.Failed || g.LastErrorCode != delivery.CodeRenderFailed {
			t.Fatalf("render failure = %+v", g)
		}
		e.disp.Renderers = nil
		if _, err := e.disp.DispatchDue(context.Background(), e.ten, 10); err != nil {
			t.Fatal(err)
		}
		if g := e.get(a.ID); g.State != delivery.GivenUp || g.LastErrorCode != delivery.CodeNoRenderer {
			t.Fatalf("no renderer = %+v", g)
		}
		if len(e.srv.Messages()) != 0 {
			t.Fatal("nothing may be sent without a body")
		}
	})
}

// Crash safety: a claim that was never recorded is retried after its lease, counts as an attempt, and a
// Delivery with no attempt left is closed with attempts_exhausted instead of staying claimed forever.
func TestLeaseResumeAndExhaustion(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		d := e.enqueue("a", delivery.Recipient{Address: "alice@ok.example"}, src, false)
		// A worker claimed it twice and died both times: leases are in the past.
		err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.notify_deliveries SET attempts = 2, lease_until = now() - interval '1 minute' WHERE id = $1::uuid`, d.ID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if sum, err := e.disp.DispatchDue(context.Background(), e.ten, 10); err != nil || sum.Sent != 1 {
			t.Fatalf("resume: %+v %v", sum, err)
		}
		if g := e.get(d.ID); g.State != delivery.Sent || g.Attempts != 3 {
			t.Fatalf("resumed = %+v", g)
		}

		x := e.enqueue("b", delivery.Recipient{Address: "alice@ok.example"}, src, false)
		err = e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.notify_deliveries SET attempts = 3, lease_until = now() - interval '1 minute' WHERE id = $1::uuid`, x.ID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if sum, err := e.disp.DispatchDue(context.Background(), e.ten, 10); err != nil || sum.Sent != 0 {
			t.Fatalf("exhausted: %+v %v", sum, err)
		}
		if g := e.get(x.ID); g.State != delivery.GivenUp || g.LastErrorCode != delivery.CodeAttemptsExhausted {
			t.Fatalf("exhausted = %+v", g)
		}
		if !contains(e.snk.kinds(), "notify.delivery.given_up/attempts_exhausted") {
			t.Fatalf("not audited: %v", e.snk.kinds())
		}
		// A live lease is respected.
		y := e.enqueue("c", delivery.Recipient{Address: "alice@ok.example"}, src, false)
		_ = e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.notify_deliveries SET lease_until = now() + interval '1 hour' WHERE id = $1::uuid`, y.ID)
			return err
		})
		if sum, _ := e.disp.DispatchDue(context.Background(), e.ten, 10); sum.Sent != 0 {
			t.Fatalf("a leased delivery was sent: %+v", sum)
		}
	})
}

// The database refuses to change who was sent what, and to reopen a finished delivery.
func TestRowGuard(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		d := e.enqueue("a", delivery.Recipient{Account: acctA}, src, false)
		try := func(sql string) error {
			return e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
				_, err := tx.Exec(ctx, sql, d.ID)
				return err
			})
		}
		for _, sql := range []string{
			`UPDATE public.notify_deliveries SET recipient_account = '22222222-2222-4222-8222-222222222222' WHERE id = $1::uuid`,
			`UPDATE public.notify_deliveries SET source_id = 'other' WHERE id = $1::uuid`,
			`UPDATE public.notify_deliveries SET purpose = 'x.y' WHERE id = $1::uuid`,
			`DELETE FROM public.notify_deliveries WHERE id = $1::uuid`,
		} {
			if err := try(sql); err == nil {
				t.Errorf("statement was accepted: %s", sql)
			}
		}
		if _, err := e.disp.DispatchDue(context.Background(), e.ten, 10); err != nil {
			t.Fatal(err)
		}
		if err := try(`UPDATE public.notify_deliveries SET state = 'queued', next_attempt_at = now(), sent_at = NULL WHERE id = $1::uuid`); err == nil {
			t.Error("a sent delivery was reopened")
		}
	})
}

// Another tenant's dispatcher run never touches this tenant's deliveries.
func TestTenantIsolation(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		d := e.enqueue("a", delivery.Recipient{Address: "alice@ok.example"}, src, false)
		if sum, err := e.disp.DispatchDue(context.Background(), e.other, 10); err != nil || sum != (delivery.Summary{}) {
			t.Fatalf("other tenant dispatch = %+v, %v", sum, err)
		}
		if g := e.get(d.ID); g.State != delivery.Queued {
			t.Fatalf("delivery = %+v", g)
		}
	})
}
