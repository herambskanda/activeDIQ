package delivery_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/egress"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	nm "github.com/skenzeriq/activediq/internal/platform/notify/mail"
	"github.com/skenzeriq/activediq/internal/platform/notify/mailtest"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// hookRenderer calls after (once per call) the content is built, so a test can act between a
// Delivery's resolution and its send, the way a slow render or a concurrent admin would.
type hookRenderer struct {
	mu    sync.Mutex
	calls int
	after func(n int)
}

func (r *hookRenderer) Render(ctx context.Context, tx store.Tx, d delivery.Delivery) (delivery.Content, error) {
	r.mu.Lock()
	r.calls++
	n := r.calls
	after := r.after
	r.mu.Unlock()
	if after != nil {
		after(n)
	}
	return delivery.Content{Subject: "Report", Text: "body"}, nil
}

func (e *env) sql(q string, args ...any) {
	e.t.Helper()
	if err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, q, args...)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) sentEvents() int {
	n := 0
	for _, k := range e.snk.kinds() {
		if k == "notify.delivery.sent/sent" {
			n++
		}
	}
	return n
}

// Security review T-0950 #1: a batch claim reserves every row, but a slow batch can outlive the
// lease. A second dispatcher then takes the rows; the first must not send them again, and every
// message the relay gets must have its audit event.
func TestSlowBatchDoesNotSendTwice(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		const n = 4
		for i := 0; i < n; i++ {
			e.enqueue(string(rune('a'+i)), delivery.Recipient{Address: "alice@ok.example"}, src, false)
		}
		hr := &hookRenderer{}
		e.disp.Renderers = map[string]delivery.Renderer{"test.report": hr}
		var fired atomic.Bool
		hr.after = func(int) {
			if fired.CompareAndSwap(false, true) {
				// The first worker is "slow": its leases lapse and another node dispatches.
				e.sql(`UPDATE public.notify_deliveries SET lease_until = now() - interval '1 second' WHERE state = 'queued'`)
				second := *e.disp
				if sum, err := second.DispatchDue(context.Background(), e.ten, 50); err != nil || sum.Sent != n {
					t.Errorf("second dispatcher: %+v %v", sum, err)
				}
			}
		}
		sum, err := e.disp.DispatchDue(context.Background(), e.ten, 50)
		if err != nil {
			t.Fatal(err)
		}
		if sum != (delivery.Summary{}) {
			t.Fatalf("first dispatcher should have lost every row, got %+v", sum)
		}
		if got := len(e.srv.Messages()); got != n {
			t.Fatalf("relay got %d messages for %d deliveries", got, n)
		}
		if got := e.sentEvents(); got != n {
			t.Fatalf("%d sent audit events for %d messages", got, n)
		}
	})
}

func TestLeaseMustExceedSenderTimeout(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		e.disp.Lease = 10 * time.Second // default sender timeout is 60 s
		if _, err := e.disp.DispatchDue(context.Background(), e.ten, 5); !errors.Is(err, delivery.ErrLease) {
			t.Fatalf("err = %v, want ErrLease", err)
		}
		e.disp.Lease = 0
		if _, err := e.disp.DispatchDue(context.Background(), e.ten, 5); err != nil {
			t.Fatal(err)
		}
	})
}

// Security review T-0950 #2 (SX-6): the allowed list and the relay are read per attempt, so a change
// mid-batch is honoured by the deliveries after it.
func TestSettingsChangeMidBatchIsHonoured(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		a := e.enqueue("a", delivery.Recipient{Address: "alice@ok.example"}, src, true)
		b := e.enqueue("b", delivery.Recipient{Address: "alice@ok.example"}, src, true)
		hr := &hookRenderer{}
		e.disp.Renderers = map[string]delivery.Renderer{"test.report": hr}
		hr.after = func(n int) {
			if n == 1 {
				e.sql(`UPDATE public.notify_settings SET allowed_domains = '{}'`)
			}
		}
		sum, err := e.disp.DispatchDue(context.Background(), e.ten, 50)
		if err != nil {
			t.Fatal(err)
		}
		if sum.Sent != 1 || sum.GivenUp != 1 {
			t.Fatalf("summary = %+v, want one sent, one refused", sum)
		}
		// The batch is ordered by id, so either may have been first; one went out before the change
		// and the other was refused after it.
		ga, gb := e.get(a.ID), e.get(b.ID)
		sent, refused := ga, gb
		if ga.State == delivery.GivenUp {
			sent, refused = gb, ga
		}
		if sent.State != delivery.Sent {
			t.Fatalf("sent = %+v", sent)
		}
		if refused.State != delivery.GivenUp || refused.LastErrorCode != delivery.CodeRecipientExternal {
			t.Fatalf("refused = %+v, want given_up recipient_external", refused)
		}
		if len(e.srv.Messages()) != 1 {
			t.Fatalf("relay got %d messages", len(e.srv.Messages()))
		}
	})
}

func TestRelayChangeMidBatchIsHonoured(t *testing.T) {
	each(t, mailtest.Plain, "none", func(t *testing.T, e *env) {
		other := mailtest.Start(t, mailtest.Plain)
		eg, err := egress.New(egress.Config{Allow: mailtest.Loopback(), RootCAs: e.srv.CA()})
		if err != nil {
			t.Fatal(err)
		}
		e.disp.Sender = &nm.Sender{Dialer: eg}
		e.enqueue("a", delivery.Recipient{Address: "alice@ok.example"}, src, false)
		e.enqueue("b", delivery.Recipient{Address: "alice@ok.example"}, src, false)
		hr := &hookRenderer{}
		e.disp.Renderers = map[string]delivery.Renderer{"test.report": hr}
		hr.after = func(n int) {
			if n == 1 {
				e.sql(`UPDATE public.notify_settings SET smtp_port = $1`, other.Port())
			}
		}
		if sum, err := e.disp.DispatchDue(context.Background(), e.ten, 50); err != nil || sum.Sent != 2 {
			t.Fatalf("%+v %v", sum, err)
		}
		if len(e.srv.Messages()) != 1 || len(other.Messages()) != 1 {
			t.Fatalf("old relay %d, new relay %d messages; want 1 each", len(e.srv.Messages()), len(other.Messages()))
		}
	})
}
