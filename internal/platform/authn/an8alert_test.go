package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// an8Owners is the OwnerSource of the drain tests.
type an8Owners struct{ ids []string }

func (f an8Owners) TenantOwners(context.Context, store.Tx, tenant.ID) ([]string, error) {
	return f.ids, nil
}

// fakeSink is the transport port: it records the Deliveries the drain asks for and can refuse them, as a
// mail relay that is down would make the Delivery fail later (never at enqueue), or fail the enqueue itself.
type fakeSink struct {
	got       []AlertDelivery
	enqueueEr error
	total     int
	given     int
}

func (f *fakeSink) Enqueue(_ context.Context, _ store.Tx, d AlertDelivery) error {
	if f.enqueueEr != nil {
		return f.enqueueEr
	}
	f.got = append(f.got, d)
	return nil
}
func (f *fakeSink) Given(context.Context, store.Tx, string) (int, int, error) {
	return f.total, f.given, nil
}

type an8Env struct {
	*realAN8
	drain *AlertDrain
	sink  *fakeSink
}

func newAN8Env(t *testing.T, owners ...string) *an8Env {
	t.Helper()
	tg, _ := realAN8Target(t, an8Seeds)
	r := tg.(*realAN8)
	fs := &fakeSink{}
	d := &AlertDrain{DB: r.db, Owners: an8Owners{owners}, Sink: fs, Audit: r.snk, Clock: func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }}
	return &an8Env{realAN8: r, drain: d, sink: fs}
}

func (e *an8Env) notices(event string) int {
	return e.count(fmt.Sprintf(`SELECT count(*) FROM public.authn_authority_notices WHERE event = '%s'`, event))
}

func (e *an8Env) kindCount(k audit.Kind) int {
	n := 0
	for _, x := range e.snk.kinds() {
		if x == k {
			n++
		}
	}
	return n
}

const (
	own1 = "0b3f2f9e-6a1c-4c53-9a53-3a7a3f5f1c01"
	own2 = "0b3f2f9e-6a1c-4c53-9a53-3a7a3f5f1c02"
)

// Acceptance 1: one outbox row from the success's transaction, one Delivery per tenant-owner at drain
// time, and nothing secret anywhere in the row.
func TestAN8SuccessWritesOneOutboxRowAndDrainFansOut(t *testing.T) {
	e := newAN8Env(t, own1, own2)
	if r := e.Do(an8Seeds.Known, an8Seeds.Password, "198.51.100.40"); r.Status != 204 {
		t.Fatalf("sign-in answered %d", r.Status)
	}
	if n := e.notices(EventBreakGlassUsed); n != 1 {
		t.Fatalf("break_glass_used rows = %d, want 1", n)
	}
	if len(e.sink.got) != 0 {
		t.Fatal("the sign-in path itself enqueued a Delivery: it must only write the outbox row")
	}
	sum, err := e.drain.Drain(context.Background(), e.ten)
	if err != nil || sum.Enqueued != 2 {
		t.Fatalf("drain = %+v, %v; want 2 enqueued", sum, err)
	}
	if len(e.sink.got) != 2 || e.sink.got[0].Recipient != own1 || e.sink.got[1].Recipient != own2 || e.sink.got[0].Notice != e.sink.got[1].Notice {
		t.Fatalf("deliveries = %+v", e.sink.got)
	}
	if again, _ := e.drain.Drain(context.Background(), e.ten); again.Enqueued != 0 {
		t.Fatalf("a second drain enqueued %d: delivered_at must have moved", again.Enqueued)
	}
	// The row and its message carry no password, token, session id or submitted name.
	var dump string
	_ = e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT n::text FROM public.authn_authority_notices n WHERE event = 'break_glass_used'`).Scan(&dump)
	})
	for _, bad := range []string{an8Seeds.Password, an8Seeds.Known} {
		if strings.Contains(strings.ToLower(dump), strings.ToLower(bad)) {
			t.Errorf("outbox row contains %q: %s", bad, dump)
		}
	}
	m, err := loadMsg(e, dumpID(t, e))
	if err != nil || m.Account != "Known" || m.Source != "198.51.100.40" || m.Event != EventBreakGlassUsed {
		t.Fatalf("message = %+v, %v", m, err)
	}
}

func dumpID(t *testing.T, e *an8Env) string {
	t.Helper()
	var id string
	if err := e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT id::text FROM public.authn_authority_notices WHERE event = 'break_glass_used'`).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func loadMsg(e *an8Env, id string) (m AlertMessage, err error) {
	err = e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		m, err = LoadAlertMessage(ctx, tx, e.ten, id)
		return err
	})
	return
}

// A failed sign-in writes no break_glass_used and an outbox fault is not an alert: only a success is.
func TestAN8FailureWritesNoUsedRow(t *testing.T) {
	e := newAN8Env(t, own1)
	e.Do(an8Seeds.Known, an8Wrong, "198.51.100.41")
	if n := e.notices(EventBreakGlassUsed); n != 0 {
		t.Fatalf("a failed sign-in wrote %d break_glass_used rows", n)
	}
}

// Acceptance 2: the 10th failure of the hour raises break_glass_failures once for that window; the next
// window raises another.
func TestAN8TenFailuresInAnHourAlertOncePerWindow(t *testing.T) {
	e := newAN8Env(t, own1, own2)
	for i := 1; i <= 9; i++ {
		e.Do(fmt.Sprintf("name-%d", i), an8Wrong, "198.51.100.50")
	}
	if n := e.notices(EventBreakGlassFailures); n != 0 {
		t.Fatalf("9 failures raised %d alerts", n)
	}
	e.Do("name-10", an8Wrong, "198.51.100.50")
	if n := e.notices(EventBreakGlassFailures); n != 1 {
		t.Fatalf("the 10th failure raised %d alerts, want 1", n)
	}
	for i := 11; i <= 14; i++ {
		e.Do(fmt.Sprintf("name-%d", i), an8Wrong, "198.51.100.50")
	}
	if n := e.notices(EventBreakGlassFailures); n != 1 {
		t.Fatalf("failures 11-14 of the same window raised %d alerts in all, want 1", n)
	}
	sum, err := e.drain.Drain(context.Background(), e.ten)
	if err != nil || sum.Enqueued != 2 || len(e.sink.got) != 2 {
		t.Fatalf("drain = %+v, %v, %d deliveries; want every tenant-owner once", sum, err, len(e.sink.got))
	}
	e.Advance(FailureAlertWindow + time.Minute)
	for i := 0; i < FailureAlertThreshold; i++ {
		e.Do(fmt.Sprintf("later-%d", i), an8Wrong, "198.51.100.51")
	}
	if n := e.notices(EventBreakGlassFailures); n != 2 {
		t.Fatalf("a second window raised %d alerts in all, want 2", n)
	}
}

// Acceptance 3: with the channel down the sign-in is unchanged, the failure of the enqueue stays in the
// drain (the row stays pending), and give-up is audited once and shown as a banner until acknowledged.
func TestAN8ChannelDownDoesNotTouchSignInAndGiveUpIsLoud(t *testing.T) {
	e := newAN8Env(t, own1, own2)
	e.sink.enqueueEr = errors.New("relay down")
	ok := e.Do(an8Seeds.Known, an8Seeds.Password, "198.51.100.60")
	if ok.Status != 204 {
		t.Fatalf("sign-in with the channel down answered %d", ok.Status)
	}
	if _, err := e.drain.Drain(context.Background(), e.ten); err == nil {
		t.Fatal("a failing enqueue must surface from the drain so the job retries")
	}
	if n := e.count(`SELECT count(*) FROM public.authn_authority_notices WHERE event = 'break_glass_used' AND delivered_at IS NULL`); n != 1 {
		t.Fatalf("a row whose Delivery was not created must stay pending, got %d", n)
	}
	// The relay recovers for the enqueue but every Delivery ends up given up.
	e.sink.enqueueEr = nil
	e.sink.total, e.sink.given = 2, 2
	if _, err := e.drain.Drain(context.Background(), e.ten); err != nil {
		t.Fatal(err)
	}
	sum, err := e.drain.Drain(context.Background(), e.ten)
	if err != nil || sum.GivenUp != 1 {
		t.Fatalf("settle = %+v, %v; want one give-up", sum, err)
	}
	if _, err := e.drain.Drain(context.Background(), e.ten); err != nil {
		t.Fatal(err)
	}
	if n := e.kindCount(KindAlertGivenUp); n != 1 {
		t.Fatalf("an8_alert_given_up audited %d times, want once", n)
	}
	var banners []AlertBanner
	read := func() {
		_ = e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
			var err error
			banners, err = e.drain.AlertBanners(ctx, tx, e.ten)
			return err
		})
	}
	read()
	if len(banners) != 1 || banners[0].Event != EventBreakGlassUsed {
		t.Fatalf("banners = %+v, want the given-up alert", banners)
	}
	var cleared bool
	_ = e.db.WithTenant(context.Background(), e.ten, func(ctx context.Context, tx store.Tx) error {
		var err error
		cleared, err = e.drain.AcknowledgeAlert(ctx, tx, e.ten, banners[0].ID)
		return err
	})
	read()
	if !cleared || len(banners) != 0 {
		t.Fatalf("acknowledge cleared=%v, banners left %d", cleared, len(banners))
	}
}

// A Delivery still retrying (some not given up) is not a give-up.
func TestAN8PartialDeliveryIsNotGivenUp(t *testing.T) {
	e := newAN8Env(t, own1, own2)
	e.Do(an8Seeds.Known, an8Seeds.Password, "198.51.100.61")
	e.sink.total, e.sink.given = 2, 1
	for i := 0; i < 2; i++ {
		if _, err := e.drain.Drain(context.Background(), e.ten); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.kindCount(KindAlertGivenUp); n != 0 {
		t.Fatalf("one delivered owner is not a give-up, audited %d", n)
	}
}

// No tenant-owner at drain time: the row is given up with its own audit event, and the banner shows.
func TestAN8NoRecipientIsGivenUp(t *testing.T) {
	e := newAN8Env(t)
	e.Do(an8Seeds.Known, an8Seeds.Password, "198.51.100.62")
	sum, err := e.drain.Drain(context.Background(), e.ten)
	if err != nil || sum.NoRecipient != 1 {
		t.Fatalf("drain = %+v, %v", sum, err)
	}
	if e.kindCount(KindAlertNoRecipient) != 1 {
		t.Fatal("an8_alert_no_recipient not audited once")
	}
}

// Acceptance 4: a row the drain has not reached in 15 minutes is audited once.
func TestAN8PendingOverThresholdAuditedOnce(t *testing.T) {
	e := newAN8Env(t, own1)
	e.Do(an8Seeds.Known, an8Seeds.Password, "198.51.100.63")
	ctx := context.Background()
	e.Advance(PendingAlertThreshold - time.Minute)
	if n, err := e.drain.Watch(ctx, e.ten); err != nil || n != 0 {
		t.Fatalf("watch before the threshold = %d, %v", n, err)
	}
	e.Advance(2 * time.Minute)
	if n, err := e.drain.Watch(ctx, e.ten); err != nil || n != 1 {
		t.Fatalf("watch after the threshold = %d, %v; want 1", n, err)
	}
	if n, err := e.drain.Watch(ctx, e.ten); err != nil || n != 0 {
		t.Fatalf("second watch = %d, %v; want the row audited once only", n, err)
	}
	if e.kindCount(KindAlertPendingOverTime) != 1 {
		t.Fatalf("pending-over-threshold audited %d times", e.kindCount(KindAlertPendingOverTime))
	}
}

// The guard trigger: only the markers move, once.
func TestAN8NoticeRowsAreImmutableBeyondMarkers(t *testing.T) {
	e := newAN8Env(t, own1)
	e.Do(an8Seeds.Known, an8Seeds.Password, "198.51.100.64")
	for name, sql := range map[string]string{
		"source rewritten": `UPDATE public.authn_authority_notices SET source_ip = '203.0.113.1'`,
		"event rewritten":  `UPDATE public.authn_authority_notices SET event = 'break_glass_failures'`,
	} {
		if err := fixtureAs(e.db, e.ten, sql); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := fixtureAs(e.db, e.ten, `UPDATE public.authn_authority_notices SET delivered_at = now()`); err != nil {
		t.Fatalf("first delivered_at move refused: %v", err)
	}
	if err := fixtureAs(e.db, e.ten, `UPDATE public.authn_authority_notices SET delivered_at = NULL`); err == nil {
		t.Error("delivered_at moved back to NULL")
	}
}
