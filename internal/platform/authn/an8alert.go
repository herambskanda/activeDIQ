package authn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.authn_an8_failure_window", Entity: "DM-30", Kind: tablekind.Tenant})

// The AN-8 owner alert (RULING AN8-A1; threat model §7.6 rules 3-4). The password step writes one outbox
// row in authn_authority_notices, in the transaction that decides its outcome: break_glass_used on a
// success, break_glass_failures on the FailureAlertThreshold-th failure of the tenant within one
// FailureAlertWindow (once per window). The sign-in path never calls notify, never waits on a relay and
// never looks up the owners: AlertDrain does that later. The row holds no password, token, session id or
// submitted name; the message is made from the account id, the time and the source address.

// Alert events of the outbox.
const (
	EventBreakGlassUsed     = "break_glass_used"
	EventBreakGlassFailures = "break_glass_failures"
)

const (
	// FailureAlertThreshold failures of a tenant inside FailureAlertWindow raise break_glass_failures.
	FailureAlertThreshold = 10
	FailureAlertWindow    = time.Hour
	// PendingAlertThreshold is how long a row may wait for the drain before the audit event.
	PendingAlertThreshold = 15 * time.Minute
)

// Audit kinds of the alert plumbing. They carry ids and counts, never an address or a name.
const (
	KindAlertGivenUp         audit.Kind = "authn.an8_alert_given_up"
	KindAlertNoRecipient     audit.Kind = "authn.an8_alert_no_recipient"
	KindAlertPendingOverTime audit.Kind = "authn.an8_alert_pending_over_threshold"
)

// recordUsed queues break_glass_used for a successful AN-8 of account.
func (l *LocalCredentials) recordUsed(ctx context.Context, tx store.Tx, t tenant.ID, account string, from netip.Addr, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO public.authn_authority_notices (tenant_id, subject_id, event, created_at, source_ip)
VALUES ($1::uuid, $2::uuid, $3, $4, $5)`, t.String(), account, EventBreakGlassUsed, now, sourceText(from))
	return err
}

// countFailure counts one AN-8 failure of the tenant and queues break_glass_failures when it is the
// threshold-th inside the window. The window row is locked by the upsert, so concurrent failures count in
// turn and exactly one raises the alert.
func (l *LocalCredentials) countFailure(ctx context.Context, tx store.Tx, t tenant.ID, from netip.Addr, now time.Time) error {
	var failures int
	if err := tx.QueryRow(ctx, `INSERT INTO public.authn_an8_failure_window AS w (tenant_id, window_start, failures, alerted)
VALUES ($1::uuid, $2, 1, false)
ON CONFLICT (tenant_id) DO UPDATE SET
  failures = CASE WHEN w.window_start <= $3 THEN 1 ELSE w.failures + 1 END,
  alerted = CASE WHEN w.window_start <= $3 THEN false ELSE w.alerted END,
  window_start = CASE WHEN w.window_start <= $3 THEN $2 ELSE w.window_start END
RETURNING failures`, t.String(), now, now.Add(-FailureAlertWindow)).Scan(&failures); err != nil {
		return err
	}
	if failures < FailureAlertThreshold {
		return nil
	}
	tag, err := tx.Exec(ctx, `UPDATE public.authn_an8_failure_window SET alerted = true WHERE tenant_id = $1::uuid AND NOT alerted`, t.String())
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO public.authn_authority_notices (tenant_id, event, created_at, source_ip, failure_count)
VALUES ($1::uuid, $2, $3, $4, $5)`, t.String(), EventBreakGlassFailures, now, sourceText(from), failures)
	return err
}

func sourceText(a netip.Addr) *string {
	if !a.IsValid() {
		return nil
	}
	s := a.Unmap().String()
	return &s
}

// ---------------------------------------------------------------------------------------------------
// the drain

// AlertDelivery is one message to one tenant-owner about one outbox row.
type AlertDelivery struct {
	Notice    string // the outbox row id: the Source of the Delivery
	Recipient string // account id
}

// AlertSink is the transport port (platform/notify/delivery behind authn/alertjob). Enqueue is idempotent
// for the same (Notice, Recipient). Given reports for the notice how many Deliveries exist, how many are still open (queued or failed, a retry pending) and how many
// were given up.
type AlertSink interface {
	Enqueue(ctx context.Context, tx store.Tx, d AlertDelivery) error
	Given(ctx context.Context, tx store.Tx, notice string) (total, open, givenUp int, err error)
}

// AlertDrain fans the AN-8 outbox rows out to the tenant-owners, follows their Deliveries to the end and
// watches for rows the drain has not reached.
type AlertDrain struct {
	DB     *store.DB
	Owners OwnerSource
	Sink   AlertSink
	Audit  audit.Sink
	Clock  func() time.Time // nil: the real clock
}

// DrainBatch is the most rows one Drain call handles per phase.
const DrainBatch = 50

// DrainSummary counts what one Drain did.
type DrainSummary struct{ Enqueued, NoRecipient, GivenUp int }

func (d *AlertDrain) now() time.Time {
	if d.Clock != nil {
		return d.Clock().UTC()
	}
	return time.Now().UTC()
}

func (d *AlertDrain) ready() error {
	if d.DB == nil || d.Owners == nil || d.Sink == nil || d.Audit == nil {
		return errors.New("authn: AlertDrain is not fully configured")
	}
	return nil
}

var alertActor = authority.Chain{Requester: authority.Principal{ID: "authn-an8-alert", Kind: authority.System}}

func (d *AlertDrain) emit(ctx context.Context, tx store.Tx, kind audit.Kind, notice string, outcome audit.Outcome, reason string, at time.Time) error {
	ev := audit.Event{
		ID: "authn.an8alert." + notice + "." + string(kind), At: at, Kind: kind, Actor: alertActor,
		Target:    authority.TargetRef{GUID: notice, Class: "an8_alert"},
		Component: "authn", Outcome: outcome, Reason: reason,
	}
	if err := d.Audit.Append(ctx, tx, ev); err != nil {
		return fmt.Errorf("authn: audit an8 alert: %w", err)
	}
	return nil
}

type idRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

func collectIDs(rows idRows) ([]string, error) {
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Drain runs both phases for the tenant: fan-out of pending rows, then the give-up check of rows already
// handed to notify. Each row is its own transaction, so one bad row stops nothing else.
func (d *AlertDrain) Drain(ctx context.Context, t tenant.ID) (DrainSummary, error) {
	var sum DrainSummary
	if err := d.ready(); err != nil {
		return sum, err
	}
	var pending, enqueued []string
	err := d.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		var err error
		prows, qerr := tx.Query(ctx, `SELECT id::text FROM public.authn_authority_notices
WHERE tenant_id = $1::uuid AND delivered_at IS NULL AND given_up_at IS NULL AND event IN ($2, $3) ORDER BY created_at LIMIT $4`,
			t.String(), EventBreakGlassUsed, EventBreakGlassFailures, DrainBatch)
		if qerr != nil {
			return qerr
		}
		if pending, err = collectIDs(prows); err != nil {
			return err
		}
		rows, qerr := tx.Query(ctx, `SELECT id::text FROM public.authn_authority_notices
WHERE tenant_id = $1::uuid AND delivered_at IS NOT NULL AND settled_at IS NULL AND given_up_at IS NULL AND event IN ($2, $3) ORDER BY created_at LIMIT $4`,
			t.String(), EventBreakGlassUsed, EventBreakGlassFailures, DrainBatch)
		if qerr != nil {
			return qerr
		}
		enqueued, err = collectIDs(rows)
		return err
	})
	if err != nil {
		return sum, err
	}
	var first error
	for _, id := range pending {
		err := d.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error { return d.fanOut(ctx, tx, t, id, &sum) })
		if err != nil && first == nil {
			first = err
		}
	}
	for _, id := range enqueued {
		err := d.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error { return d.settle(ctx, tx, t, id, &sum) })
		if err != nil && first == nil {
			first = err
		}
	}
	return sum, first
}

// fanOut resolves the owners now and queues one Delivery each. delivered_at moves only after every
// Delivery exists. No owner: the row is given up (banner and audit) because no one can be told.
func (d *AlertDrain) fanOut(ctx context.Context, tx store.Tx, t tenant.ID, id string, sum *DrainSummary) error {
	var open bool
	err := tx.QueryRow(ctx, `SELECT true FROM public.authn_authority_notices
WHERE tenant_id = $1::uuid AND id = $2::uuid AND delivered_at IS NULL AND given_up_at IS NULL FOR UPDATE SKIP LOCKED`, t.String(), id).Scan(&open)
	if store.IsNoRows(err) {
		return nil // another worker has it
	}
	if err != nil {
		return err
	}
	now := d.now()
	owners, err := d.Owners.TenantOwners(ctx, tx, t)
	if err != nil {
		return err
	}
	if len(owners) == 0 {
		if _, err := tx.Exec(ctx, `UPDATE public.authn_authority_notices SET given_up_at = $3 WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), id, now); err != nil {
			return err
		}
		sum.NoRecipient++
		return d.emit(ctx, tx, KindAlertNoRecipient, id, audit.Failure, "no tenant-owner", now)
	}
	for _, o := range owners {
		if err := d.Sink.Enqueue(ctx, tx, AlertDelivery{Notice: id, Recipient: o}); err != nil {
			return err
		}
		sum.Enqueued++
	}
	_, err = tx.Exec(ctx, `UPDATE public.authn_authority_notices SET delivered_at = $3 WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), id, now)
	return err
}

// settle closes a row once every Delivery of it is terminal (sent or given up), so it leaves the enqueued
// set and a long history of sent alerts never hides a newer one. It is marked given up, audited and so shown
// as a banner only when every Delivery was given up; one that reached an owner is settled without a banner.
func (d *AlertDrain) settle(ctx context.Context, tx store.Tx, t tenant.ID, id string, sum *DrainSummary) error {
	var open bool
	err := tx.QueryRow(ctx, `SELECT true FROM public.authn_authority_notices
WHERE tenant_id = $1::uuid AND id = $2::uuid AND settled_at IS NULL AND given_up_at IS NULL FOR UPDATE SKIP LOCKED`, t.String(), id).Scan(&open)
	if store.IsNoRows(err) {
		return nil
	}
	if err != nil {
		return err
	}
	total, stillOpen, given, err := d.Sink.Given(ctx, tx, id)
	if err != nil || total == 0 || stillOpen > 0 {
		return err
	}
	now := d.now()
	if given < total {
		_, err := tx.Exec(ctx, `UPDATE public.authn_authority_notices SET settled_at = $3 WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), id, now)
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE public.authn_authority_notices SET settled_at = $3, given_up_at = $3 WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), id, now); err != nil {
		return err
	}
	sum.GivenUp++
	return d.emit(ctx, tx, KindAlertGivenUp, id, audit.Failure, "all deliveries given up", now)
}

// Watch audits an8_alert_pending_over_threshold, once per row, for rows the drain has not reached within
// PendingAlertThreshold. It is its own cadence so a stopped drain job is seen. It returns the rows audited.
func (d *AlertDrain) Watch(ctx context.Context, t tenant.ID) (int, error) {
	if err := d.ready(); err != nil {
		return 0, err
	}
	n := 0
	err := d.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now := d.now()
		rows, qerr := tx.Query(ctx, `SELECT id::text FROM public.authn_authority_notices
WHERE tenant_id = $1::uuid AND delivered_at IS NULL AND given_up_at IS NULL AND pending_audited_at IS NULL
  AND event IN ($2, $3) AND created_at <= $4 ORDER BY created_at LIMIT $5 FOR UPDATE SKIP LOCKED`,
			t.String(), EventBreakGlassUsed, EventBreakGlassFailures, now.Add(-PendingAlertThreshold), DrainBatch)
		if qerr != nil {
			return qerr
		}
		ids, err := collectIDs(rows)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := tx.Exec(ctx, `UPDATE public.authn_authority_notices SET pending_audited_at = $3 WHERE tenant_id = $1::uuid AND id = $2::uuid`, t.String(), id, now); err != nil {
				return err
			}
			if err := d.emit(ctx, tx, KindAlertPendingOverTime, id, audit.Failure, "not drained within the threshold", now); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// ---------------------------------------------------------------------------------------------------
// the banner

// AlertBanner is an alert nobody could be told about; tenant-owners see it until they acknowledge it.
type AlertBanner struct {
	ID      string
	Event   string
	At      time.Time // when the event happened
	GivenUp time.Time
}

// AlertBanners lists the unacknowledged given-up AN-8 alerts of the tenant, oldest first.
func (d *AlertDrain) AlertBanners(ctx context.Context, tx store.Tx, t tenant.ID) ([]AlertBanner, error) {
	rows, err := tx.Query(ctx, `SELECT id::text, event, created_at, given_up_at FROM public.authn_authority_notices
WHERE tenant_id = $1::uuid AND given_up_at IS NOT NULL AND acknowledged_at IS NULL AND event IN ($2, $3) ORDER BY given_up_at LIMIT 100`,
		t.String(), EventBreakGlassUsed, EventBreakGlassFailures)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertBanner
	for rows.Next() {
		var b AlertBanner
		if err := rows.Scan(&b.ID, &b.Event, &b.At, &b.GivenUp); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// AcknowledgeAlert clears one banner. It reports whether a banner was cleared.
func (d *AlertDrain) AcknowledgeAlert(ctx context.Context, tx store.Tx, t tenant.ID, id string) (bool, error) {
	if !validAccount(id) {
		return false, ErrInvalid
	}
	tag, err := tx.Exec(ctx, `UPDATE public.authn_authority_notices SET acknowledged_at = $3
WHERE tenant_id = $1::uuid AND id = $2::uuid AND given_up_at IS NOT NULL AND acknowledged_at IS NULL AND event IN ($4, $5)`,
		t.String(), id, d.now(), EventBreakGlassUsed, EventBreakGlassFailures)
	return err == nil && tag.RowsAffected() == 1, err
}

// AlertMessage is what the body of an alert is made of: no password, token, session id or submitted name.
type AlertMessage struct {
	Event        string
	At           time.Time
	Source       string // source address, or ""
	Account      string // display name of the break-glass account (used), or ""
	FailureCount int
}

// LoadAlertMessage reads the facts of one AN-8 outbox row for the renderer.
func LoadAlertMessage(ctx context.Context, tx store.Tx, t tenant.ID, id string) (AlertMessage, error) {
	if !validAccount(id) {
		return AlertMessage{}, ErrInvalid
	}
	var m AlertMessage
	var src, name *string
	var n *int
	err := tx.QueryRow(ctx, `SELECT n.event, n.created_at, n.source_ip, a.display_name, n.failure_count
FROM public.authn_authority_notices n LEFT JOIN public.authn_accounts a ON a.tenant_id = n.tenant_id AND a.id = n.subject_id
WHERE n.tenant_id = $1::uuid AND n.id = $2::uuid AND n.event IN ($3, $4)`, t.String(), id, EventBreakGlassUsed, EventBreakGlassFailures).
		Scan(&m.Event, &m.At, &src, &name, &n)
	if err != nil {
		if store.IsNoRows(err) {
			return AlertMessage{}, ErrInvalid
		}
		return AlertMessage{}, err
	}
	if src != nil {
		m.Source = *src
	}
	if name != nil {
		m.Account = *name
	}
	if n != nil {
		m.FailureCount = *n
	}
	return m, nil
}
