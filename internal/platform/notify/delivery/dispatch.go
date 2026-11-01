package delivery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/notify/mail"
	"github.com/skenzeriq/activediq/internal/platform/notify/mailaddr"
	"github.com/skenzeriq/activediq/internal/platform/notify/settings"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Codes a Delivery can give up with, besides the mail.Code* values of the sender.
const (
	CodeRecipientExternal = "recipient_external" // RequireInternal and the address is outside the allowed domains (SX-5)
	CodeInvalidAddress    = "invalid_address"
	CodeNoAddress         = "no_address" // the account has no mail address
	CodeNoRenderer        = "no_renderer"
	CodeRenderFailed      = "render_failed"
	CodeAttemptsExhausted = "attempts_exhausted" // reserved for a row found past its last attempt after a crash
)

// LeaseSlack is the least a Lease must exceed the sender's timeout by, so an outcome is recorded
// while the attempt still holds its Delivery.
const LeaseSlack = 30 * time.Second

// ErrLease: the Lease is not longer than the sender's timeout plus LeaseSlack.
var ErrLease = errors.New("delivery: lease must exceed the sender timeout plus the slack")

// ErrNoAddress is what Accounts.MailAddress returns for an account without a usable address.
var ErrNoAddress = errors.New("delivery: account has no mail address")

// Content is a rendered message body. It exists only in memory, for one send.
type Content struct {
	Subject     string
	Text        string
	Attachments []mail.Attachment
}

// Renderer produces the content of a Delivery from its purpose, template version and variable
// references. A Renderer must be safe to call again for the same Delivery: a retry renders anew.
type Renderer interface {
	Render(ctx context.Context, tx store.Tx, d Delivery) (Content, error)
}

// Accounts resolves an account recipient to the mail address the message is sent to.
type Accounts interface {
	MailAddress(ctx context.Context, tx store.Tx, accountID string) (string, error)
}

// Dispatcher claims due Deliveries and sends them. Callers run DispatchDue on a schedule per tenant.
type Dispatcher struct {
	DB         *store.DB
	Deliveries *Deliveries
	Sender     *mail.Sender
	Accounts   Accounts
	// Renderers by Delivery purpose.
	Renderers map[string]Renderer
	// Backoff is the wait before attempt n+1 after attempt n failed (n starts at 1). Default 1 m, 5 m,
	// 30 m, then 2 h.
	Backoff func(attempt int) time.Duration
	// Lease is how long a Delivery is reserved for one attempt. Default 5 minutes. It must exceed the
	// sender's timeout by LeaseSlack, or DispatchDue refuses to run (ErrLease). The claim reserves the
	// whole batch, so every Delivery renews its own lease right before it is sent and is skipped if
	// another worker has claimed it meanwhile.
	Lease time.Duration
}

// Summary counts what one DispatchDue did.
type Summary struct{ Sent, Retrying, GivenUp int }

// System is the actor of events the dispatcher records.
var System = authority.Chain{Requester: authority.Principal{ID: "system:notify-dispatcher", Kind: authority.System}}

func (d *Dispatcher) backoff(n int) time.Duration {
	if d.Backoff != nil {
		return d.Backoff(n)
	}
	steps := []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}
	return steps[min(max(n, 1), len(steps))-1]
}

// DispatchDue claims up to limit due Deliveries of tenant t and attempts each one. Each Delivery has
// its own outcome: one failure never stops the others. It returns when the batch is done or ctx ends;
// a Delivery left claimed by a cancelled context is picked up again after its lease expires.
func (d *Dispatcher) DispatchDue(ctx context.Context, t tenant.ID, limit int) (Summary, error) {
	if t.IsZero() || limit < 1 || limit > 500 {
		return Summary{}, ErrInvalid
	}
	lease := d.Lease
	if lease <= 0 {
		lease = 5 * time.Minute
	}
	sendTimeout := d.Sender.Timeout
	if sendTimeout <= 0 {
		sendTimeout = 60 * time.Second
	}
	if lease < sendTimeout+LeaseSlack {
		return Summary{}, ErrLease
	}
	var claimed []Delivery
	var cfg settings.Settings
	if err := d.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		var err error
		if cfg, err = (settings.Store{}).Get(ctx, tx); err != nil {
			return err
		}
		if err := d.closeExhausted(ctx, tx, t, cfg); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, sqlClaimDue, t.String(), lease.Seconds(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			del, err := scan(rows)
			if err != nil {
				return err
			}
			claimed = append(claimed, del)
		}
		return rows.Err()
	}); err != nil {
		return Summary{}, fmt.Errorf("delivery: claim: %w", err)
	}

	var sum Summary
	for _, del := range claimed {
		if ctx.Err() != nil {
			break
		}
		o := d.attempt(ctx, t, lease, del)
		if o.lost {
			continue // another worker claimed it after our lease lapsed: it is theirs, nothing is sent
		}
		if ctx.Err() != nil && o.code != "" {
			break // cancelled mid-attempt: the lease returns the Delivery
		}
		next, err := d.record(ctx, t, del, o.res, o.code, o.perm)
		if err != nil {
			return sum, err
		}
		switch next {
		case Sent:
			sum.Sent++
		case Failed:
			sum.Retrying++
		case GivenUp:
			sum.GivenUp++
		}
	}
	return sum, nil
}

// closeExhausted gives up a Delivery whose last attempt was claimed and never recorded (the worker
// died): its lease has expired and it has no attempt left.
func (d *Dispatcher) closeExhausted(ctx context.Context, tx store.Tx, t tenant.ID, cfg settings.Settings) error {
	rows, err := tx.Query(ctx, sqlCloseExhausted, t.String(), CodeAttemptsExhausted)
	if err != nil {
		return err
	}
	var closed []Delivery
	for rows.Next() {
		del, err := scan(rows)
		if err != nil {
			rows.Close()
			return err
		}
		closed = append(closed, del)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, del := range closed {
		class := "account"
		if a, err := mailaddr.Parse(del.Recipient.Address); err == nil {
			class = cfg.Classify(a).String()
		}
		if err := d.Deliveries.audit.Append(ctx, tx, d.Deliveries.event(del, KindGivenUp, System, audit.Failure, CodeAttemptsExhausted, class, time.Now().UTC())); err != nil {
			return err
		}
	}
	return nil
}

// outcome is what one attempt produced: a relay result, or a failure code and whether retrying
// cannot help, or lost when the Delivery is no longer this worker's.
type outcome struct {
	res  mail.Result
	code string
	perm bool
	lost bool
}

// attempt tries one Delivery. The settings are read in the same transaction that resolves the
// address, so the classification, the RequireInternal check and the relay are those in force now,
// not those at claim time (SX-6). Just before the send the same transaction renews the lease for
// this attempt's claim and finds out whether the Delivery is still ours.
func (d *Dispatcher) attempt(ctx context.Context, t tenant.ID, lease time.Duration, del Delivery) outcome {
	r, ok := d.Renderers[del.Purpose]
	if !ok {
		return outcome{code: CodeNoRenderer, perm: true}
	}
	var to mailaddr.Address
	var content Content
	var relay settings.Relay
	var from mailaddr.Address
	var o outcome
	err := d.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		o = outcome{}
		cfg, err := (settings.Store{}).Get(ctx, tx)
		if err != nil {
			return err
		}
		if cfg.Relay == nil {
			o.code = mail.CodeNoRelay
			return nil
		}
		relay = *cfg.Relay
		if from, err = mailaddr.Parse(relay.From); err != nil {
			o.code = mail.CodeNoRelay
			return nil
		}
		raw := del.Recipient.Address
		if del.Recipient.Account != "" {
			if d.Accounts == nil {
				o.code, o.perm = CodeNoAddress, true
				return nil
			}
			a, err := d.Accounts.MailAddress(ctx, tx, del.Recipient.Account)
			if err != nil {
				if errors.Is(err, ErrNoAddress) {
					o.code, o.perm = CodeNoAddress, true
					return nil
				}
				return err
			}
			raw = a
		}
		// Classify the canonical address that is then sent to: one parse, no second reading (SX-7).
		addr, class, err := cfg.ClassifyString(raw)
		if err != nil {
			o.code, o.perm = CodeInvalidAddress, true
			return nil
		}
		if del.RequireInternal && class != settings.Internal {
			o.code, o.perm = CodeRecipientExternal, true
			return nil
		}
		to = addr
		c, err := r.Render(ctx, tx, del)
		if err != nil {
			o.code = CodeRenderFailed
			return nil
		}
		content = c
		// Renew the lease for this claim, last, so the time spent resolving and rendering is not
		// taken from it. The attempts counter is the claim: a re-claim after expiry has raised it.
		tag, err := tx.Exec(ctx, `UPDATE public.notify_deliveries SET lease_until = clock_timestamp() + make_interval(secs => $4), updated_at = now()
			WHERE tenant_id = $1::uuid AND id = $2::uuid AND attempts = $3 AND state IN ('queued', 'failed')`,
			t.String(), del.ID, del.Attempts, lease.Seconds())
		if err != nil {
			return err
		}
		o.lost = tag.RowsAffected() != 1
		return nil
	})
	switch {
	case err != nil && ctx.Err() != nil:
		return outcome{code: "cancelled"}
	case err != nil:
		return outcome{code: CodeRenderFailed}
	case o.lost || o.code != "":
		return o
	}
	res, err := d.Sender.Send(ctx, relay, mail.Message{From: from, To: to, Subject: content.Subject, Text: content.Text, Attachments: content.Attachments})
	if err != nil {
		var me *mail.Error
		if errors.As(err, &me) {
			return outcome{code: me.Code, perm: me.Permanent}
		}
		if ctx.Err() != nil {
			return outcome{code: "cancelled"}
		}
		return outcome{code: mail.CodeConnect}
	}
	return outcome{res: res}
}

// record stores the outcome of a claimed attempt, and the audit event of a final one, in one
// transaction.
func (d *Dispatcher) record(ctx context.Context, t tenant.ID, del Delivery, res mail.Result, code string, permanent bool) (State, error) {
	var final State
	err := d.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		var upd Delivery
		var err error
		switch {
		case code == "":
			final = Sent
			upd, err = scan(tx.QueryRow(ctx, sqlRecordSent, t.String(), del.ID, res.MessageID, del.Attempts))
		case permanent || del.Attempts >= del.MaxAttempts:
			final = GivenUp
			upd, err = scan(tx.QueryRow(ctx, sqlRecordGivenUp, t.String(), del.ID, code, del.Attempts))
		default:
			final = Failed
			upd, err = scan(tx.QueryRow(ctx, sqlRecordFailed,
				t.String(), del.ID, code, d.backoff(del.Attempts).Seconds(), del.Attempts))
		}
		if store.IsNoRows(err) { // claimed or finished by another worker after a lease expiry: nothing to record
			final = ""
			return nil
		}
		if err != nil {
			return err
		}
		if final == Failed {
			return nil
		}
		kind, out, reason := KindSent, audit.Success, "sent"
		if final == GivenUp {
			kind, out, reason = KindGivenUp, audit.Failure, code
		}
		class := "account"
		if upd.Recipient.Address != "" {
			cur, err := (settings.Store{}).Get(ctx, tx)
			if err != nil {
				return err
			}
			a, _ := mailaddr.Parse(upd.Recipient.Address)
			class = cur.Classify(a).String()
		}
		return d.Deliveries.audit.Append(ctx, tx, d.Deliveries.event(upd, kind, System, out, reason, class, time.Now().UTC()))
	})
	if err != nil {
		return "", fmt.Errorf("delivery: record outcome: %w", err)
	}
	return final, nil
}
