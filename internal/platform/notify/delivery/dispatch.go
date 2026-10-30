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
	// Lease is how long a claimed Delivery is reserved for its attempt. Default 5 minutes; it must
	// exceed the sender's timeout.
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
		rows, err := tx.Query(ctx, `UPDATE public.notify_deliveries SET attempts = attempts + 1, lease_until = now() + make_interval(secs => $2), updated_at = now()
			WHERE (tenant_id, id) IN (
			  SELECT tenant_id, id FROM public.notify_deliveries
			  WHERE tenant_id = $1::uuid AND state IN ('queued', 'failed') AND next_attempt_at <= now()
			    AND (lease_until IS NULL OR lease_until < now()) AND attempts < max_attempts
			  ORDER BY next_attempt_at, id LIMIT $3 FOR UPDATE SKIP LOCKED)
			RETURNING `+cols, t.String(), lease.Seconds(), limit)
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
		res, code, perm := d.attempt(ctx, t, cfg, del)
		if ctx.Err() != nil && code != "" {
			break // cancelled mid-attempt: the lease returns the Delivery
		}
		next, err := d.record(ctx, t, del, res, code, perm)
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
	rows, err := tx.Query(ctx, `UPDATE public.notify_deliveries SET state = 'given_up', next_attempt_at = NULL, lease_until = NULL,
		last_error_code = $2, updated_at = now()
		WHERE tenant_id = $1::uuid AND state IN ('queued', 'failed') AND attempts >= max_attempts AND (lease_until IS NULL OR lease_until < now())
		RETURNING `+cols, t.String(), CodeAttemptsExhausted)
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

// attempt tries one Delivery. It returns the relay's result and, on failure, the stable code and
// whether retrying cannot help.
func (d *Dispatcher) attempt(ctx context.Context, t tenant.ID, cfg settings.Settings, del Delivery) (mail.Result, string, bool) {
	if cfg.Relay == nil {
		return mail.Result{}, mail.CodeNoRelay, false
	}
	r, ok := d.Renderers[del.Purpose]
	if !ok {
		return mail.Result{}, CodeNoRenderer, true
	}
	var to mailaddr.Address
	var content Content
	var code string
	var perm bool
	err := d.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		raw := del.Recipient.Address
		if del.Recipient.Account != "" {
			if d.Accounts == nil {
				code, perm = CodeNoAddress, true
				return nil
			}
			a, err := d.Accounts.MailAddress(ctx, tx, del.Recipient.Account)
			if err != nil {
				if errors.Is(err, ErrNoAddress) {
					code, perm = CodeNoAddress, true
					return nil
				}
				return err
			}
			raw = a
		}
		// Classify the canonical address that is then sent to: one parse, no second reading (SX-7).
		addr, class, err := cfg.ClassifyString(raw)
		if err != nil {
			code, perm = CodeInvalidAddress, true
			return nil
		}
		if del.RequireInternal && class != settings.Internal {
			code, perm = CodeRecipientExternal, true
			return nil
		}
		to = addr
		c, err := r.Render(ctx, tx, del)
		if err != nil {
			code = CodeRenderFailed
			return nil
		}
		content = c
		return nil
	})
	switch {
	case err != nil && ctx.Err() != nil:
		return mail.Result{}, "cancelled", false
	case err != nil:
		return mail.Result{}, CodeRenderFailed, false
	case code != "":
		return mail.Result{}, code, perm
	}
	from, err := mailaddr.Parse(cfg.Relay.From)
	if err != nil {
		return mail.Result{}, mail.CodeNoRelay, false
	}
	res, err := d.Sender.Send(ctx, *cfg.Relay, mail.Message{From: from, To: to, Subject: content.Subject, Text: content.Text, Attachments: content.Attachments})
	if err != nil {
		var me *mail.Error
		if errors.As(err, &me) {
			return mail.Result{}, me.Code, me.Permanent
		}
		if ctx.Err() != nil {
			return mail.Result{}, "cancelled", false
		}
		return mail.Result{}, mail.CodeConnect, false
	}
	return res, "", false
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
			upd, err = scan(tx.QueryRow(ctx, `UPDATE public.notify_deliveries SET state = 'sent', next_attempt_at = NULL, lease_until = NULL,
				last_error_code = NULL, provider_message_id = $3, sent_at = now(), updated_at = now()
				WHERE tenant_id = $1::uuid AND id = $2::uuid AND state IN ('queued', 'failed') RETURNING `+cols, t.String(), del.ID, res.MessageID))
		case permanent || del.Attempts >= del.MaxAttempts:
			final = GivenUp
			upd, err = scan(tx.QueryRow(ctx, `UPDATE public.notify_deliveries SET state = 'given_up', next_attempt_at = NULL, lease_until = NULL,
				last_error_code = $3, updated_at = now()
				WHERE tenant_id = $1::uuid AND id = $2::uuid AND state IN ('queued', 'failed') RETURNING `+cols, t.String(), del.ID, code))
		default:
			final = Failed
			upd, err = scan(tx.QueryRow(ctx, `UPDATE public.notify_deliveries SET state = 'failed', lease_until = NULL, last_error_code = $3,
				next_attempt_at = now() + make_interval(secs => $4), updated_at = now()
				WHERE tenant_id = $1::uuid AND id = $2::uuid AND state IN ('queued', 'failed') RETURNING `+cols,
				t.String(), del.ID, code, d.backoff(del.Attempts).Seconds()))
		}
		if store.IsNoRows(err) { // finished by another worker after a lease expiry: nothing to record
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
