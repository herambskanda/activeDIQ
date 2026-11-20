package authn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// NoticeMessage is the one message an enrolment sends (spec 6.5): what happened, when (UTC), the source
// address as the server saw it (advisory) and who to call. No code, no seed, no link. Nothing in it comes
// from the visitor except the address.
func NoticeMessage(replaced bool, at time.Time, from netip.Addr) (subject, body string) {
	what := "An authenticator app was set up on your account."
	if replaced {
		what = "The authenticator app on your account was replaced."
	}
	src := "unknown"
	if from.IsValid() {
		src = from.Unmap().String()
	}
	return "Authenticator change on your account",
		what + " Time: " + at.UTC().Format("2006-01-02 15:04") + " UTC. Source address: " + src +
			". If this was not you, call the IT help desk now."
}

type dueNotice struct {
	ID       string
	Ref      DirectoryRef
	State    string
	Started  time.Time
	Replaced bool
	From     netip.Addr
}

// claim takes the notice for delivery by moving its next-attempt time past a lease, so two nodes never
// send it twice. ok is false when it is not due (or already sent).
func (s *SelfEnrolment) claim(ctx context.Context, t tenant.ID, id string) (n dueNotice, now time.Time, ok bool, err error) {
	err = s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err = s.now(ctx, tx)
		if err != nil {
			return err
		}
		n.ID = id
		var ip *netip.Addr
		e := tx.QueryRow(ctx, `UPDATE public.authn_authenticator_enrollments SET notice_next_at = $3
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'active' AND notice_state IN ('pending', 'failed') AND notice_next_at <= $4
RETURNING connection_id::text, object_guid::text, notice_state, notice_started_at, replaces IS NOT NULL,
  (SELECT client_ip FROM public.authn_enrolment_sessions x WHERE x.tenant_id = $1::uuid AND x.enrollment_id = $2::uuid LIMIT 1)`,
			t.String(), id, now.Add(noticeLease), now).
			Scan(&n.Ref.ConnectionID, &n.Ref.ObjectGUID, &n.State, &n.Started, &n.Replaced, &ip)
		if store.IsNoRows(e) {
			return nil
		}
		if e != nil {
			return e
		}
		if ip != nil {
			n.From = *ip
		}
		ok = true
		return nil
	})
	return n, now, ok, err
}

// deliver sends the notice of an activated enrolment to the contact data held in AD now. It reports whether
// the transport accepted it. A rejection is not an error: the enrolment stays active, cooling-off has not
// started, and RetryNotices tries again. Only a database fault is returned.
func (s *SelfEnrolment) deliver(ctx context.Context, t tenant.ID, id string) (bool, error) {
	n, now, ok, err := s.claim(ctx, t, id)
	if err != nil || !ok {
		return false, err
	}
	subject, body := NoticeMessage(n.Replaced, now, n.From)
	accepted := false
	reason := "no_contact_data"
	if contacts, cerr := s.Contacts.Held(ctx, t, n.Ref); cerr != nil {
		reason = "contact_lookup_failed"
	} else {
		for _, c := range contacts {
			if serr := s.Sender.Send(ctx, t, c, subject, body); serr == nil {
				accepted = true
			} else {
				reason = "transport_rejected"
			}
		}
	}
	err = s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		at, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		detail := audit.Detail{Key: "enrollment", Value: n.ID}
		if accepted {
			tag, err := tx.Exec(ctx, `UPDATE public.authn_authenticator_enrollments
SET notice_state = 'sent', cooling_off_until = $3, notice_attempts = notice_attempts + 1, notice_next_at = NULL
WHERE tenant_id = $1::uuid AND id = $2::uuid AND notice_state IN ('pending', 'failed')`, t.String(), n.ID, at.Add(CoolingOff))
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return nil
			}
			return s.emit(ctx, tx, KindNoticeSent, n.ID+".sent", n.Ref, audit.Success, "", n.From, detail)
		}
		// Failed. From pending the first failure is 'failed'; from 'failed' the failure after the give-up
		// time is the end state.
		if n.State == "failed" && !at.Before(n.Started.Add(NoticeGiveUp)) {
			if _, err := tx.Exec(ctx, `UPDATE public.authn_authenticator_enrollments
SET notice_state = 'abandoned', notice_attempts = notice_attempts + 1, notice_next_at = NULL
WHERE tenant_id = $1::uuid AND id = $2::uuid AND notice_state = 'failed'`, t.String(), n.ID); err != nil {
				return err
			}
			return s.emit(ctx, tx, KindNoticeAbandon, n.ID+".abandoned", n.Ref, audit.Failure, reason, n.From, detail)
		}
		var attempts int
		if err := tx.QueryRow(ctx, `UPDATE public.authn_authenticator_enrollments
SET notice_state = 'failed', notice_attempts = notice_attempts + 1, notice_next_at = $3
WHERE tenant_id = $1::uuid AND id = $2::uuid AND notice_state IN ('pending', 'failed') RETURNING notice_attempts`,
			t.String(), n.ID, at.Add(NoticeRetry)).Scan(&attempts); err != nil {
			if store.IsNoRows(err) {
				return nil
			}
			return err
		}
		return s.emit(ctx, tx, KindNoticeFailed, fmt.Sprintf("%s.failed.%d", n.ID, attempts), n.Ref, audit.Failure, reason, n.From, detail)
	})
	if err != nil {
		return false, err
	}
	return accepted, nil
}

// RetryNotices delivers the notices that are due: those still pending (a crash between activation and
// delivery) and those that failed, every NoticeRetry for NoticeGiveUp, after which the end state is
// 'abandoned'. A job calls it on a schedule per tenant. It returns how many it handled.
func (s *SelfEnrolment) RetryNotices(ctx context.Context, t tenant.ID, limit int) (int, error) {
	if err := s.ready(); err != nil {
		return 0, err
	}
	if t.IsZero() || limit <= 0 || limit > 1000 {
		return 0, ErrInvalid
	}
	var ids []string
	err := s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id::text FROM public.authn_authenticator_enrollments
WHERE tenant_id = $1::uuid AND state = 'active' AND notice_state IN ('pending', 'failed') AND notice_next_at <= $2
ORDER BY notice_next_at LIMIT $3`, t.String(), now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, fmt.Errorf("authn: list due notices: %w", err)
	}
	var errs []error
	for _, id := range ids {
		if _, err := s.deliver(ctx, t, id); err != nil {
			errs = append(errs, err)
		}
	}
	return len(ids), errors.Join(errs...)
}
