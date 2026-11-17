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

// enrolSession is a live pending enrolment, read by its handle.
type enrolSession struct {
	ID           string
	Ref          DirectoryRef
	Proved       bool // the existing factor's code was given (6.3a)
	EnrollmentID string
	From         netip.Addr
	Confirmed    int
}

// load reads the session without charging it.
func (s *SelfEnrolment) load(ctx context.Context, tx store.Tx, t tenant.ID, h EnrolHandle, now time.Time) (enrolSession, error) {
	var (
		es  enrolSession
		eid *string
		ip  *netip.Addr
	)
	err := tx.QueryRow(ctx, `SELECT id::text, connection_id::text, object_guid::text, existing_proved, enrollment_id::text, client_ip, confirmations
FROM public.authn_enrolment_sessions
WHERE tenant_id = $1::uuid AND handle_hash = $2 AND consumed_at IS NULL AND expires_at > $3 AND confirmations < $4`,
		t.String(), h.hash(), now, MaxConfirmAttempts).
		Scan(&es.ID, &es.Ref.ConnectionID, &es.Ref.ObjectGUID, &es.Proved, &eid, &ip, &es.Confirmed)
	if store.IsNoRows(err) {
		return enrolSession{}, ErrEnrolSession
	}
	if err != nil {
		return enrolSession{}, fmt.Errorf("authn: read enrolment session: %w", err)
	}
	es.EnrollmentID = deref(eid)
	if ip != nil {
		es.From = *ip
	}
	return es, nil
}

// charge spends one of the session's 5 confirmations in its own committed transaction, before the code is
// looked at, so a request that rolls back cannot undo it and parallel requests cannot exceed the cap.
func (s *SelfEnrolment) charge(ctx context.Context, t tenant.ID, h EnrolHandle) (enrolSession, error) {
	var es enrolSession
	var out error
	err := s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		var eid *string
		var ip *netip.Addr
		err = tx.QueryRow(ctx, `UPDATE public.authn_enrolment_sessions SET confirmations = confirmations + 1
WHERE tenant_id = $1::uuid AND handle_hash = $2 AND consumed_at IS NULL AND expires_at > $3 AND confirmations < $4
RETURNING id::text, connection_id::text, object_guid::text, existing_proved, enrollment_id::text, client_ip, confirmations`,
			t.String(), h.hash(), now, MaxConfirmAttempts).
			Scan(&es.ID, &es.Ref.ConnectionID, &es.Ref.ObjectGUID, &es.Proved, &eid, &ip, &es.Confirmed)
		if store.IsNoRows(err) {
			out = ErrEnrolSession
			return nil
		}
		if err != nil {
			return err
		}
		es.EnrollmentID = deref(eid)
		if ip != nil {
			es.From = *ip
		}
		return nil
	})
	if err != nil {
		return enrolSession{}, fmt.Errorf("authn: charge enrolment confirmation: %w", err)
	}
	return es, out
}

// activeFactors lists the user's active TOTP enrolments.
func activeFactors(ctx context.Context, tx store.Tx, t tenant.ID, ref DirectoryRef, lock bool) ([]string, error) {
	const q = `SELECT id::text FROM public.authn_authenticator_enrollments
WHERE tenant_id = $1::uuid AND connection_id = $2::uuid AND object_guid = $3::uuid AND method = 'totp' AND state = 'active'
ORDER BY created_at, id`
	const qLock = q + ` FOR UPDATE`
	query := q
	if lock {
		query = qLock
	}
	rows, err := tx.Query(ctx, query, t.String(), ref.ConnectionID, ref.ObjectGUID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	return ids, rows.Err()
}

func (s *SelfEnrolment) refuse(ctx context.Context, t tenant.ID, es enrolSession, reason string, from netip.Addr) error {
	if err := s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		return s.emit(ctx, tx, KindEnrolRefused, "", es.Ref, audit.Denied, reason, from, audit.Detail{Key: "stage", Value: "start"})
	}); err != nil {
		return fmt.Errorf("authn: record enrolment refusal: %w", err)
	}
	return ErrEnrolHelpDesk
}

// Start creates the pending seed for the user the handle names. currentCode is the code of the user's
// existing factor, needed only when they have one (6.3a). Without held contact data, or with an active
// factor and no valid current code, it is ErrEnrolHelpDesk and no seed exists. The seed is returned once;
// the caller shows it and destroys it. Confirm completes the enrolment.
func (s *SelfEnrolment) Start(ctx context.Context, h EnrolHandle, currentCode string, from netip.Addr) (Provisioned, error) {
	if err := s.ready(); err != nil {
		return Provisioned{}, err
	}
	t, err := h.tok.Tenant()
	if err != nil {
		return Provisioned{}, ErrEnrolSession
	}
	var (
		es      enrolSession
		actives []string
	)
	if err := s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		if es, err = s.load(ctx, tx, t, h, now); err != nil {
			return err
		}
		actives, err = activeFactors(ctx, tx, t, es.Ref, false)
		return err
	}); err != nil {
		if errors.Is(err, ErrEnrolSession) {
			return Provisioned{}, err
		}
		return Provisioned{}, fmt.Errorf("authn: start enrolment: %w", err)
	}

	// The notice needs somewhere to go: no held destination, no enrolment (6.5).
	contacts, err := s.Contacts.Held(ctx, t, es.Ref)
	if err != nil {
		return Provisioned{}, fmt.Errorf("authn: held contact data: %w", err)
	}
	if len(contacts) == 0 {
		return Provisioned{}, s.refuse(ctx, t, es, EnrolNoContact, from)
	}

	proved := es.Proved
	if len(actives) > 0 && !proved {
		// 6.3a: only the holder of the existing factor may replace it. A technician reset (6.4) revokes it
		// first, so then there is nothing active and this branch is not taken.
		if currentCode == "" {
			return Provisioned{}, s.refuse(ctx, t, es, EnrolFactorRequired, from)
		}
		if _, err := s.charge(ctx, t, h); err != nil {
			return Provisioned{}, err
		}
		for _, id := range actives {
			err := s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
				return s.Factors.Verify(ctx, tx, t, id, currentCode)
			})
			switch {
			case err == nil:
				proved = true
			case errors.Is(err, ErrCodeRejected), errors.Is(err, ErrCodeReplayed), errors.Is(err, ErrFactorPaused):
			default:
				return Provisioned{}, fmt.Errorf("authn: verify existing factor: %w", err)
			}
			if proved {
				break
			}
		}
		if !proved {
			return Provisioned{}, s.refuse(ctx, t, es, EnrolFactorNotProved, from)
		}
	}

	var out Provisioned
	err = s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		cur, err := s.load(ctx, tx, t, h, now)
		if err != nil {
			return err
		}
		if cur.EnrollmentID != "" { // the user restarts: the previous pending seed is discarded
			if _, err := tx.Exec(ctx, `UPDATE public.authn_authenticator_enrollments SET state = 'expired', sealed_secret = NULL
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'pending'`, t.String(), cur.EnrollmentID); err != nil {
				return err
			}
		}
		p, err := s.Factors.Enroll(ctx, tx, t, Subject{ConnectionID: es.Ref.ConnectionID, ObjectGUID: es.Ref.ObjectGUID}, enrolFactorName)
		if err != nil {
			return err
		}
		out = p
		// An existing-code attempt that passed is refunded: 5 confirmations are for the new seed.
		tag, err := tx.Exec(ctx, `UPDATE public.authn_enrolment_sessions
SET enrollment_id = $3::uuid, existing_proved = $4, confirmations = CASE WHEN $5 THEN GREATEST(confirmations - 1, 0) ELSE confirmations END
WHERE tenant_id = $1::uuid AND id = $2::uuid AND consumed_at IS NULL`, t.String(), es.ID, p.ID, proved, proved && !es.Proved)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrEnrolSession
		}
		return nil
	})
	if err != nil {
		out.Seed.Destroy()
		if errors.Is(err, ErrEnrolSession) {
			return Provisioned{}, err
		}
		return Provisioned{}, fmt.Errorf("authn: start enrolment: %w", err)
	}
	return out, nil
}

// ConfirmResult tells the page what happened. NoticeSent is false when delivery failed and is being retried.
type ConfirmResult struct {
	Replaced   bool
	NoticeSent bool
}

// Confirm checks the first code of the pending seed. Each call spends one of the handle's 5 confirmations.
// On success, in one transaction: the factor is active, the factor it replaces is revoked, the notice is
// queued, the handle is consumed and the events are chained. The notice is then delivered (6.5).
func (s *SelfEnrolment) Confirm(ctx context.Context, h EnrolHandle, code string, from netip.Addr) (ConfirmResult, error) {
	if err := s.ready(); err != nil {
		return ConfirmResult{}, err
	}
	t, err := h.tok.Tenant()
	if err != nil {
		return ConfirmResult{}, ErrEnrolSession
	}
	es, err := s.charge(ctx, t, h)
	if err != nil {
		return ConfirmResult{}, err
	}
	if es.EnrollmentID == "" {
		return ConfirmResult{}, ErrEnrolSession // no seed was started on this handle
	}
	var (
		res  ConfirmResult
		fail error
	)
	err = s.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now, err := s.now(ctx, tx)
		if err != nil {
			return err
		}
		// The old factors, locked: a replacement without proof of the old one is refused even if the factor
		// appeared after Start.
		olds, err := activeFactors(ctx, tx, t, es.Ref, true)
		if err != nil {
			return err
		}
		if len(olds) > 0 && !es.Proved {
			fail = ErrEnrolHelpDesk
			return s.emit(ctx, tx, KindEnrolRefused, "", es.Ref, audit.Denied, EnrolFactorNotProved, from, audit.Detail{Key: "stage", Value: "confirm"})
		}
		if err := s.Factors.Activate(ctx, tx, t, es.EnrollmentID, code); err != nil {
			switch {
			case errors.Is(err, ErrCodeRejected), errors.Is(err, ErrCodeReplayed), errors.Is(err, ErrFactorPaused):
				fail = ErrEnrolCodeRejected
				reason := EnrolCodeRejected
				if es.Confirmed >= MaxConfirmAttempts {
					reason = EnrolAttemptsExhausted
					if _, err := tx.Exec(ctx, `UPDATE public.authn_enrolment_sessions SET consumed_at = $3 WHERE tenant_id = $1::uuid AND id = $2::uuid AND consumed_at IS NULL`,
						t.String(), es.ID, now); err != nil {
						return err
					}
				}
				return s.emit(ctx, tx, KindEnrolFailed, "", es.Ref, audit.Failure, reason, from, audit.Detail{Key: "enrollment", Value: es.EnrollmentID})
			}
			return err
		}
		var previous string
		for i, old := range olds {
			if i == 0 {
				previous = old
			}
			if _, err := tx.Exec(ctx, `UPDATE public.authn_authenticator_enrollments SET state = 'revoked', sealed_secret = NULL
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'active'`, t.String(), old); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE public.authn_authenticator_enrollments
SET replaces = NULLIF($3, '')::uuid, notice_state = 'pending', notice_started_at = $4, notice_next_at = $4
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'active'`, t.String(), es.EnrollmentID, previous, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE public.authn_enrolment_sessions SET consumed_at = $3 WHERE tenant_id = $1::uuid AND id = $2::uuid AND consumed_at IS NULL`,
			t.String(), es.ID, now); err != nil {
			return err
		}
		if err := s.emit(ctx, tx, KindEnrolConfirmed, es.EnrollmentID, es.Ref, audit.Success, "", from, audit.Detail{Key: "enrollment", Value: es.EnrollmentID}); err != nil {
			return err
		}
		if previous != "" {
			res.Replaced = true
			return s.emit(ctx, tx, KindEnrolReplaced, es.EnrollmentID, es.Ref, audit.Success, "", from,
				audit.Detail{Key: "enrollment", Value: es.EnrollmentID}, audit.Detail{Key: "previous", Value: previous})
		}
		return nil
	})
	if err != nil {
		return ConfirmResult{}, fmt.Errorf("authn: confirm enrolment: %w", err)
	}
	if fail != nil {
		return ConfirmResult{}, fail
	}
	// The factor is active whatever happens to the notice; a failure is retried by RetryNotices.
	sent, err := s.deliver(ctx, t, es.EnrollmentID)
	if err != nil {
		return res, fmt.Errorf("authn: deliver enrolment notice: %w", err)
	}
	res.NoticeSent = sent
	return res, nil
}
