package helpdesk

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.helpdesk_caller_verifications", Entity: "DM-38", Kind: tablekind.Tenant})

// The rule set of ENH-09 §4. They are constants, not settings: a tenant cannot loosen them.
const (
	CodeLength          = 6
	Lifetime            = 5 * time.Minute // 4.2
	MaxAttempts         = 3               // 4.3
	TargetIssuesPerHour = 3               // 4.6
	TechIssuesPerHour   = 10              // 4.7
	TechFailedPerHour   = 5               // 4.7
	TechPause           = 15 * time.Minute
	VerifiedWindow      = 5 * time.Minute // 4.16
)

// Audit kinds (ENH-09 §4a C7, AC-OTP-13). None carries a code or a MAC.
const (
	KindIssued   audit.Kind = "authenticator.challenge.issued"
	KindRefused  audit.Kind = "authenticator.challenge.refused"
	KindFailed   audit.Kind = "authenticator.challenge.failed"
	KindVerified audit.Kind = "authenticator.challenge.verified"
	KindConsumed audit.Kind = "authenticator.challenge.consumed"
)

// Verifier issues, checks and consumes caller-verification challenges.
type Verifier struct {
	DB           *store.DB
	Audit        audit.Sink // bound to DB so an event commits with the change
	Destinations Destinations
	Authorizer   Authorizer
	Sender       Sender
	Keys         MACKey
	Clock        func() time.Time // nil: time.Now
}

func (v *Verifier) now() time.Time {
	if v.Clock != nil {
		return v.Clock().UTC()
	}
	return time.Now().UTC()
}

func (v *Verifier) ready() error {
	if v == nil || v.DB == nil || v.Audit == nil || v.Destinations == nil || v.Authorizer == nil || v.Sender == nil || v.Keys == nil {
		return errors.New("helpdesk: Verifier is not fully configured")
	}
	return nil
}

// IssueInput is one issue request. It is made on a user act (a POST from the sheet's key or click), never
// on route render (C1); Resend is the "Send a new code" act (C2, 4.5).
type IssueInput struct {
	Tenant     tenant.ID
	Technician string // the console account ID of the real human
	Target     Target
	Factor     Factor
	Resend     bool
}

// Challenge is what the technician sees: no code, a masked destination (4.14).
type Challenge struct {
	ID          string
	Factor      Factor
	Masked      string
	ExpiresAt   time.Time
	Reused      bool // an open challenge of this technician was attached to; nothing was sent (C2)
	Technician  string
	Destination string // alias of Masked, kept so callers never reach for Address
}

// Issue sends a code to the target's held destination. Checks run in the order of C3 and any failure
// sends nothing. Re-opening attaches to the technician's open challenge and sends nothing (C2).
func (v *Verifier) Issue(ctx context.Context, in IssueInput) (Challenge, error) {
	if err := v.ready(); err != nil {
		return Challenge{}, err
	}
	if in.Tenant.IsZero() || in.Technician == "" || !validUUID(in.Target.ConnectionID) || !validUUID(in.Target.ObjectGUID) || !in.Factor.valid() {
		return Challenge{}, ErrInvalid
	}
	in.Target = Target{ConnectionID: lower(in.Target.ConnectionID), ObjectGUID: lower(in.Target.ObjectGUID)}
	self, err := v.Authorizer.MayVerify(ctx, in.Tenant, in.Technician, in.Target)
	if err != nil {
		return Challenge{}, ErrNotAuthorised
	}
	if self != nil && *self == in.Target {
		return Challenge{}, ErrNotAuthorised // 4.15
	}
	offered, err := v.Destinations.Offered(ctx, in.Tenant, in.Target)
	if err != nil || !contains(offered, in.Factor) {
		return Challenge{}, ErrNoDestination
	}
	dest, err := v.Destinations.Resolve(ctx, in.Tenant, in.Target, in.Factor)
	if err != nil || dest.Address == "" || dest.Masked == "" {
		return Challenge{}, ErrNoDestination
	}
	key, err := v.Keys.Key(ctx, in.Tenant)
	if err != nil || len(key) < 16 {
		return Challenge{}, errors.New("helpdesk: no MAC key for the tenant")
	}
	code, err := newCode()
	if err != nil {
		return Challenge{}, err
	}
	id, err := newUUID()
	if err != nil {
		return Challenge{}, err
	}
	trigger := "sheet_open"
	if in.Resend {
		trigger = "resend"
	}
	var (
		out     Challenge
		outcome error
	)
	err = v.DB.WithTenant(ctx, in.Tenant, func(ctx context.Context, tx store.Tx) error {
		now := v.now()
		// One writer per target at a time: counters and the one-open rule are decided under this lock.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			"helpdesk.cv:"+in.Tenant.String()+":"+in.Target.ConnectionID+":"+in.Target.ObjectGUID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE public.helpdesk_caller_verifications SET state = 'expired'
WHERE tenant_id = $1::uuid AND connection_id = $2::uuid AND object_guid = $3::uuid AND state = 'issued' AND expires_at <= $4`,
			in.Tenant.String(), in.Target.ConnectionID, in.Target.ObjectGUID, now); err != nil {
			return err
		}
		if !in.Resend {
			var (
				openID, openFactor, openMask string
				openExp                      time.Time
			)
			err := tx.QueryRow(ctx, `SELECT id::text, factor, destination_masked, expires_at FROM public.helpdesk_caller_verifications
WHERE tenant_id = $1::uuid AND connection_id = $2::uuid AND object_guid = $3::uuid AND state = 'issued' AND technician_id = $4 AND factor = $5`,
				in.Tenant.String(), in.Target.ConnectionID, in.Target.ObjectGUID, in.Technician, string(in.Factor)).Scan(&openID, &openFactor, &openMask, &openExp)
			if err == nil {
				out = Challenge{ID: openID, Factor: Factor(openFactor), Masked: openMask, Destination: openMask, ExpiresAt: openExp, Reused: true, Technician: in.Technician}
				return nil
			}
			if !store.IsNoRows(err) {
				return err
			}
		}
		var paused bool
		if err := tx.QueryRow(ctx, `SELECT count(*) >= $3 AND max(failed_at) > $4 FROM public.helpdesk_caller_verifications
WHERE tenant_id = $1::uuid AND technician_id = $2 AND state = 'failed' AND failed_at > $5`,
			in.Tenant.String(), in.Technician, TechFailedPerHour, now.Add(-TechPause), now.Add(-time.Hour)).Scan(&paused); err != nil {
			return err
		}
		if paused {
			outcome = ErrPaused
			return nil
		}
		var perTarget, perTech int
		if err := tx.QueryRow(ctx, `SELECT
  (SELECT count(*) FROM public.helpdesk_caller_verifications WHERE tenant_id = $1::uuid AND connection_id = $3::uuid AND object_guid = $4::uuid AND counted AND created_at > $5),
  (SELECT count(*) FROM public.helpdesk_caller_verifications WHERE tenant_id = $1::uuid AND technician_id = $2 AND counted AND created_at > $5)`,
			in.Tenant.String(), in.Technician, in.Target.ConnectionID, in.Target.ObjectGUID, now.Add(-time.Hour)).Scan(&perTarget, &perTech); err != nil {
			return err
		}
		if perTarget >= TargetIssuesPerHour || perTech >= TechIssuesPerHour {
			outcome = ErrQuota
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE public.helpdesk_caller_verifications SET state = 'cancelled', cancel_reason = 'superseded'
WHERE tenant_id = $1::uuid AND connection_id = $2::uuid AND object_guid = $3::uuid AND state = 'issued'`,
			in.Tenant.String(), in.Target.ConnectionID, in.Target.ObjectGUID); err != nil {
			return err
		}
		exp := now.Add(Lifetime)
		if _, err := tx.Exec(ctx, `INSERT INTO public.helpdesk_caller_verifications
  (tenant_id, id, technician_id, connection_id, object_guid, factor, destination_masked, code_mac, trigger, created_at, expires_at)
VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5::uuid, $6, $7, $8, $9, $10, $11)`,
			in.Tenant.String(), id, in.Technician, in.Target.ConnectionID, in.Target.ObjectGUID, string(in.Factor), dest.Masked,
			codeMAC(key, id, code), trigger, now, exp); err != nil {
			return err
		}
		out = Challenge{ID: id, Factor: in.Factor, Masked: dest.Masked, Destination: dest.Masked, ExpiresAt: exp, Technician: in.Technician}
		return v.emit(ctx, tx, now, KindIssued, audit.Success, "", in.Tenant, in.Technician, in.Target, id, "",
			audit.Detail{Key: "challenge", Value: id}, audit.Detail{Key: "destination_masked", Value: dest.Masked},
			audit.Detail{Key: "factor", Value: string(in.Factor)}, audit.Detail{Key: "trigger", Value: trigger})
	})
	if err != nil {
		return Challenge{}, fmt.Errorf("helpdesk: issue: %w", err)
	}
	if outcome != nil {
		return Challenge{}, outcome
	}
	if out.Reused {
		return out, nil
	}
	if err := v.Sender.Send(ctx, in.Tenant, in.Factor, dest, CodeMessage(code)); err != nil {
		// 4.17: cancelled, released from the quota, and no code is shown as a fallback.
		_ = v.DB.WithTenant(ctx, in.Tenant, func(ctx context.Context, tx store.Tx) error {
			_, err := tx.Exec(ctx, `UPDATE public.helpdesk_caller_verifications SET state = 'cancelled', cancel_reason = 'delivery_failed', counted = false
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'issued'`, in.Tenant.String(), id)
			return err
		})
		return Challenge{}, ErrDelivery
	}
	if err := v.DB.WithTenant(ctx, in.Tenant, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE public.helpdesk_caller_verifications SET delivered_at = $3
WHERE tenant_id = $1::uuid AND id = $2::uuid AND state = 'issued'`, in.Tenant.String(), id, v.now())
		return err
	}); err != nil {
		return Challenge{}, fmt.Errorf("helpdesk: record delivery: %w", err)
	}
	return out, nil
}

// VerifyInput is the code the caller read back.
type VerifyInput struct {
	Tenant      tenant.ID
	Technician  string
	ChallengeID string
	Code        string
}

// Verified says a challenge passed and until when it may authorise one operation.
type Verified struct {
	ChallengeID string
	Until       time.Time
}

// Verify checks the code. The attempt is charged under the row lock before the code is compared, so
// parallel guesses on any node cannot exceed MaxAttempts (4.3, 4.9). Every failure, the cap and a wrong
// code alike, is ErrRefused.
func (v *Verifier) Verify(ctx context.Context, in VerifyInput) (Verified, error) {
	if err := v.ready(); err != nil {
		return Verified{}, err
	}
	if in.Tenant.IsZero() || in.Technician == "" || !validUUID(in.ChallengeID) {
		return Verified{}, ErrRefused
	}
	key, err := v.Keys.Key(ctx, in.Tenant)
	if err != nil || len(key) < 16 {
		return Verified{}, errors.New("helpdesk: no MAC key for the tenant")
	}
	var (
		res     Verified
		outcome = ErrRefused
	)
	err = v.DB.WithTenant(ctx, in.Tenant, func(ctx context.Context, tx store.Tx) error {
		now := v.now()
		var (
			tech, state, conn, guid string
			attempts                int
			mac                     []byte
			exp                     time.Time
		)
		err := tx.QueryRow(ctx, `SELECT technician_id, state, attempts, code_mac, expires_at, connection_id::text, object_guid::text
FROM public.helpdesk_caller_verifications WHERE tenant_id = $1::uuid AND id = $2::uuid FOR UPDATE`,
			in.Tenant.String(), in.ChallengeID).Scan(&tech, &state, &attempts, &mac, &exp, &conn, &guid)
		if store.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if tech != in.Technician || state != "issued" {
			return nil
		}
		target := Target{ConnectionID: conn, ObjectGUID: guid}
		if !now.Before(exp) {
			_, err := tx.Exec(ctx, `UPDATE public.helpdesk_caller_verifications SET state = 'expired' WHERE tenant_id = $1::uuid AND id = $2::uuid`,
				in.Tenant.String(), in.ChallengeID)
			return err
		}
		if attempts >= MaxAttempts {
			return nil // already failed in the call that spent the last attempt; unreachable, kept as a bound
		}
		attempts++
		if mac != nil && hmac.Equal(mac, codeMAC(key, in.ChallengeID, in.Code)) {
			until := now.Add(VerifiedWindow)
			if _, err := tx.Exec(ctx, `UPDATE public.helpdesk_caller_verifications SET state = 'verified', attempts = $3, verified_at = $4, authorised_until = $5
WHERE tenant_id = $1::uuid AND id = $2::uuid`, in.Tenant.String(), in.ChallengeID, attempts, now, until); err != nil {
				return err
			}
			res, outcome = Verified{ChallengeID: in.ChallengeID, Until: until}, nil
			return v.emit(ctx, tx, now, KindVerified, audit.Success, "", in.Tenant, tech, target, in.ChallengeID, "",
				audit.Detail{Key: "attempt", Value: itoa(attempts)}, audit.Detail{Key: "challenge", Value: in.ChallengeID})
		}
		if attempts >= MaxAttempts {
			if _, err := tx.Exec(ctx, `UPDATE public.helpdesk_caller_verifications SET state = 'failed', attempts = $3, failed_at = $4
WHERE tenant_id = $1::uuid AND id = $2::uuid`, in.Tenant.String(), in.ChallengeID, attempts, now); err != nil {
				return err
			}
			return v.emit(ctx, tx, now, KindFailed, audit.Denied, "attempts_exhausted", in.Tenant, tech, target, in.ChallengeID, "",
				audit.Detail{Key: "attempt", Value: itoa(attempts)}, audit.Detail{Key: "challenge", Value: in.ChallengeID})
		}
		if _, err := tx.Exec(ctx, `UPDATE public.helpdesk_caller_verifications SET attempts = $3 WHERE tenant_id = $1::uuid AND id = $2::uuid`,
			in.Tenant.String(), in.ChallengeID, attempts); err != nil {
			return err
		}
		return v.emit(ctx, tx, now, KindRefused, audit.Denied, "wrong_code", in.Tenant, tech, target, in.ChallengeID, "",
			audit.Detail{Key: "attempt", Value: itoa(attempts)}, audit.Detail{Key: "challenge", Value: in.ChallengeID})
	})
	if err != nil {
		return Verified{}, fmt.Errorf("helpdesk: verify: %w", err)
	}
	if outcome != nil {
		return Verified{}, outcome
	}
	return res, nil
}

// AuthoriseInput names the one operation a verified challenge is spent on.
type AuthoriseInput struct {
	Tenant      tenant.ID
	Technician  string
	ChallengeID string
	Target      Target
	Action      string // an ActionID in StepUpActions
	Operation   step.OperationID
}

// Authorise spends a verified challenge, once, for the technician and target it was issued for, inside its
// window (4.16, DM-38.I3). It writes the audit event that records which factor verified the caller, apart
// from the technician's own identity (DM-38.I4), and returns the Grant that Bind turns into a satisfied step-up.
func (v *Verifier) Authorise(ctx context.Context, in AuthoriseInput) (Grant, error) {
	if err := v.ready(); err != nil {
		return Grant{}, err
	}
	if in.Tenant.IsZero() || in.Technician == "" || !validUUID(in.ChallengeID) || in.Operation == "" || !stepUpActions[in.Action] {
		return Grant{}, ErrRefused
	}
	var (
		g       Grant
		outcome = ErrRefused
	)
	err := v.DB.WithTenant(ctx, in.Tenant, func(ctx context.Context, tx store.Tx) error {
		now := v.now()
		var (
			tech, state, conn, guid, factor string
			until                           *time.Time
		)
		err := tx.QueryRow(ctx, `SELECT technician_id, state, connection_id::text, object_guid::text, factor, authorised_until
FROM public.helpdesk_caller_verifications WHERE tenant_id = $1::uuid AND id = $2::uuid FOR UPDATE`,
			in.Tenant.String(), in.ChallengeID).Scan(&tech, &state, &conn, &guid, &factor, &until)
		if store.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if tech != in.Technician || state != "verified" || until == nil || conn != lower(in.Target.ConnectionID) || guid != lower(in.Target.ObjectGUID) {
			return nil
		}
		if !now.Before(*until) {
			_, err := tx.Exec(ctx, `UPDATE public.helpdesk_caller_verifications SET state = 'expired' WHERE tenant_id = $1::uuid AND id = $2::uuid`,
				in.Tenant.String(), in.ChallengeID)
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE public.helpdesk_caller_verifications SET state = 'consumed', consumed_at = $3, consumed_operation = $4
WHERE tenant_id = $1::uuid AND id = $2::uuid`, in.Tenant.String(), in.ChallengeID, now, string(in.Operation)); err != nil {
			return err
		}
		g = Grant{tenant: in.Tenant, technician: tech, target: Target{ConnectionID: conn, ObjectGUID: guid},
			action: in.Action, operation: in.Operation, factor: Factor(factor), challenge: in.ChallengeID}
		outcome = nil
		return v.emit(ctx, tx, now, KindConsumed, audit.Success, "", in.Tenant, tech, g.target, in.ChallengeID, in.Operation,
			audit.Detail{Key: "action", Value: in.Action}, audit.Detail{Key: "challenge", Value: in.ChallengeID},
			audit.Detail{Key: "operation", Value: string(in.Operation)}, audit.Detail{Key: "verified_by_factor", Value: factor})
	})
	if err != nil {
		return Grant{}, fmt.Errorf("helpdesk: authorise: %w", err)
	}
	if outcome != nil {
		return Grant{}, outcome
	}
	return g, nil
}

func (v *Verifier) emit(ctx context.Context, tx store.Tx, at time.Time, kind audit.Kind, out audit.Outcome, reason string,
	t tenant.ID, technician string, target Target, challenge string, op step.OperationID, details ...audit.Detail) error {
	ev := audit.Event{
		// One event per kind, challenge and attempt: a retried transaction rewrites the same ID.
		ID:   "helpdesk.cv." + challenge + "." + string(kind) + "." + at.Format("20060102T150405.000000000Z"),
		Kind: kind, At: at,
		Actor:     authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(technician), Kind: authority.Human}},
		Target:    authority.TargetRef{Connection: target.ConnectionID, GUID: target.ObjectGUID, Class: "user"},
		Key:       step.Key{Operation: op},
		Component: "helpdesk", Outcome: out, Reason: reason, Details: details,
	}
	if err := v.Audit.Append(ctx, tx, ev); err != nil {
		return fmt.Errorf("helpdesk: audit %s: %w", kind, err)
	}
	return nil
}

// codeMAC is the keyed MAC stored in place of the code. It binds the challenge ID so a MAC copied to
// another row verifies nothing.
func codeMAC(key []byte, challengeID, code string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("activediq helpdesk otp v1\x00" + challengeID + "\x00" + code))
	return m.Sum(nil)
}

// newCode returns CodeLength digits, uniform, leading zeros kept (4.1).
func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("helpdesk: no entropy: %w", err)
	}
	return fmt.Sprintf("%0*d", CodeLength, n.Int64()), nil
}
