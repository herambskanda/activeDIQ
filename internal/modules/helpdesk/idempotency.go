package helpdesk

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.helpdesk_request_keys", Entity: "DM-38", Kind: tablekind.Tenant})

// Idempotency errors.
var (
	// ErrKeyInvalid is an Idempotency-Key outside the contract's shape.
	ErrKeyInvalid = errors.New("helpdesk: invalid idempotency key")
	// ErrKeyReuse is a key already used by this technician for a different request.
	ErrKeyReuse = errors.New("helpdesk: idempotency key used with a different request")
	// ErrKeyInFlight is a key whose first request has not finished; the retry is told to wait, never run twice.
	ErrKeyInFlight = errors.New("helpdesk: a request with this idempotency key is still being processed")
)

// KeyPending is how long a claimed key holds before a crashed first attempt may be retried.
const KeyPending = time.Minute

var keyRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{8,128}$`)

// requestMAC is the keyed MAC of a request, stored in place of the request. A verify body holds the code, so a
// bare hash would be reversible by trying a million values; keyed under the tenant key it is not.
func requestMAC(key []byte, op, technician, subject, body string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("activediq helpdesk idem v1\x00" + op + "\x00" + technician + "\x00" + subject + "\x00" + body))
	return m.Sum(nil)
}

type claim struct {
	replay bool
	row    keyRow
}

type keyRow struct {
	challenge, factor, masked string
	expires, until            *time.Time
	ok                        *bool
}

// claimKey claims (technician, op, key) or finds what a first attempt recorded. A claim that is pending and fresh
// is ErrKeyInFlight; abandoned and stale-pending claims are taken over.
func (v *Verifier) claimKey(ctx context.Context, t tenant.ID, technician, op, key string, mac []byte) (claim, error) {
	var c claim
	err := v.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		now := v.now()
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			"helpdesk.rk:"+t.String()+":"+technician+":"+op+":"+key); err != nil {
			return err
		}
		var (
			state   string
			stored  []byte
			created time.Time
			r       keyRow
			chal    *string
			factor  *string
			masked  *string
		)
		err := tx.QueryRow(ctx, `SELECT state, request_mac, created_at, result_challenge::text, result_factor, result_masked, result_expires, result_ok, result_until
FROM public.helpdesk_request_keys WHERE tenant_id = $1::uuid AND technician_id = $2 AND operation = $3 AND idem_key = $4 FOR UPDATE`,
			t.String(), technician, op, key).Scan(&state, &stored, &created, &chal, &factor, &masked, &r.expires, &r.ok, &r.until)
		switch {
		case store.IsNoRows(err):
			_, err := tx.Exec(ctx, `INSERT INTO public.helpdesk_request_keys (tenant_id, technician_id, operation, idem_key, request_mac, created_at)
VALUES ($1::uuid, $2, $3, $4, $5, $6)`, t.String(), technician, op, key, mac, now)
			return err
		case err != nil:
			return err
		}
		if !hmac.Equal(stored, mac) {
			return ErrKeyReuse
		}
		switch {
		case state == "done":
			if chal != nil {
				r.challenge = *chal
			}
			if factor != nil {
				r.factor = *factor
			}
			if masked != nil {
				r.masked = *masked
			}
			c = claim{replay: true, row: r}
			return nil
		case state == "pending" && now.Before(created.Add(KeyPending)):
			return ErrKeyInFlight
		}
		_, err = tx.Exec(ctx, `UPDATE public.helpdesk_request_keys SET state = 'pending', created_at = $5
WHERE tenant_id = $1::uuid AND technician_id = $2 AND operation = $3 AND idem_key = $4`, t.String(), technician, op, key, now)
		return err
	})
	return c, err
}

// finishKey records the outcome of a claimed key, or abandons it when the work ended with no outcome worth
// replaying (a refusal that may differ next time, an infrastructure fault).
func (v *Verifier) finishKey(ctx context.Context, t tenant.ID, technician, op, key string, r *keyRow) {
	_ = v.DB.WithTenant(context.WithoutCancel(ctx), t, func(ctx context.Context, tx store.Tx) error {
		if r == nil {
			_, err := tx.Exec(ctx, `UPDATE public.helpdesk_request_keys SET state = 'abandoned'
WHERE tenant_id = $1::uuid AND technician_id = $2 AND operation = $3 AND idem_key = $4 AND state = 'pending'`, t.String(), technician, op, key)
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE public.helpdesk_request_keys SET state = 'done', completed_at = $5,
  result_challenge = NULLIF($6, '')::uuid, result_factor = NULLIF($7, ''), result_masked = NULLIF($8, ''), result_expires = $9, result_ok = $10, result_until = $11
WHERE tenant_id = $1::uuid AND technician_id = $2 AND operation = $3 AND idem_key = $4 AND state = 'pending'`,
			t.String(), technician, op, key, v.now(), r.challenge, r.factor, r.masked, r.expires, r.ok, r.until)
		return err
	})
}

// PurgeRequestKeys removes keys older than before. Keys are honoured for 24 hours; a retention job calls this.
func (v *Verifier) PurgeRequestKeys(ctx context.Context, t tenant.ID, before time.Time) (int64, error) {
	if err := v.ready(); err != nil {
		return 0, err
	}
	var n int64
	err := v.DB.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM public.helpdesk_request_keys WHERE tenant_id = $1::uuid AND created_at < $2`, t.String(), before)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return nil
	})
	return n, err
}

// IssueOnce is Issue made safe to retry: the same key and request answers what the first attempt answered and
// sends nothing; the same key with another request is ErrKeyReuse. Only a success is recorded, so a refusal
// (quota, pause, delivery) is evaluated again on a retry.
func (v *Verifier) IssueOnce(ctx context.Context, key string, in IssueInput) (Challenge, error) {
	if err := v.ready(); err != nil {
		return Challenge{}, err
	}
	if !keyRe.MatchString(key) {
		return Challenge{}, ErrKeyInvalid
	}
	if in.Tenant.IsZero() || in.Technician == "" || !validUUID(in.Target.ConnectionID) || !validUUID(in.Target.ObjectGUID) || !in.Factor.valid() {
		return Challenge{}, ErrInvalid
	}
	mk, err := v.Keys.Key(ctx, in.Tenant)
	if err != nil || len(mk) < 16 {
		return Challenge{}, errors.New("helpdesk: no MAC key for the tenant")
	}
	body := string(in.Factor) + "\x00" + fmt.Sprint(in.Resend)
	mac := requestMAC(mk, "issue", in.Technician, lower(in.Target.ConnectionID)+"/"+lower(in.Target.ObjectGUID), body)
	c, err := v.claimKey(ctx, in.Tenant, in.Technician, "issue", key, mac)
	if err != nil {
		return Challenge{}, err
	}
	if c.replay {
		if c.row.expires == nil {
			return Challenge{}, ErrRefused
		}
		return Challenge{ID: c.row.challenge, Factor: Factor(c.row.factor), Masked: c.row.masked, Destination: c.row.masked,
			ExpiresAt: *c.row.expires, Reused: true, Technician: in.Technician}, nil
	}
	ch, err := v.Issue(ctx, in)
	if err != nil {
		v.finishKey(ctx, in.Tenant, in.Technician, "issue", key, nil)
		return Challenge{}, err
	}
	exp := ch.ExpiresAt
	v.finishKey(ctx, in.Tenant, in.Technician, "issue", key, &keyRow{challenge: ch.ID, factor: string(ch.Factor), masked: ch.Masked, expires: &exp})
	return ch, nil
}

// VerifyOnce is Verify made safe to retry: a retry of the same key and request replays the first answer, pass
// or refusal alike, and charges no second attempt. The same key with another code or challenge is ErrKeyReuse.
func (v *Verifier) VerifyOnce(ctx context.Context, key string, in VerifyInput) (Verified, error) {
	if err := v.ready(); err != nil {
		return Verified{}, err
	}
	if !keyRe.MatchString(key) {
		return Verified{}, ErrKeyInvalid
	}
	if in.Tenant.IsZero() || in.Technician == "" || !validUUID(in.ChallengeID) {
		return Verified{}, ErrRefused
	}
	mk, err := v.Keys.Key(ctx, in.Tenant)
	if err != nil || len(mk) < 16 {
		return Verified{}, errors.New("helpdesk: no MAC key for the tenant")
	}
	mac := requestMAC(mk, "verify", in.Technician, lower(in.ChallengeID), in.Code)
	c, err := v.claimKey(ctx, in.Tenant, in.Technician, "verify", key, mac)
	if err != nil {
		return Verified{}, err
	}
	if c.replay {
		if c.row.ok == nil || !*c.row.ok || c.row.until == nil {
			return Verified{}, ErrRefused
		}
		return Verified{ChallengeID: in.ChallengeID, Until: *c.row.until}, nil
	}
	res, err := v.Verify(ctx, in)
	ok := err == nil
	switch {
	case ok:
		until := res.Until
		v.finishKey(ctx, in.Tenant, in.Technician, "verify", key, &keyRow{challenge: in.ChallengeID, ok: &ok, until: &until})
	case errors.Is(err, ErrRefused):
		v.finishKey(ctx, in.Tenant, in.Technician, "verify", key, &keyRow{challenge: in.ChallengeID, ok: &ok})
	default:
		v.finishKey(ctx, in.Tenant, in.Technician, "verify", key, nil)
	}
	return res, err
}
