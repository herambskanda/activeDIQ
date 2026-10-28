package saml

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tablekind"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var _ = tablekind.Declare(tablekind.Table{Name: "public.authn_saml_replay", Entity: "DM-39", Kind: tablekind.Tenant})

// ErrReplayInput is returned for a Remember call that cannot be recorded: no tenant, an empty or oversized
// IdP or assertion ID, or an expiry that is not in the future (or more than 24 hours away). Nothing is
// written. The caller must not treat it as "fresh": the assertion is refused.
var ErrReplayInput = errors.New("saml: replay cache: invalid input")

const (
	maxIDPLen       = 256
	maxAssertionLen = 1024
)

// PGReplayCache is the shared ReplayCache (DM-39.I5, SAML-16): rows live in authn_saml_replay, so every
// node refuses an assertion any node has accepted. Safe for concurrent use.
//
// The primary key is the check: INSERT ... ON CONFLICT DO NOTHING reports whether the row was new, and two
// racing nodes cannot both win. Time is the database's, never a node's, so clock skew between nodes
// cannot shorten a replay window.
type PGReplayCache struct{ db *store.DB }

var _ ReplayCache = (*PGReplayCache)(nil)

// NewPGReplayCache returns a PGReplayCache over db (the runtime-role store).
func NewPGReplayCache(db *store.DB) (*PGReplayCache, error) {
	if db == nil {
		return nil, errors.New("saml: PGReplayCache needs a database")
	}
	return &PGReplayCache{db: db}, nil
}

// Remember implements ReplayCache in its own tenant transaction. The sign-in callback, which must record
// the assertion in the transaction that consumes the SSO Transaction (SAML-16), calls RememberTx instead.
func (c *PGReplayCache) Remember(ctx context.Context, t tenant.ID, idpID, assertionID string, until time.Time) (bool, error) {
	if err := checkReplayInput(t, idpID, assertionID); err != nil {
		return false, err
	}
	var fresh bool
	err := c.db.WithTenant(ctx, t, func(ctx context.Context, tx store.Tx) error {
		var err error
		fresh, err = RememberTx(ctx, tx, t, idpID, assertionID, until)
		return err
	})
	if err != nil {
		return false, err
	}
	return fresh, nil
}

const (
	// Trims this tenant's expired rows (the DELETE policy refuses any other), so the table stays small
	// without a scheduled job, and an expired row never blocks a later insert of the same ID.
	sqlReplayTrim = `DELETE FROM public.authn_saml_replay WHERE tenant_id = $1::uuid AND expires_at <= clock_timestamp()`

	sqlReplayInsert = `INSERT INTO public.authn_saml_replay (tenant_id, idp_id, assertion_id, expires_at)
VALUES ($1::uuid, $2, $3, $4)
ON CONFLICT (tenant_id, idp_id, assertion_id) DO NOTHING`
)

// RememberTx records the assertion inside the caller's tenant transaction, so the row commits or rolls
// back with the consumption of the sign-in Transaction. It reports whether the assertion was new; a
// duplicate is the replay, not an error. tx must be a transaction of tenant t (WithTenant sets the
// tenant that row security checks; a different one makes the insert fail, never write to another tenant).
func RememberTx(ctx context.Context, tx store.Tx, t tenant.ID, idpID, assertionID string, until time.Time) (bool, error) {
	if err := checkReplayInput(t, idpID, assertionID); err != nil {
		return false, err
	}
	if until.IsZero() {
		return false, ErrReplayInput
	}
	if _, err := tx.Exec(ctx, sqlReplayTrim, t.String()); err != nil {
		return false, fmt.Errorf("saml: replay cache: trim: %w", err)
	}
	tag, err := tx.Exec(ctx, sqlReplayInsert, t.String(), idpID, assertionID, until.UTC())
	if err != nil {
		if store.SQLState(err) == "23514" { // check_violation: expiry not in (now, now+24h]
			return false, ErrReplayInput
		}
		return false, fmt.Errorf("saml: replay cache: record: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func checkReplayInput(t tenant.ID, idpID, assertionID string) error {
	if t.IsZero() || idpID == "" || assertionID == "" || len(idpID) > maxIDPLen || len(assertionID) > maxAssertionLen {
		return ErrReplayInput
	}
	return nil
}
