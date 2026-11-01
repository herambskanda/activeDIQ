package authn

import (
	"context"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// ThrottlePurgeMargin is how long past ThrottleWindow a row is kept before it is deleted. The window
// is judged by the sign-in path's own clock; the margin keeps the purge from racing a row that a
// slightly-behind node still treats as live. The job that calls PurgeThrottle on a cadence lives in
// authn/throttlejob (ADR-0005 rule 13: authn does not import jobs).
const ThrottlePurgeMargin = 5 * time.Minute

// sqlPurgeThrottle deletes the tenant's rows whose window ended before $2 and whose not_before delay has
// passed ($3): a key still inside its delay is live whatever its window says. RLS also binds the tenant.
const sqlPurgeThrottle = `DELETE FROM public.authn_signin_throttle
WHERE tenant_id = $1::uuid AND window_start < $2 AND not_before < $3`

// PurgeThrottle deletes the tenant's throttle rows that are past ThrottleWindow plus ThrottlePurgeMargin
// and no longer delayed, in the caller's tenant transaction, and returns how many it deleted. Rows of any
// other tenant are out of reach: the statement names t and row-level security binds the transaction.
func (l *LocalCredentials) PurgeThrottle(ctx context.Context, tx store.Tx, t tenant.ID) (int, error) {
	if t.IsZero() {
		return 0, ErrInvalid
	}
	now := l.now()
	tag, err := tx.Exec(ctx, sqlPurgeThrottle, t.String(), now.Add(-ThrottleWindow-ThrottlePurgeMargin), now)
	if err != nil {
		return 0, fmt.Errorf("authn: purge throttle rows: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
