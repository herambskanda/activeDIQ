package authn

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// The account events of DM-31.I2 and threat model §7.3. Each ends every active session of the account
// inside tx, the transaction that makes the change, so the change and the revocation commit together:
// a commit that disables an account can never leave a live session behind, and a rollback leaves the
// sessions alone. by is the real human (or automation) behind the change. They return how many sessions
// ended. Anything that disables an account, changes its role assignments, or resets its password or MFA
// must call the matching method in its own transaction.

// OnAccountDisabled revokes the account's sessions with reason account_disabled.
func (s *Store) OnAccountDisabled(ctx context.Context, tx store.Tx, t tenant.ID, account string, by authority.Chain) (int, error) {
	return s.RevokeAccountTx(ctx, tx, t, account, ReasonAccountDisabled, by)
}

// OnRoleChanged revokes the account's sessions with reason role_changed.
func (s *Store) OnRoleChanged(ctx context.Context, tx store.Tx, t tenant.ID, account string, by authority.Chain) (int, error) {
	return s.RevokeAccountTx(ctx, tx, t, account, ReasonRoleChanged, by)
}

// OnPasswordReset revokes the account's sessions with reason password_reset.
func (s *Store) OnPasswordReset(ctx context.Context, tx store.Tx, t tenant.ID, account string, by authority.Chain) (int, error) {
	return s.RevokeAccountTx(ctx, tx, t, account, ReasonPasswordReset, by)
}

// OnMFAReset revokes the account's sessions with reason mfa_reset.
func (s *Store) OnMFAReset(ctx context.Context, tx store.Tx, t tenant.ID, account string, by authority.Chain) (int, error) {
	return s.RevokeAccountTx(ctx, tx, t, account, ReasonMFAReset, by)
}
