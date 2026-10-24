package operation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Transient secrets (ADR-0005 rule 9). A secret input is stored only here, sealed with the TM-D7 seal
// primitive under the tenant data key, with associated data (tenant, table, row, column, key version)
// where the row names the step key. Its TTL is the request's, capped at 72 hours, and independent of
// plan_valid_until. It is deleted in the step's recording transaction, on every terminal operation
// state, and by the sweeper.

// DEKSource returns the tenant data key. version 0 asks for the current one. audit's checkpointer uses
// the same shape.
type DEKSource interface {
	DEK(ctx context.Context, tx store.Tx, id tenant.ID, version uint32) (keys.DEK, error)
}

// Secret TTL bounds (rule 9).
const (
	DefaultSecretTTL = 24 * time.Hour
	MaxSecretTTL     = 72 * time.Hour
)

// ErrSecretExpired is the reason a step fails closed when its secret is gone or past its TTL. A secret
// is never regenerated: a new secret means a new operation.
var ErrSecretExpired = errors.New("operation: transient secret expired")

const secretTable = "public.operation_secrets"

func secretRow(k step.Key) string { return fmt.Sprintf("%s/%d/%d", k.Operation, k.Item, k.Step) }

// putSecret seals and stores the secret of one step. There is no update path: the runtime role holds
// no UPDATE on the table.
func (r *Runner) putSecret(ctx context.Context, tx store.Tx, t tenant.ID, k step.Key, s secret.Secret, ttl time.Duration) error {
	if r.cfg.Keys == nil {
		return fmt.Errorf("%w: no key source wired for transient secrets", ErrInvalid)
	}
	if ttl <= 0 {
		ttl = DefaultSecretTTL
	}
	if ttl > MaxSecretTTL {
		ttl = MaxSecretTTL
	}
	dek, err := r.cfg.Keys.DEK(ctx, tx, t, 0)
	if err != nil {
		return fmt.Errorf("operation: tenant data key: %w", err)
	}
	defer dek.Destroy()
	var blob []byte
	var sealErr error
	s.Expose(func(b []byte) {
		blob, sealErr = keys.Seal(dek, keys.Context{Tenant: t, Table: secretTable, Row: secretRow(k), Column: "sealed_secret", Version: dek.Version}, b)
	})
	if sealErr != nil {
		return fmt.Errorf("operation: sealing secret: %w", sealErr)
	}
	_, err = tx.Exec(ctx, `INSERT INTO public.operation_secrets (tenant_id, operation_id, item_no, step_no, sealed_secret, key_version, expires_at)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, now() + $7 * interval '1 millisecond')`,
		t.String(), string(k.Operation), k.Item, k.Step, blob, int(dek.Version), ttl.Milliseconds())
	if err != nil {
		return fmt.Errorf("operation: storing secret: %w", err)
	}
	return nil
}

// takeSecret unseals the live secret of a step for one claim. A missing or expired secret is
// ErrSecretExpired; the step then fails closed.
func (r *Runner) takeSecret(ctx context.Context, tx store.Tx, t tenant.ID, k step.Key) (secret.Secret, error) {
	var blob []byte
	var ver int
	err := tx.QueryRow(ctx, `SELECT sealed_secret, key_version FROM public.operation_secrets
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND item_no = $3 AND step_no = $4 AND expires_at > now()`,
		t.String(), string(k.Operation), k.Item, k.Step).Scan(&blob, &ver)
	if err != nil {
		if store.IsNoRows(err) {
			return secret.Secret{}, ErrSecretExpired
		}
		return secret.Secret{}, fmt.Errorf("operation: reading secret: %w", err)
	}
	if r.cfg.Keys == nil {
		return secret.Secret{}, fmt.Errorf("%w: no key source wired for transient secrets", ErrInvalid)
	}
	dek, err := r.cfg.Keys.DEK(ctx, tx, t, uint32(ver))
	if err != nil {
		return secret.Secret{}, fmt.Errorf("operation: tenant data key: %w", err)
	}
	defer dek.Destroy()
	plain, err := keys.Open(dek, keys.Context{Tenant: t, Table: secretTable, Row: secretRow(k), Column: "sealed_secret", Version: uint32(ver)}, blob)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("operation: unsealing secret: %w", err)
	}
	defer clear(plain) // FromBytes copies; do not leave the unsealed plaintext in the heap
	return secret.FromBytes(plain), nil
}

// deleteSecret removes one step's secret (the step's recording transaction).
func deleteSecret(ctx context.Context, tx store.Tx, t tenant.ID, k step.Key) error {
	_, err := tx.Exec(ctx, `DELETE FROM public.operation_secrets
WHERE tenant_id = $1::uuid AND operation_id = $2::uuid AND item_no = $3 AND step_no = $4`,
		t.String(), string(k.Operation), k.Item, k.Step)
	return err
}

// deleteOperationSecrets removes every secret of an operation (every terminal state).
func deleteOperationSecrets(ctx context.Context, tx store.Tx, t tenant.ID, op string) error {
	_, err := tx.Exec(ctx, `DELETE FROM public.operation_secrets WHERE tenant_id = $1::uuid AND operation_id = $2::uuid`, t.String(), op)
	return err
}
