package inventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/store"
)

// ErrNotReconfirmable: the correlation is not waiting for a tenant-owner's re-confirmation. Only a
// candidate whose stored reason is reconfirm_required (DM-20.I4(g), threat model §6.8 rule 4 (g)) can
// be re-confirmed; any other candidate fails a different check that re-confirmation must not override.
var ErrNotReconfirmable = errors.New("inventory: the correlation is not waiting for a re-confirmation")

// PendingReconfirm is a correlation held by rule 4 (g), as the re-confirming Operation shows it.
type PendingReconfirm struct {
	ID               string
	AD, Entra        Ref
	EligibilityClass string
}

// PendingReconfirmation reads the correlation id and returns it if it is a candidate held for
// re-confirmation. It is ErrNotFound for an unknown or removed correlation and ErrNotReconfirmable for
// any other state. Names no secret and no directory value beyond the two GUIDs.
func (Writer) PendingReconfirmation(ctx context.Context, tx store.Tx, id string) (PendingReconfirm, error) {
	if _, ok := canon(id); !ok {
		return PendingReconfirm{}, ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return PendingReconfirm{}, err
	}
	var p PendingReconfirm
	var state, reason string
	err := tx.QueryRow(ctx, `SELECT id::text, ad_connection_id::text, ad_object_guid::text, entra_connection_id::text, entra_object_guid::text,
			eligibility_class, state, candidate_reason
		FROM public.correlations
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1::uuid AND state <> 'removed'`, id).
		Scan(&p.ID, &p.AD.Connection, &p.AD.Object, &p.Entra.Connection, &p.Entra.Object, &p.EligibilityClass, &state, &reason)
	if store.IsNoRows(err) {
		return PendingReconfirm{}, ErrNotFound
	}
	if err != nil {
		return PendingReconfirm{}, fmt.Errorf("inventory: read correlation: %w", err)
	}
	if state != string(StateCandidate) || reason != string(ReasonReconfirmRequired) {
		return PendingReconfirm{}, ErrNotReconfirmable
	}
	return p, nil
}

// Reconfirm records a tenant-owner's re-confirmation of correlation id and makes it matched. It only
// acts on a candidate held for reconfirm_required, which the gate has already found to pass (a)–(f),
// so the next Form keeps it matched while those checks hold and puts it back to candidate when a later
// cloud observation is newer than this confirmation (I4(g)). It decides nothing about who may call
// it: the owner check, the step-up and the audit event belong to the Operation. by is the human
// account's ID.
func (Writer) Reconfirm(ctx context.Context, tx store.Tx, id, by string) error {
	if _, ok := canon(id); !ok {
		return ErrInvalid
	}
	if _, ok := canon(by); !ok {
		return ErrInvalid
	}
	if err := requireTenant(ctx, tx); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE public.correlations SET state = 'matched', candidate_reason = '',
			reconfirmed_by = $2::uuid, reconfirmed_at = now(), updated_at = now()
		WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid AND id = $1::uuid
		AND state = 'candidate' AND candidate_reason = 'reconfirm_required'`, id, by)
	if err != nil {
		return writeErr("reconfirm correlation", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotReconfirmable
	}
	return nil
}
