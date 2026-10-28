package audit

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/audit/chain"
	"github.com/skenzeriq/activediq/internal/platform/personal"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// RenderedChange is one change with its values resolved from the personal side store.
type RenderedChange struct {
	Attribute string
	Secret    bool
	Before    []string
	After     []string
}

// RenderedSnapshot is one display snapshot, resolved.
type RenderedSnapshot struct {
	Field string
	Value string
}

// Rendered is a chained event's personal content for display. A value whose subject has been erased
// reads personal.Redacted.
type Rendered struct {
	Changes   []RenderedChange
	Snapshots []RenderedSnapshot
}

// Render resolves the personal references of env inside tx, a transaction of tid. The caller authorises
// the reader first: Render does not decide who may see personal values. A value that no longer exists
// (erased) is shown as personal.Redacted; a value that does not match its commitment fails with
// personal.ErrTampered.
func Render(ctx context.Context, tx store.Tx, tid tenant.ID, env chain.Envelope) (Rendered, error) {
	ps := personal.New()
	resolve := func(r chain.Ref) (string, error) {
		v, _, err := ps.Resolve(ctx, tx, tid, personal.Ref{Subject: r.Subject, ValueID: r.ValueID, Field: r.Field, Commitment: r.Commitment})
		return v, err
	}
	var out Rendered
	for _, c := range env.Changes {
		rc := RenderedChange{Attribute: c.Attribute, Secret: c.Secret}
		for _, r := range c.Before {
			v, err := resolve(r)
			if err != nil {
				return Rendered{}, err
			}
			rc.Before = append(rc.Before, v)
		}
		for _, r := range c.After {
			v, err := resolve(r)
			if err != nil {
				return Rendered{}, err
			}
			rc.After = append(rc.After, v)
		}
		out.Changes = append(out.Changes, rc)
	}
	for _, r := range env.Snapshots {
		v, err := resolve(r)
		if err != nil {
			return Rendered{}, err
		}
		out.Snapshots = append(out.Snapshots, RenderedSnapshot{Field: r.Field, Value: v})
	}
	return out, nil
}
