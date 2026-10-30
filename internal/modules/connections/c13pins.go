package connections

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// C13Pins is the durable write.PinStore of one connection (TM-D26 rule 10): the pins live in the
// platform database, not in the connector, so a connector restart or a redeploy cannot drop them.
type C13Pins struct {
	DB         *store.DB
	Tenant     tenant.ID
	Connection connection.ID
}

// PinnedC13 returns every pinned group GUID.
func (p C13Pins) PinnedC13(ctx context.Context) ([]guid.GUID, error) {
	var texts []string
	err := p.DB.WithTenant(ctx, p.Tenant, func(ctx context.Context, tx store.Tx) error {
		var err error
		texts, err = connection.Store{}.PinnedC13(ctx, tx, p.Connection)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]guid.GUID, 0, len(texts))
	for _, t := range texts {
		g, err := guid.Parse(t)
		if err != nil { // a pin we cannot read is one we cannot honour: unknown, not skipped
			return nil, fmt.Errorf("connections: stored C13 pin is not a GUID: %w", err)
		}
		out = append(out, g)
	}
	return out, nil
}

// PinC13 durably adds the GUIDs.
func (p C13Pins) PinC13(ctx context.Context, groups []guid.GUID) error {
	texts := make([]string, len(groups))
	for i, g := range groups {
		texts[i] = g.String()
	}
	return p.DB.WithTenant(ctx, p.Tenant, func(ctx context.Context, tx store.Tx) error {
		return connection.Store{}.PinC13(ctx, tx, p.Connection, texts)
	})
}
