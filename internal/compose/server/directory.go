package server

import (
	"fmt"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// buildDirectory wires the directory.users.search routes: the registry (active connection and the
// service-account gate) and the user search over the connector source. A missing source fails startup.
//
// scopes produces the caller's directory.read ReadScope (rbac.ReadScopes behind a transaction, T-0916).
// Search is trimmed to it; while it is nil every search is refused (fail closed), never unscoped.
func buildDirectory(db *store.DB, conns *connection.Registry, src client.ConnectorSource, reads client.Reads, scopes directory.ReadScopes) (apihost.TagHandlers, error) {
	us, err := client.NewUserSearch(conns, src, reads)
	if err != nil {
		return apihost.TagHandlers{}, fmt.Errorf("server: directory search: %w", err)
	}
	// The TM-D17 classification of each hybrid-synced user: the stored correlation (DM-20) and the
	// Entra connection's takeover protection (DM-10.I7), read live per request.
	hy := directory.Classifier{Corr: inventory.NewReader(db, nil), Takeovers: conns}
	return directory.Handlers{Connections: conns, Search: us, Scopes: scopes, Hybrid: hy}.Bind(), nil
}
