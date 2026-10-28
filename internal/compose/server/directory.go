package server

import (
	"fmt"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/modules/directory"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

// buildDirectory wires the directory.users.search routes: the registry (active connection and the
// service-account gate) and the user search over the connector source. A missing source fails startup.
func buildDirectory(conns *connection.Registry, src client.ConnectorSource) (apihost.TagHandlers, error) {
	us, err := client.NewUserSearch(conns, src)
	if err != nil {
		return apihost.TagHandlers{}, fmt.Errorf("server: directory search: %w", err)
	}
	return directory.Handlers{Connections: conns, Search: us}.Bind(), nil
}
