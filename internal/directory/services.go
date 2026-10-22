package directory

import "github.com/skenzeriq/activediq/internal/directory/connection"

// Services is the set of directory services handed to every server module: the inventory's read
// API, the connector client, and the connection registry with its credential port (ADR-0003
// rule 4).
//
// It grows one field per directory service, never per
// module: a field's type must be declared in a directory package listed in the blueprint
// catalogue (§5.2). Because this package is a directory service for the import matrix, agent
// modules and the connector can never import it.
type Services struct {
	// Connection is the connection registry (DM-10), the only writer of connections.
	Connection *connection.Registry
}
