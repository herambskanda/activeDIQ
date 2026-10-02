package main

import "github.com/skenzeriq/activediq/tools/fitness/pgharness"

// The throw-away PostgreSQL environment is shared with fitness-domain-keys (tools/fitness/pgharness).
type (
	Server   = pgharness.Server
	Database = pgharness.Database
)

var (
	StartServer     = pgharness.StartServer
	dockerAvailable = pgharness.DockerAvailable
)
