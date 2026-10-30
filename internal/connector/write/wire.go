package write

import (
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// GUIDFromWire converts a v1.Guid to the attr/guid type (see fromWire).
func GUIDFromWire(g *connectorv1.Guid) (guid.GUID, error) { return fromWire(g) }

// GUIDToWire converts an attr/guid value to a v1.Guid (see toWire).
func GUIDToWire(g guid.GUID) *connectorv1.Guid { return toWire(g) }
