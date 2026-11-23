package write

import (
	"github.com/skenzeriq/activediq/internal/connector/provider"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// fromWire and toWire are the GUID wire conversions of the provider package (the one place the
// mixed-endian layout is handled).
func fromWire(g *connectorv1.Guid) (guid.GUID, error) { return provider.GUIDFromWire(g) }

func toWire(g guid.GUID) *connectorv1.Guid { return provider.GUIDToWire(g) }
