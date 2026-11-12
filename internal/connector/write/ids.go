package write

import (
	"encoding/hex"
	"errors"
	"github.com/skenzeriq/activediq/internal/connector/wirevalue"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

var errBadGUID = errors.New("write: not a 16-byte non-nil GUID")

// fromWire converts a v1.Guid (RFC 4122 network order, the order of the canonical text) to the
// attr/guid type through its canonical text, so the mixed-endian layout stays inside attr/guid.
func fromWire(g *connectorv1.Guid) (guid.GUID, error) {
	b := g.GetValue()
	if len(b) != guid.Size {
		return guid.GUID{}, errBadGUID
	}
	h := hex.EncodeToString(b)
	out, err := guid.Parse(h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:])
	if err != nil {
		return guid.GUID{}, errBadGUID
	}
	return out, nil
}

// toWire is the inverse of fromWire.
func toWire(g guid.GUID) *connectorv1.Guid { return wirevalue.GUIDToWire(g) }
