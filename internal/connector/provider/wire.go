package provider

import (
	"encoding/hex"
	"errors"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// ErrBadGUID is returned for a wire GUID that is not 16 bytes or is nil.
var ErrBadGUID = errors.New("provider: not a 16-byte non-nil GUID")

// GUIDFromWire converts a v1.Guid (RFC 4122 network order, the order of the canonical text) to the
// attr/guid type through its canonical text, so the mixed-endian layout stays inside attr/guid.
func GUIDFromWire(g *connectorv1.Guid) (guid.GUID, error) {
	b := g.GetValue()
	if len(b) != guid.Size {
		return guid.GUID{}, ErrBadGUID
	}
	h := hex.EncodeToString(b)
	out, err := guid.Parse(h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:])
	if err != nil {
		return guid.GUID{}, ErrBadGUID
	}
	return out, nil
}

// GUIDToWire is the inverse of GUIDFromWire.
func GUIDToWire(g guid.GUID) *connectorv1.Guid {
	s := g.String()
	b, err := hex.DecodeString(s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:])
	if err != nil { // String is canonical by construction
		return &connectorv1.Guid{}
	}
	return &connectorv1.Guid{Value: b}
}
