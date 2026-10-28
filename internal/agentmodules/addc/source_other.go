//go:build !windows

package addc

import (
	"context"

	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
)

type unsupported struct{}

// NewSource returns the platform event source. Off Windows there is none: the module reports the
// channel as failed rather than pretending to collect.
func NewSource() Source { return unsupported{} }

func (unsupported) Subscribe(context.Context, agentpolicy.Channel, uint64, []uint32, func(RawEvent)) error {
	return ErrUnsupported
}
