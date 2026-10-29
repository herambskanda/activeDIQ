//go:build !windows

package agent

import (
	"context"

	"github.com/skenzeriq/activediq/internal/agenthost/api"
)

type unsupportedSource struct{}

// NewEventSource returns the platform event source. Off Windows there is none: the module reports the
// channel as failed rather than pretending to collect.
func NewEventSource() api.EventSource { return unsupportedSource{} }

func (unsupportedSource) Subscribe(context.Context, api.Channel, uint64, []uint16, func([]byte)) error {
	return api.ErrUnsupported
}

func (unsupportedSource) OldestRecord(api.Channel) (uint64, error) { return 0, api.ErrUnsupported }
