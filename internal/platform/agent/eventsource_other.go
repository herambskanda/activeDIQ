//go:build !windows

package agent

import (
	"context"

	"github.com/skenzeriq/activediq/internal/agenthost/hostapi"
)

type unsupportedSource struct{}

// NewEventSource returns the platform event source. Off Windows there is none: the module reports the
// channel as failed rather than pretending to collect.
func NewEventSource() hostapi.EventSource { return unsupportedSource{} }

func (unsupportedSource) Subscribe(context.Context, hostapi.Channel, uint64, []uint16, func([]byte)) error {
	return hostapi.ErrUnsupported
}

func (unsupportedSource) OldestRecord(hostapi.Channel) (uint64, error) {
	return 0, hostapi.ErrUnsupported
}
