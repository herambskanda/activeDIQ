// Package logon is the never-block rule. The provider's SSPR tile is additive: whatever
// happens to the SSPR call, the system password/smart-card providers stay available and
// the UI thread never waits on the network.
package logon

import (
	"context"
	"errors"
	"time"

	"credprovspike/pin"
)

// Outcome is all the UI layer may see. There is no value that means "block logon".
type Outcome int

const (
	Ready         Outcome = iota // server verified; tile may offer reset
	Offline                      // unreachable/timeout: tile shows "reset unavailable offline"
	ServerRefused                // pin mismatch: tile disabled, event logged, nothing sent
	Disabled                     // no pins configured: provider inert
)

// Deadline bounds every probe; the caller runs Probe off the UI thread.
const Deadline = 3 * time.Second

// Dialer abstracts the TLS dial so tests (and the native DLL's WinHTTP/Schannel layer)
// can be exercised without a socket.
type Dialer func(ctx context.Context) error

func Probe(parent context.Context, dial Dialer, pins []pin.Hash) Outcome {
	if len(pins) == 0 {
		return Disabled
	}
	ctx, cancel := context.WithTimeout(parent, Deadline)
	defer cancel()
	err := dial(ctx)
	switch {
	case err == nil:
		return Ready
	case errors.Is(err, pin.ErrUnpinned):
		return ServerRefused
	default:
		return Offline // DNS, refused, timeout, TLS alert, panic-wrapped errors: never a block
	}
}
