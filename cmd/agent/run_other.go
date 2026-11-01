//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/skenzeriq/activediq/internal/compose/agent"
	"github.com/skenzeriq/activediq/internal/compose/config"
)

// run is the foreground mode used in development and on the Linux CI lab; the product agent is a
// Windows service.
func run(cfg config.Config) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := agent.RunWith(ctx, cfg, agent.Hooks{Version: version}); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		return 1
	}
	return 0
}
