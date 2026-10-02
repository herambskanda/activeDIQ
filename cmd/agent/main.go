// Command agent is the agent process. It loads configuration and runs its own role package.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/skenzeriq/activediq/internal/compose/agent"
	"github.com/skenzeriq/activediq/internal/compose/config"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := agent.Run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}
