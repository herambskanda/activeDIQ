// Command connector is the connector process. It loads configuration and runs its own role package.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/connector"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connector:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := connector.Run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "connector:", err)
		os.Exit(1)
	}
}
