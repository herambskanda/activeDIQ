// Command labserver is the server with the lab bootstrap attached (T-0684, T-0550): lab builds are a
// separate binary under tools/ (tier L), never a build tag in the shipped server package (ADR-0001 F2).
// Environment and behaviour: tools/labserver/labboot.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/server"
	"github.com/skenzeriq/activediq/internal/platform/prochardening"
	"github.com/skenzeriq/activediq/tools/labserver/labboot"
)

func main() {
	if err := prochardening.Apply(os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "labserver:", err)
		os.Exit(2)
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labserver:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.Run(ctx, cfg, os.Getenv, server.WithLabBootstrap(labboot.Bootstrap)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
