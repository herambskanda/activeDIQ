// Command server is the server process. It loads configuration and runs its own role package.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/server"
)

func main() {
	if err := hardenProcess(os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(2)
	}
	if len(os.Args) > 1 && os.Args[1] == "kek" {
		os.Exit(runKEK(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		os.Exit(runSetup(os.Args[2:]))
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.Run(ctx, cfg, os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// runKEK is `activediq-server kek <command>`. Only init exists; it generates the installation KEK, which the
// server itself never does.
func runKEK(args []string) int {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprintln(os.Stderr, "usage: activediq-server kek init   (see the key-custody settings in the install guide)")
		return 2
	}
	if err := server.KEKInit(args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return 1
	}
	return 0
}

// runSetup is `activediq-server setup <command>`. Only show exists: it prints the one-time first-run setup
// secret to the installing administrator (TM-TB16-T7).
func runSetup(args []string) int {
	if len(args) != 1 || args[0] != "show" {
		fmt.Fprintln(os.Stderr, "usage: activediq-server setup show   (prints the one-time first-run setup secret)")
		return 2
	}
	if err := server.SetupShow(os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return 1
	}
	return 0
}
