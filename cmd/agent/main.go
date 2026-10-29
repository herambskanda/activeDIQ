// Command agent is the activeDIQ agent. It runs as a Windows service under NT SERVICE\activeDIQAgent
// (main_windows.go) or in the foreground for development, and has one administrative subcommand:
//
//	agent enroll <server-host:port> <sha256:pin>   reads the single-use token from stdin
//
// The token never appears in argv, an environment variable or a log.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/skenzeriq/activediq/internal/compose/agent"
	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	"github.com/skenzeriq/activediq/internal/platform/prochardening"
)

// version is set by the release pipeline (-ldflags -X main.version=...).
var version = "dev"

func main() {
	if err := prochardening.Apply(os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(2)
	}
	if len(os.Args) > 1 && os.Args[1] == "enroll" {
		os.Exit(enroll(os.Args[2:], os.Stdin, os.Stderr))
	}
	if len(os.Args) > 1 {
		fmt.Fprintln(os.Stderr, "agent: unknown command; the only command is `enroll`")
		os.Exit(2)
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(2)
	}
	os.Exit(run(cfg))
}

func enroll(args []string, in io.Reader, errw io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(errw, "usage: agent enroll <server-host:port> <sha256:pin>   (token on stdin)")
		return 2
	}
	tok, err := bufio.NewReader(io.LimitReader(in, 4096)).ReadString('\n')
	tok = strings.TrimSpace(tok)
	if tok == "" || (err != nil && err != io.EOF) {
		fmt.Fprintln(errw, "agent: no enrolment token on stdin")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := agent.Enroll(ctx, dial.Material{Address: args[0], Token: tok, Pin: args[1]}); err != nil {
		fmt.Fprintln(errw, "agent: enrolment failed:", err)
		return 1
	}
	fmt.Fprintln(errw, "agent: enrolled")
	return 0
}
