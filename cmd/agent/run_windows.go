//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/sys/windows/svc"

	"github.com/skenzeriq/activediq/internal/compose/agent"
	"github.com/skenzeriq/activediq/internal/compose/config"
	kernel "github.com/skenzeriq/activediq/internal/platform/agent"
)

const serviceName = "activeDIQAgent"

func hooks(log *kernel.EventLog) agent.Hooks {
	return agent.Hooks{
		Version:        version,
		HeldPrivileges: kernel.HeldPrivileges,
		Confine:        kernel.Confine,
		Burst:          kernel.Burst,
		StateUnusable: func(e *agent.StateError) {
			if log != nil {
				log.StateUnusable(string(e.Class), e.Detail)
			}
		},
		Applied: func(what string, seq uint64) {
			if log != nil {
				log.Applied(what, seq)
			}
		},
	}
}

func run(cfg config.Config) int {
	log, _ := kernel.OpenEventLog("activeDIQ Agent") // best effort: a missing source must not stop the agent
	if log != nil {
		defer log.Close()
	}
	isSvc, err := svc.IsWindowsService()
	if err == nil && isSvc {
		if err := svc.Run(serviceName, &handler{cfg: cfg, log: log}); err != nil {
			return 1
		}
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := agent.RunWith(ctx, cfg, hooks(log)); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		return 1
	}
	return 0
}

type handler struct {
	cfg config.Config
	log *kernel.EventLog
}

// Execute implements svc.Handler. A refusal to run (extra privilege, bad config) ends the service
// with a non-zero service-specific exit code so the SCM recovery action does not mask it as healthy.
func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- agent.RunServing(ctx, h.cfg, hooks(h.log), agent.WaitInterval, func() {
			if h.log != nil {
				h.log.NotEnrolled()
			}
		})
	}()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				if h.log != nil {
					h.log.Failed(err)
				}
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}
