// Package agent is the composition-root role package of cmd/agent (blueprint §1, §2 rule 7). It wires
// this role's adapters and imports only what that binary may link: the kernel host, the agent module
// named in modules.gen.go, the tunnel dial-out and the local configuration.
package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/skenzeriq/activediq/internal/compose/config"
	kernel "github.com/skenzeriq/activediq/internal/platform/agent"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
)

// ConfigEnv names the environment variable that holds the path of the local configuration file. The
// MSI sets it on the service; it points into the install directory.
const ConfigEnv = "ACTIVEDIQ_AGENT_CONFIG"

// Errors the caller can tell apart: a missing enrolment is an operator action, not a crash loop.
var (
	ErrNoConfig    = errors.New("agent: " + ConfigEnv + " is not set")
	ErrNotEnrolled = errors.New("agent: not enrolled; run `agent enroll`")
	ErrPrivileges  = kernel.ErrPrivileges
)

// Hooks are the platform seams the Windows service wrapper fills in; tests use none.
type Hooks struct {
	// HeldPrivileges returns the privilege names in this process's token. nil means "not checked" and
	// is allowed only off Windows.
	HeldPrivileges func() ([]string, error)
	// Applied receives the local trace of an applied policy or keyset (Windows Application log).
	Applied func(what string, seq uint64)
	// Confine puts the process in its job-object limits; nil off Windows.
	Confine func() error
	Version string
}

func endpointAddr(e dial.Endpoint) string { return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))) }

// Run runs the agent role until ctx is done.
func Run(ctx context.Context, cfg config.Config) error { return RunWith(ctx, cfg, Hooks{}) }

// RunWith is Run with the platform hooks. Order matters: the privilege check comes first and refuses
// to run before any subscription or network use (ADR-0006 decision 3).
func RunWith(ctx context.Context, cfg config.Config, hk Hooks) error {
	path := os.Getenv(ConfigEnv)
	if path == "" {
		return ErrNoConfig
	}
	loc, err := LoadLocal(path)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	checked := false
	if hk.HeldPrivileges != nil {
		held, err := hk.HeldPrivileges()
		if err != nil {
			return err
		}
		if err := kernel.CheckPrivileges(held); err != nil {
			return err
		}
		checked = true
	}
	if hk.Confine != nil {
		if err := hk.Confine(); err != nil {
			return err
		}
	}
	st, err := dial.Load(loc.EnrollmentDir)
	if err != nil {
		return ErrNotEnrolled
	}
	leaf, err := leafOf(st)
	if err != nil {
		return err
	}
	id, err := fleet.IdentityOf(leaf)
	if err != nil {
		return err
	}
	mod, ok := buildModule(id.Kind, loc.ReportedDCGUID)
	if !ok {
		return errors.New("agent: no module for this component kind")
	}
	contract, err := addcContract()
	if err != nil {
		return err
	}
	h, err := kernel.Open(kernel.Config{Identity: id, DataDir: loc.DataDir, Version: hk.Version, Module: mod,
		Ceilings: loc.ceilings(), Logger: log, TokenCheckPassed: checked,
		Applied: func(a agentpolicy.Applied) {
			if hk.Applied != nil {
				hk.Applied(a.What, a.Seq)
			}
		}})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go tunnelLoop(ctx, st, h, id, contract, log)
	return h.Run(ctx)
}

func leafOf(st *dial.State) (*x509.Certificate, error) {
	if len(st.Leaf.Certificate) == 0 {
		return nil, ErrNotEnrolled
	}
	return x509.ParseCertificate(st.Leaf.Certificate[0])
}
