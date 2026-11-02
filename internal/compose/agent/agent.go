// Package agent is the composition-root role package of cmd/agent (blueprint §1, §2 rule 7). It wires
// this role's adapters and imports only what that binary may link: the kernel host, the agent module
// named in modules.gen.go, the tunnel dial-out and the local configuration.
package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/skenzeriq/activediq/internal/compose/config"
	kernel "github.com/skenzeriq/activediq/internal/platform/agent"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
)

// ConfigEnv names the environment variable that holds the path of the local configuration file. The
// variable is honoured off Windows only; on Windows the file is agent.json beside the executable.
const ConfigEnv = "ACTIVEDIQ_AGENT_CONFIG"

// Errors the caller can tell apart: a missing enrolment is an operator action, not a crash loop.
var (
	ErrNoConfig    = errors.New("agent: " + ConfigEnv + " is not set")
	ErrNotEnrolled = errors.New("agent: not enrolled; run `agent enroll`")
	ErrPrivileges  = kernel.ErrPrivileges
	// ErrStateUnusable: enrolment state exists but cannot be used (unsafe owner or DACL, corrupt,
	// expired). It is NOT "not enrolled": an operator has to act, and the service says so (T-1249).
	ErrStateUnusable = errors.New("agent: enrolment state exists but cannot be used")
)

// StateClass names why enrolment state cannot be used. The values are the words in the event text
// and the runbook; they carry no path, SID or content.
type StateClass string

const (
	StateUnsafe  StateClass = "unsafe-permissions" // owner/DACL/file type refused (also: written for another identity)
	StateExpired StateClass = "expired"            // the component certificate is outside its validity
	StateCorrupt StateClass = "corrupt"            // incomplete or does not verify
)

// StateError is returned by RunWith for state that exists and cannot be used. Detail names the file
// and the rule that failed, never content.
type StateError struct {
	Class  StateClass
	Detail string
}

func (e *StateError) Error() string {
	return "agent: enrolment state cannot be used (" + string(e.Class) + "): " + e.Detail
}

// Is makes errors.Is(err, ErrStateUnusable) true for every StateError.
func (e *StateError) Is(target error) bool { return target == ErrStateUnusable }

// classify turns a dial.Load failure into ErrNotEnrolled (only when the files are absent) or a
// StateError. Anything else is never treated as "not enrolled".
func classify(err error) error {
	switch {
	case errors.Is(err, dial.ErrAbsent):
		return ErrNotEnrolled
	case errors.Is(err, dial.ErrUnsafe):
		return &StateError{Class: StateUnsafe, Detail: err.Error()}
	case errors.Is(err, dial.ErrExpired):
		return &StateError{Class: StateExpired, Detail: err.Error()}
	default:
		return &StateError{Class: StateCorrupt, Detail: err.Error()}
	}
}

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
	// NotEnrolledCheck, if set, is called after every RunServing attempt that found the agent not yet
	// enrolled (tests use it to observe re-checks without sleeping).
	NotEnrolledCheck func()
	// StateUnusable, if set, is called by RunServing when enrolment state exists but cannot be used.
	// RunServing calls it once per distinct class and again if the class changes, not every interval.
	StateUnusable func(*StateError)
	// StateUnusableCheck is NotEnrolledCheck's counterpart for unusable state (tests).
	StateUnusableCheck func()
}

// Run runs the agent role until ctx is done.
func Run(ctx context.Context, cfg config.Config) error { return RunWith(ctx, cfg, Hooks{}) }

// RunWith is Run with the platform hooks. Order matters: the privilege check comes first and refuses
// to run before any subscription or network use (ADR-0006 decision 3).
func RunWith(ctx context.Context, cfg config.Config, hk Hooks) error {
	path, err := configPath()
	if err != nil {
		return err
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
		return classify(err)
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

// WaitInterval is how often a service that is installed but not yet enrolled re-checks for the
// enrolment material.
const WaitInterval = 15 * time.Second

// RunServing is RunWith for the Windows service: an agent that is installed but not yet enrolled is
// an expected state (the MSI starts the service before the operator runs `agent enroll`), not a
// failure. It calls waiting once, then re-checks every interval until enrolment appears or ctx is
// done, so the SCM never sees an exit and the recovery action never loops.
//
// State that exists but cannot be used is a different thing and is never reported as "waiting": the
// service refuses it (fail closed, it does not dial), reports it through hk.StateUnusable (a distinct
// event naming the class) once per class, and keeps re-checking, so an operator who fixes the state
// does not have to restart the service. Every other error (privileges, bad config) is returned
// unchanged and still stops the service.
func RunServing(ctx context.Context, cfg config.Config, hk Hooks, interval time.Duration, waiting func()) error {
	announced := false
	var reported StateClass
	for {
		err := RunWith(ctx, cfg, hk)
		var se *StateError
		switch {
		case errors.Is(err, ErrNotEnrolled):
			reported = ""
			if hk.NotEnrolledCheck != nil {
				hk.NotEnrolledCheck()
			}
			if !announced {
				announced = true
				if waiting != nil {
					waiting()
				}
			}
		case errors.As(err, &se):
			if hk.StateUnusableCheck != nil {
				hk.StateUnusableCheck()
			}
			if se.Class != reported {
				reported = se.Class
				if hk.StateUnusable != nil {
					hk.StateUnusable(se)
				}
			}
		default:
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}
