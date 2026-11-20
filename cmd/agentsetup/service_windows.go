//go:build windows

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceName is the service this binary configures. Compiled in; never taken from input.
const serviceName = "activeDIQAgent"

// configureService sets the service's recovery actions (restart after every failure; no reboot, no command)
// and registers the Application event source with EventCreate.exe as the message file (the agent's event ids
// are within 1..1000, which that file defines). Idempotent: running it again leaves the same state.
// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w
func configureService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service control manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service %s: %w", serviceName, err)
	}
	defer s.Close()
	actions := make([]mgr.RecoveryAction, recoveryRestarts)
	for i := range actions {
		actions[i] = mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: recoveryDelay}
	}
	if err := s.SetRecoveryActions(actions, recoveryResetSeconds); err != nil {
		return fmt.Errorf("set recovery actions: %w", err)
	}
	// Install refuses an existing key, so a repeat run (repair, upgrade) replaces it.
	const supported = eventlog.Info | eventlog.Warning | eventlog.Error
	if err := eventlog.InstallAsEventCreate(agentEventSource, supported); err != nil {
		if rerr := eventlog.Remove(agentEventSource); rerr != nil {
			return fmt.Errorf("register event source: %w (and could not replace the existing one: %v)", err, rerr)
		}
		if err := eventlog.InstallAsEventCreate(agentEventSource, supported); err != nil {
			return fmt.Errorf("register event source: %w", err)
		}
	}
	return nil
}

// unconfigureService removes the event source. The recovery actions go with the service. A source that is
// already gone is not an error (rollback and uninstall both run this).
func unconfigureService() error {
	err := eventlog.Remove(agentEventSource)
	if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return fmt.Errorf("remove event source: %w", err)
	}
	return nil
}
