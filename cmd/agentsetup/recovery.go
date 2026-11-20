package main

import "time"

// Service recovery and event-source registration (T-0724). They are done here, by two fixed verbs, because
// the MSI cannot carry them without something fitness-built-msi refuses: WiX 5.0.2's core
// ServiceConfigFailureActions writes action names ("restart") where Windows Installer wants integers
// (the install fails with error 1939, lab), util:ServiceConfig adds a DLL custom action and a Binary row, and
// util:EventSource writes HKLM\SYSTEM registry rows.
const (
	// recoveryDelay is the wait before the service control manager restarts the service.
	recoveryDelay = 30 * time.Second
	// recoveryResetSeconds forgets earlier failures after a day without one.
	recoveryResetSeconds = 24 * 60 * 60
	// recoveryRestarts is how many failures in a row are answered with a restart. Later failures repeat the
	// last action (SERVICE_FAILURE_ACTIONS). Never reboot the host, never run a command.
	recoveryRestarts = 3
)
