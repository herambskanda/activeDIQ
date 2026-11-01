//go:build windows

// Command svcstub is a LAB-ONLY stand-in service (T-0613). No agent MSI or Windows service host exists yet
// (cmd/agent is not an SCM service), so this stub lets Install-AgentLabHarness.ps1 create
// NT SERVICE\activeDIQAgent with the ADR-0006 token and capture what that token really contains.
// It does nothing else: at start it records `whoami` output (inherits the service token) into the data dir
// and then idles until stopped. It is never shipped and holds no secrets.
package main

import (
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows/svc"
)

type stub struct{ dir string }

func (s stub) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	s.capture()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			st <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
	return false, 0
}

// capture runs fixed argv (no shell, no interpolation); output files land in the service's data directory.
func (s stub) capture() {
	for name, args := range map[string][]string{
		"whoami-priv.txt":   {"/priv"},
		"whoami-user.txt":   {"/user"},
		"whoami-groups.txt": {"/groups"},
	} {
		out, err := exec.Command(`C:\Windows\System32\whoami.exe`, args...).CombinedOutput()
		if err != nil {
			out = append(out, []byte("\nerror: "+err.Error()+"\n")...)
		}
		_ = os.WriteFile(filepath.Join(s.dir, name), out, 0o600)
	}
	_ = os.WriteFile(filepath.Join(s.dir, "done"), []byte("ok\n"), 0o600)
}

func main() {
	dir := os.Getenv("ADIQ_LAB_DATA_DIR")
	if dir == "" {
		dir = `C:\ProgramData\skenzeriq\agent`
	}
	if err := svc.Run("activeDIQAgent", stub{dir: dir}); err != nil {
		os.Exit(1)
	}
}
