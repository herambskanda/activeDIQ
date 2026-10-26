// Package harnessdocker is the single place test Postgres containers are labelled, removed and reaped
// (T-0377). The postgres image declares an anonymous data volume, so a container removed without -v
// leaks ~74 MB each; a test process killed before cleanup leaks the container itself.
package harnessdocker

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	// Label marks every container a test harness starts.
	Label = "activediq.harness"
	// OwnerLabel records the pid of the test process that owns the container.
	OwnerLabel = "activediq.harness.pid"
)

// RunArgs returns the label arguments to insert into `docker run` for the current process.
func RunArgs() []string { return runArgs(Label, OwnerLabel) }

func runArgs(label, owner string) []string {
	return []string{"--label", label + "=1", "--label", owner + "=" + strconv.Itoa(os.Getpid())}
}

// Remove force-removes a container together with its anonymous volumes.
func Remove(id string) {
	if id != "" {
		_ = exec.Command("docker", "rm", "-f", "-v", id).Run()
	}
}

// Reap removes harness containers (and volumes) whose owning process is gone, i.e. leftovers of a
// killed test run. Containers of live sibling processes (parallel packages) are left alone.
// Liveness is a pid check, so it assumes all test processes share one pid namespace.
func Reap() { reap(Label, OwnerLabel) }

// reap is parameterised so this package's own test can use a private label that the production
// reaper (run by every other test package in parallel) can never see.
func reap(label, owner string) {
	out, err := exec.Command("docker", "ps", "-a", "--filter", "label="+label+"=1",
		"--format", `{{.ID}} {{.Label "`+owner+`"}}`).Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		id, pid, _ := strings.Cut(strings.TrimSpace(line), " ")
		if id == "" || ownerAlive(pid) {
			continue
		}
		Remove(id)
	}
}
