package harnessdocker

import (
	"os/exec"
	"strings"
	"testing"
)

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %v: %s", args, out)
	}
	return strings.TrimSpace(string(out))
}

// VolumesOf lists the volume names mounted into a container.
func volumesOf(t *testing.T, id string) []string {
	return strings.Fields(docker(t, "inspect", "-f", "{{range .Mounts}}{{.Name}} {{end}}", id))
}

func volumeExists(t *testing.T, name string) bool {
	return exec.Command("docker", "volume", "inspect", name).Run() == nil
}

// TestRemoveAndReapLeaveNoContainerOrVolume proves the acceptance criteria: a labelled container
// with an anonymous volume is gone, with its volume, after Remove; and a leftover owned by a dead pid
// is reaped while one owned by this live process is not.
func TestRemoveAndReapLeaveNoContainerOrVolume(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil || exec.Command("docker", "info").Run() != nil {
		t.Skip("docker unavailable")
	}
	const img = "postgres:16-alpine" // declares an anonymous data volume, like the harness image
	run := func(extra ...string) string {
		a := append([]string{"run", "-d", "-e", "POSTGRES_PASSWORD=x"}, extra...)
		return docker(t, append(a, img)...)
	}
	// Owned by a pid that cannot exist: a killed test run's leftover.
	dead := run("--label", Label+"=1", "--label", OwnerLabel+"=2147483646")
	// Owned by this live process: a sibling package's container must survive Reap.
	live := run(RunArgs()...)
	t.Cleanup(func() { Remove(dead); Remove(live) })
	deadVols, liveVols := volumesOf(t, dead), volumesOf(t, live)
	if len(deadVols) == 0 || len(liveVols) == 0 {
		t.Fatal("test image has no anonymous volume; the proof would be vacuous")
	}

	Reap()
	if got := docker(t, "ps", "-aq", "--filter", "id="+dead); got != "" {
		t.Fatalf("leftover container of a dead owner survived Reap: %s", got)
	}
	if got := docker(t, "ps", "-aq", "--filter", "id="+live); got == "" {
		t.Fatal("Reap removed a container owned by a live process")
	}
	Remove(live)
	if got := docker(t, "ps", "-aq", "--filter", "id="+live); got != "" {
		t.Fatalf("harness container still present: %s", got)
	}
	for _, v := range append(deadVols, liveVols...) {
		if volumeExists(t, v) {
			t.Fatalf("anonymous volume %s leaked", v)
		}
	}
}
