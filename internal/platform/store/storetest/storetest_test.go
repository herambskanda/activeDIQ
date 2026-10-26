package storetest

import (
	"os/exec"
	"strings"
	"testing"
)

// TestStopRemovesContainerAndAnonymousVolume proves T-0377: after a harness server stops, neither the
// container nor the image's anonymous data volume remains, and the container carried the harness label.
func TestStopRemovesContainerAndAnonymousVolume(t *testing.T) {
	s := start(t, Versions()[0])
	id := s.id
	out, err := exec.Command("docker", "inspect", "-f",
		`{{index .Config.Labels "activediq.harness"}} {{range .Mounts}}{{.Name}} {{end}}`, id).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect: %s", out)
	}
	f := strings.Fields(string(out))
	if len(f) < 2 || f[0] != "1" {
		t.Fatalf("want harness label and an anonymous volume, got %q", out)
	}
	vols := f[1:]
	s.stop()
	if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "id="+id).Output(); strings.TrimSpace(string(out)) != "" {
		t.Fatalf("container %s still present", id)
	}
	for _, v := range vols {
		if exec.Command("docker", "volume", "inspect", v).Run() == nil {
			t.Fatalf("anonymous volume %s leaked", v)
		}
	}
}
