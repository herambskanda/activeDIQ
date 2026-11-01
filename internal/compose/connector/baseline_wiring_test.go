package connector

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/tier0"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// T-0242: the gate openBackend builds must report a widened ratchet baseline. A FileBaseline wired
// without a recorder would narrow the file and lose the finding (code review, 2026-10-30).
func TestGateReportsWidenedBaselineThroughRealWiring(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DACL widening through this wiring is exercised by the ownerfile windows tests")
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	path := filepath.Join(t.TempDir(), ratchetFile)
	g, err := newGate(path, log)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 16)
	raw[15] = 1
	const conn = "conn-1"
	g.Complete(conn, write.Run{})
	mark := func(b byte) []write.Mark {
		raw[0] = b
		o, _ := guid.FromBytes(raw)
		return []write.Mark{{Object: o, Basis: tier0.C16, Source: "request"}}
	}
	if err := g.Ratchet(conn, mark(1)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), write.ReasonBaselineACLCorrected) {
		t.Fatalf("fresh baseline reported a correction: %s", buf.String())
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := g.Ratchet(conn, mark(2)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), write.ReasonBaselineACLCorrected) {
		t.Fatalf("widened baseline not recorded through the real wiring: %q", buf.String())
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("baseline not corrected: %v", st.Mode())
	}
}

func TestNewGateRefusesWithoutPath(t *testing.T) {
	if _, err := newGate("", slog.Default()); err == nil {
		t.Fatal("empty baseline path must be refused")
	}
}
