package connector_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/compose/config"
	"github.com/skenzeriq/activediq/internal/compose/connector"
	"github.com/skenzeriq/activediq/internal/platform/fleet"
	"github.com/skenzeriq/activediq/internal/platform/fleet/dial"
	"github.com/skenzeriq/activediq/internal/platform/fleet/tunnelclient"
	"github.com/skenzeriq/activediq/internal/platform/ownerfile"
)

// cfgWithDataDir is cfgFile with the given data_dir.
func cfgWithDataDir(t *testing.T, dataDir string) config.Config {
	t.Helper()
	doc := strings.Replace(goodLocal, `"/var/lib/diq/data"`, fmt.Sprintf("%q", dataDir), 1)
	p := filepath.Join(t.TempDir(), "connector.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Config{ConnectorConfigPath: p}
}

// startTrace records what a start did, in order.
type startTrace struct{ events []string }

func (s *startTrace) hooks(t *testing.T) (func(string) (*dial.State, error),
	func(context.Context, connector.Local, *slog.Logger) (*connector.Backend, error),
	func(context.Context, tunnelclient.Config)) {
	var closed bool
	return func(string) (*dial.State, error) {
			s.events = append(s.events, "load")
			return leafState(t, fleet.KindConnector), nil
		},
		func(_ context.Context, loc connector.Local, _ *slog.Logger) (*connector.Backend, error) {
			s.events = append(s.events, "open")
			return boundBackend(t, loc.ConnectionID, &closed), nil
		},
		func(context.Context, tunnelclient.Config) { s.events = append(s.events, "serve") }
}

// T-0596 AC1/AC3: both the state root (the parent) and the state directory are ensured, in that
// order, before any enrolment state is read, the AD session opened or the tunnel dialled.
func TestStartEnsuresStateDirBeforeAnyStateIsTouched(t *testing.T) {
	var tr startTrace
	ensure := func(d string) error { tr.events = append(tr.events, "ensure "+d); return nil }
	load, open, serve := tr.hooks(t)
	root := filepath.Join(string(filepath.Separator), "srv", "diq")
	if err := connector.RunWithEnsure(context.Background(), cfgWithDataDir(t, filepath.Join(root, "data")), ensure, load, open, serve); err != nil {
		t.Fatal(err)
	}
	want := []string{"ensure " + root, "ensure " + filepath.Join(root, "data"), "load", "open", "serve"}
	if fmt.Sprint(tr.events) != fmt.Sprint(want) {
		t.Fatalf("start order %v, want %v", tr.events, want)
	}
}

// T-0596 AC2: ErrDirUnsafe on the state directory or on its parent stops the start before any
// state is read and before the tunnel is dialled, with an error that names the directory.
func TestStartRefusesOnUnsafeStateDir(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "srv", "diq")
	data := filepath.Join(root, "data")
	for _, bad := range []string{data, root} {
		t.Run(bad, func(t *testing.T) {
			var tr startTrace
			ensure := func(d string) error {
				if d == bad {
					return fmt.Errorf("%w: %s", ownerfile.ErrDirUnsafe, filepath.Base(d))
				}
				return nil
			}
			load, open, serve := tr.hooks(t)
			err := connector.RunWithEnsure(context.Background(), cfgWithDataDir(t, data), ensure, load, open, serve)
			if !errors.Is(err, connector.ErrStateDirUnsafe) || !errors.Is(err, ownerfile.ErrDirUnsafe) {
				t.Fatalf("err = %v, want ErrStateDirUnsafe wrapping ErrDirUnsafe", err)
			}
			if !strings.Contains(err.Error(), bad) {
				t.Fatalf("error %q does not name the directory %q", err, bad)
			}
			for _, e := range tr.events {
				t.Errorf("%q ran after the state directory was refused", e)
			}
		})
	}
}

// Any failure to create or verify the directory (not just ErrDirUnsafe) refuses the start.
func TestStartRefusesWhenStateDirCannotBeEnsured(t *testing.T) {
	var tr startTrace
	boom := errors.New("access denied")
	load, open, serve := tr.hooks(t)
	err := connector.RunWithEnsure(context.Background(), cfgWithDataDir(t, filepath.Join(string(filepath.Separator), "srv", "diq", "data")),
		func(string) error { return boom }, load, open, serve)
	if !errors.Is(err, connector.ErrStateDirUnsafe) || !errors.Is(err, boom) || len(tr.events) != 0 {
		t.Fatalf("err = %v, events %v", err, tr.events)
	}
}

// A data_dir with no parent of its own (a filesystem root) has no state root to protect: refused.
func TestStartRefusesDataDirAtFilesystemRoot(t *testing.T) {
	var tr startTrace
	load, open, serve := tr.hooks(t)
	root := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	err := connector.RunWithEnsure(context.Background(), cfgWithDataDir(t, root),
		func(string) error { t.Fatal("ensure called"); return nil }, load, open, serve)
	if !errors.Is(err, connector.ErrStateDirUnsafe) || len(tr.events) != 0 {
		t.Fatalf("err = %v, events %v", err, tr.events)
	}
}

// The real ownerfile check, on real directories (Unix modes; the Windows DACL cases are the
// ownerfile windows tests and the dc1 evidence of T-0577).
func TestStartWithRealOwnerfileCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode cases; Windows DACLs are covered by the ownerfile windows tests")
	}
	run := func(t *testing.T, _, data string) (error, []string) {
		var tr startTrace
		load, open, serve := tr.hooks(t)
		err := connector.RunReal(context.Background(), cfgWithDataDir(t, data), load, open, serve)
		return err, tr.events
	}
	mk := func(t *testing.T, mode os.FileMode) string {
		d := filepath.Join(t.TempDir(), "root")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		return d
	}
	t.Run("safe parent, directory created", func(t *testing.T) {
		root := mk(t, 0o700)
		data := filepath.Join(root, "data")
		err, ev := run(t, root, data)
		if err != nil || fmt.Sprint(ev) != "[load open serve]" {
			t.Fatalf("err %v events %v", err, ev)
		}
		if fi, e := os.Stat(data); e != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("state dir not created 0700: %v %v", fi, e)
		}
	})
	t.Run("parent created when missing", func(t *testing.T) {
		base := mk(t, 0o700)
		root := filepath.Join(base, "diq")
		if err, ev := run(t, root, filepath.Join(root, "data")); err != nil || len(ev) != 3 {
			t.Fatalf("err %v events %v", err, ev)
		}
		if fi, e := os.Stat(root); e != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("parent not created 0700: %v %v", fi, e)
		}
	})
	t.Run("existing safe state directory", func(t *testing.T) {
		root := mk(t, 0o700)
		data := filepath.Join(root, "data")
		if err := os.Mkdir(data, 0o700); err != nil {
			t.Fatal(err)
		}
		if err, _ := run(t, root, data); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("state directory wider than owner-only", func(t *testing.T) {
		root := mk(t, 0o700)
		data := filepath.Join(root, "data")
		if err := os.Mkdir(data, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(data, 0o755); err != nil {
			t.Fatal(err)
		}
		err, ev := run(t, root, data)
		if !errors.Is(err, ownerfile.ErrDirUnsafe) || !strings.Contains(err.Error(), data) || len(ev) != 0 {
			t.Fatalf("err %v events %v", err, ev)
		}
	})
	t.Run("parent wider than owner-only", func(t *testing.T) {
		root := mk(t, 0o755)
		err, ev := run(t, root, filepath.Join(root, "data"))
		if !errors.Is(err, ownerfile.ErrDirUnsafe) || !strings.Contains(err.Error(), root) || len(ev) != 0 {
			t.Fatalf("err %v events %v", err, ev)
		}
		if _, e := os.Stat(filepath.Join(root, "data")); e == nil {
			t.Fatal("state directory was created under an unsafe parent")
		}
	})
	t.Run("state directory is a symlink", func(t *testing.T) {
		root := mk(t, 0o700)
		target := t.TempDir()
		data := filepath.Join(root, "data")
		if err := os.Symlink(target, data); err != nil {
			t.Fatal(err)
		}
		if err, ev := run(t, root, data); !errors.Is(err, ownerfile.ErrDirUnsafe) || len(ev) != 0 {
			t.Fatalf("err %v events %v", err, ev)
		}
	})
}

// A parent owned by someone else (root, for an unprivileged test run) is refused, and nothing is created under it.
func TestStartRefusesParentOwnedBySomeoneElse(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a root-owned directory and an unprivileged euid")
	}
	if fi, err := os.Stat("/usr"); err != nil || !fi.IsDir() {
		t.Skip("no /usr")
	}
	var tr startTrace
	load, open, serve := tr.hooks(t)
	data := "/usr/diq-t0596-data"
	err := connector.RunReal(context.Background(), cfgWithDataDir(t, data), load, open, serve)
	if !errors.Is(err, ownerfile.ErrDirUnsafe) || len(tr.events) != 0 {
		t.Fatalf("err %v events %v", err, tr.events)
	}
	if _, e := os.Stat(data); e == nil {
		t.Fatal("state directory created under a foreign-owned parent")
	}
}
