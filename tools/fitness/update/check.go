package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/updateverify"
)

// scenario is one TM-F-UPDATE case: a payload, the install's state, and the expected outcome.
type scenario struct {
	id, ac string
	// want is the closed-enum refusal reason, or "" when the update must be accepted.
	want    updateverify.Reason
	pinned  []byte
	payload payload
	floor   updateverify.Floor
	// hostFloor, when set, is the host half of a Dual floor; the database half starts empty, i.e. the
	// database was restored from a backup taken before the floor rose.
	hostFloor   *updateverify.Floor
	now         time.Time
	wantExpiry  bool  // a freeze refusal must carry the expiry for the console
	maxArtefact int64 // when > 0, the verifier may read at most this many artefact bytes (mid-stream abort)
	wantVersion string
}

// verifyFunc is the call under proof. The real one is Verifier.Verify; -sabotage substitutes a broken
// one so ci-proof can show the harness fails when the verifier does.
type verifyFunc func(ctx context.Context, v *updateverify.Verifier, in updateverify.Input, dataDir string) (*updateverify.Result, error)

func realVerify(ctx context.Context, v *updateverify.Verifier, in updateverify.Input, _ string) (*updateverify.Result, error) {
	return v.Verify(ctx, in)
}

// outcome is what one courier run ended with, for the cross-courier comparison.
type outcome struct{ sha, committed string }

// runOne runs a scenario through a courier in a fresh sandbox and returns the problems found.
func runOne(sc scenario, c courier, verify verifyFunc) (problems []string, out outcome) {
	fail := func(f string, a ...any) {
		problems = append(problems, fmt.Sprintf("%s/%s: %s", sc.id, c.name, fmt.Sprintf(f, a...)))
	}
	sandbox, err := os.MkdirTemp("", "tmfupdate-")
	if err != nil {
		fail("sandbox: %v", err)
		return
	}
	defer os.RemoveAll(sandbox)
	quarDir := filepath.Join(sandbox, "quarantine")
	dataDir := filepath.Join(sandbox, "data") // where an extraction would land; must stay empty
	courierDir := filepath.Join(sandbox, "courier")
	for _, d := range []string{dataDir, courierDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			fail("sandbox: %v", err)
			return
		}
	}

	mem := &updateverify.MemoryFloor{F: sc.floor}
	var floor updateverify.FloorStore = mem
	if sc.hostFloor != nil {
		host := &updateverify.FileFloor{Path: filepath.Join(sandbox, "host", "floor.json")}
		if err := os.Mkdir(filepath.Dir(host.Path), 0o700); err != nil {
			fail("sandbox: %v", err)
			return
		}
		if err := host.Raise(context.Background(), *sc.hostFloor); err != nil {
			fail("seed host floor: %v", err)
			return
		}
		floor = updateverify.Dual{Database: mem, Host: host}
	}
	v, err := updateverify.New(updateverify.Config{PinnedRoot: sc.pinned, Floor: floor, Quarantine: updateverify.DirQuarantine{Dir: quarDir},
		Name: "server", Platform: "windows", NoPlatformCheck: true, Now: func() time.Time { return sc.now }})
	if err != nil {
		fail("construct verifier: %v", err)
		return
	}
	in, cnt, cleanup, err := c.deliver(courierDir, sc.payload)
	defer cleanup()
	if err != nil {
		fail("courier: %v", err)
		return
	}
	ctx := context.Background()
	res, verr := verify(ctx, v, in, dataDir)

	if sc.want == "" {
		if verr != nil {
			fail("expected acceptance, got: %v", verr)
			return
		}
		if err := v.Commit(ctx, res); err != nil {
			fail("commit: %v", err)
			return
		}
		f, err := floor.Load(ctx)
		if err != nil || f.Committed != sc.wantVersion {
			fail("committed version %q, want %q (%v)", f.Committed, sc.wantVersion, err)
		}
		rc, err := res.Open()
		if err != nil {
			fail("open quarantined artefact: %v", err)
			return
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		if sum(b) != res.Release.SHA256 || sum(b) != sum(sc.payload.artefact) {
			fail("quarantined artefact does not match the signed hash")
		}
		out = outcome{res.Release.SHA256, f.Committed}
	} else {
		var ref *updateverify.Refusal
		switch {
		case verr == nil:
			fail("accepted a bad update; want refusal %q", sc.want)
		case !errors.As(verr, &ref):
			fail("operational error instead of the refusal %q: %v", sc.want, verr)
		case ref.Reason != sc.want:
			fail("refused with %q, want %q (%s)", ref.Reason, sc.want, ref.Detail)
		case sc.wantExpiry && ref.Expiry.IsZero():
			fail("freeze refusal carries no expiry for the console")
		}
	}

	// Nothing outside quarantine; nothing in quarantine unless accepted; nothing ever extracted.
	if left := entries(dataDir); len(left) > 0 {
		fail("files appeared in the data directory (extraction before verification): %v", left)
	}
	q := entries(quarDir)
	switch {
	case sc.want != "" && len(q) > 0:
		fail("a refused update left %v in quarantine", q)
	case sc.want == "" && len(q) != 1:
		fail("an accepted update left %d quarantine files, want 1", len(q))
	}
	if extra := strays(sandbox, quarDir, dataDir, courierDir, filepath.Join(sandbox, "host")); len(extra) > 0 {
		fail("files outside quarantine: %v", extra)
	}
	if sc.maxArtefact > 0 && cnt != nil && cnt.n > sc.maxArtefact {
		fail("read %d artefact bytes, want an abort at about %d (overlong artefact must stop mid-stream)", cnt.n, sc.maxArtefact)
	}
	return
}

func entries(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && p != dir {
			out = append(out, filepath.Base(p))
		}
		return nil
	})
	return out
}

// strays lists sandbox entries that are not under one of the allowed directories.
func strays(sandbox string, allowed ...string) []string {
	var out []string
	_ = filepath.WalkDir(sandbox, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == sandbox {
			return nil
		}
		for _, a := range allowed {
			if p == a {
				return fs.SkipDir
			}
		}
		out = append(out, p)
		return nil
	})
	return out
}

// Run executes every scenario through the couriers and returns the problems found.
func Run(scenarios []scenario, couriers []courier, verify verifyFunc) []string {
	var problems []string
	for _, sc := range scenarios {
		outs := map[string]outcome{}
		for _, c := range couriers {
			p, o := runOne(sc, c, verify)
			problems = append(problems, p...)
			outs[c.name] = o
		}
		if sc.want == "" && len(couriers) > 1 {
			var first *outcome
			for _, c := range couriers {
				o := outs[c.name]
				if first == nil {
					first = &o
				} else if o != *first {
					problems = append(problems, fmt.Sprintf("%s: couriers diverged: %v vs %v", sc.id, *first, o))
				}
			}
		}
	}
	return problems
}
