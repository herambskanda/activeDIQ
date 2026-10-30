//go:build unix

package updateverify

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQuarantineRefusesSymlinkDir(t *testing.T) {
	w, fl, _ := setup(t)
	base := t.TempDir()
	target := filepath.Join(base, "open")
	if err := os.Mkdir(target, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(target, 0o777)
	link := filepath.Join(base, "q")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err := w.verifier(fl, DirQuarantine{link}).Verify(context.Background(), w.input())
	if err == nil {
		t.Fatal("symlinked quarantine dir accepted")
	}
	if len(ls(t, target)) != 0 {
		t.Fatal("artefact written through the symlink")
	}
}

func TestQuarantineRefusesGroupOrWorldWritable(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o720} {
		w, fl, _ := setup(t)
		dir := filepath.Join(t.TempDir(), "q")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := w.verifier(fl, DirQuarantine{dir}).Verify(context.Background(), w.input()); err == nil {
			t.Fatalf("mode %o accepted", mode)
		}
		if len(ls(t, dir)) != 0 {
			t.Fatalf("mode %o: file left behind", mode)
		}
	}
}

func TestResultOpenReturnsVerifiedBytes(t *testing.T) {
	w, fl, q := setup(t)
	res, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), w.input())
	if err != nil {
		t.Fatal(err)
	}
	f, err := res.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	if string(b) != string(w.artefact) {
		t.Fatalf("got %q", b)
	}
}

func TestResultOpenDetectsSwapAfterVerify(t *testing.T) {
	swaps := map[string]func(path string) error{
		"overwrite": func(p string) error { return os.WriteFile(p, []byte("evil-bytes"), 0o600) },
		"same-length": func(p string) error {
			b, _ := os.ReadFile(p)
			b[0] ^= 1
			return os.WriteFile(p, b, 0o600)
		},
		"symlink": func(p string) error {
			ev := p + ".evil"
			if err := os.WriteFile(ev, []byte("evil"), 0o600); err != nil {
				return err
			}
			if err := os.Remove(p); err != nil {
				return err
			}
			return os.Symlink(ev, p)
		},
		"delete": os.Remove,
	}
	for name, swap := range swaps {
		w, fl, q := setup(t)
		res, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), w.input())
		if err != nil {
			t.Fatal(err)
		}
		if err := swap(res.Path); err != nil {
			t.Fatal(err)
		}
		f, err := res.Open()
		if err == nil {
			f.Close()
			t.Fatalf("%s: swapped artefact opened", name)
		}
		wantRefusal(t, err, ReasonTamper)
	}
}

func TestResultOpenRefusesWritableByOthers(t *testing.T) {
	cases := map[string]func(t *testing.T, path string){
		"parent-swap": func(t *testing.T, path string) {
			dir := filepath.Dir(path)
			b, _ := os.ReadFile(path)
			if err := os.Rename(dir, dir+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0o777); err != nil {
				t.Fatal(err)
			}
			_ = os.Chmod(dir, 0o777)
			if err := os.WriteFile(path, b, 0o666); err != nil {
				t.Fatal(err)
			}
			_ = os.Chmod(path, 0o666)
		},
		"in-place-0666": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, swap := range cases {
		w, fl, q := setup(t)
		res, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), w.input())
		if err != nil {
			t.Fatal(err)
		}
		swap(t, res.Path)
		f, err := res.Open()
		if err == nil {
			f.Close()
			t.Fatalf("%s: opened", name)
		}
		wantRefusal(t, err, ReasonTamper)
	}
}

func TestPinnedComponentRefusesOtherSignedRelease(t *testing.T) {
	w, fl, q := setup(t) // the signed manifest lists only server/windows
	for _, pin := range [][2]string{{"agent", "windows"}, {"server", "linux"}} {
		v, err := New(Config{PinnedRoot: w.rootRaw, Floor: fl, Quarantine: DirQuarantine{q}, Name: pin[0], Platform: pin[1],
			NoPlatformCheck: true, Now: func() time.Time { return t0 }})
		if err != nil {
			t.Fatal(err)
		}
		_, err = v.Verify(context.Background(), w.input())
		wantRefusal(t, err, ReasonTamper)
		if len(ls(t, q)) != 0 {
			t.Fatal("artefact quarantined for another component")
		}
	}
	if _, err := New(Config{PinnedRoot: w.rootRaw, Floor: fl, Quarantine: DirQuarantine{q}, NoPlatformCheck: true}); err == nil {
		t.Fatal("Name/Platform not required")
	}
}

func TestClockSkewToleratedForSigningTime(t *testing.T) {
	w, fl, q := setup(t)
	w.issued = t0.Add(4 * time.Minute) // signed 4 minutes ahead of our clock, inside the skew
	fl.F.NewestSigning = time.Time{}
	if _, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), w.input()); err != nil {
		t.Fatal(err)
	}
	// The floor now holds that signing time; the same clock must not freeze the next check.
	w.rel = w.release("1.6")
	if _, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), w.input()); err != nil {
		t.Fatalf("frozen by own skew: %v", err)
	}
}
