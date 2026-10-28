package updateverify

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func wantRefusal(t *testing.T, err error, r Reason) *Refusal {
	t.Helper()
	var ref *Refusal
	if !errors.As(err, &ref) || ref.Reason != r {
		t.Fatalf("want refusal %s, got %v", r, err)
	}
	return ref
}

func ls(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func setup(t *testing.T) (*world, *MemoryFloor, string) {
	return newWorld(t), &MemoryFloor{}, filepath.Join(t.TempDir(), "q")
}

func TestHappyPath(t *testing.T) {
	w, fl, q := setup(t)
	res, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), w.input())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(res.Path)
	if !bytes.Equal(got, w.artefact) || filepath.Dir(res.Path) != q {
		t.Fatalf("artefact not in quarantine: %s", res.Path)
	}
	if fl.F.Targets != 5 || fl.F.Committed != "" {
		t.Fatalf("floor %+v", fl.F)
	}
	if len(res.SignerKeyIDs[RoleTargets]) != 1 {
		t.Fatal("signer ids missing")
	}
}

// AC-1 / AC-2
func TestTamperArtefactAndManifest(t *testing.T) {
	w, fl, q := setup(t)
	in := w.input()
	bad := append([]byte(nil), w.artefact...)
	bad[3] ^= 1
	in.Artifact = bytesReader(bad)
	_, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), in)
	wantRefusal(t, err, ReasonTamper)
	if f := ls(t, q); len(f) != 0 {
		t.Fatalf("quarantine not cleaned: %v", f)
	}

	// manifest with modified hash: signed by targets key but not matching the artefact
	w.rel.SHA256 = w.release("1.6").SHA256[:62] + "00"
	_, err = w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), w.input())
	wantRefusal(t, err, ReasonTamper)

	// modified length
	w2 := newWorld(t)
	w2.rel.Length++
	_, err = w2.verifier(&MemoryFloor{}, DirQuarantine{q}).Verify(context.Background(), w2.input())
	wantRefusal(t, err, ReasonTamper)
	if f := ls(t, q); len(f) != 0 {
		t.Fatalf("quarantine not cleaned: %v", f)
	}
}

type countingReader struct{ n int64 }

func (c *countingReader) Read(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func TestOverlongArtefactAbortsMidStream(t *testing.T) {
	w, fl, q := setup(t)
	in := w.input()
	cr := &countingReader{}
	in.Artifact = cr // endless
	_, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), in)
	wantRefusal(t, err, ReasonTamper)
	if cr.n > int64(len(w.artefact))+64*1024 {
		t.Fatalf("read %d bytes of an endless stream", cr.n)
	}
	if len(ls(t, q)) != 0 {
		t.Fatal("partial left behind")
	}
}

func TestMetadataTamperAndOversize(t *testing.T) {
	w, fl, q := setup(t)
	in := w.input()
	in.Targets = append([]byte(nil), in.Targets...)
	in.Targets[40] ^= 1
	_, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), in)
	wantRefusal(t, err, ReasonTamper)

	in = w.input()
	v := w.verifier(fl, DirQuarantine{q})
	v.cfg.MaxMetadataBytes = 10
	_, err = v.Verify(context.Background(), in)
	wantRefusal(t, err, ReasonTamper)
}

// AC-4
func TestRollback(t *testing.T) {
	w, fl, q := setup(t)
	fl.F = Floor{Root: 1, Timestamp: 5, Snapshot: 5, Targets: 5, Committed: "1.6"}
	w.rel = w.release("1.5")
	_, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), w.input())
	wantRefusal(t, err, ReasonRollback)

	for name, mut := range map[string]func(*world){
		"timestamp": func(w *world) { w.tsV = 4 },
		"snapshot":  func(w *world) { w.snV = 4 },
		"targets":   func(w *world) { w.tgV = 4 },
	} {
		w := newWorld(t)
		mut(w)
		_, err := w.verifier(&MemoryFloor{F: Floor{Timestamp: 5, Snapshot: 5, Targets: 5}}, DirQuarantine{q}).Verify(context.Background(), w.input())
		if r := wantRefusal(t, err, ReasonRollback); r.Role != name {
			t.Fatalf("%s: role %s", name, r.Role)
		}
	}
}

func TestRollbackSurvivesDatabaseRestore(t *testing.T) {
	w, _, q := setup(t)
	db, host := &MemoryFloor{}, &FileFloor{Path: filepath.Join(t.TempDir(), "floor.json")}
	d := Dual{db, host}
	v := w.verifier(d, DirQuarantine{q})
	res, err := v.Verify(context.Background(), w.input())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Commit(context.Background(), res); err != nil {
		t.Fatal(err)
	}
	db.F = Floor{} // database restored from a backup taken before 1.6
	w.rel = w.release("1.5")
	w.tgV, w.snV, w.tsV = 3, 3, 3
	_, err = v.Verify(context.Background(), w.input())
	wantRefusal(t, err, ReasonRollback)
	if db.F.Committed != "1.6" {
		t.Fatalf("database half not healed: %+v", db.F)
	}
}

func TestDualFailsClosed(t *testing.T) {
	if _, err := (Dual{&MemoryFloor{}, nil}).Load(context.Background()); err == nil {
		t.Fatal("missing half must fail")
	}
}

// AC-5
func TestFreezeAndClock(t *testing.T) {
	for name, mut := range map[string]func(*world){
		"timestamp": func(w *world) { w.tsExp = t0.Add(-time.Minute) },
		"snapshot":  func(w *world) { w.snExp = t0.Add(-time.Minute) },
		"targets":   func(w *world) { w.tgExp = t0.Add(-time.Minute) },
	} {
		w, fl, q := setup(t)
		mut(w)
		_, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), w.input())
		r := wantRefusal(t, err, ReasonFreeze)
		if r.Role != name || r.Expiry.IsZero() {
			t.Fatalf("%s: %+v", name, r)
		}
	}
	w, fl, q := setup(t)
	fl.F.NewestSigning = t0.Add(time.Hour) // we verified something signed in the "future": the clock went back
	_, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), w.input())
	wantRefusal(t, err, ReasonFreeze)
}

// AC-3 / AC-6
func rotate(t *testing.T, w *world, newTS tkey, signers []tkey, expiresNewRoot ...time.Time) []byte {
	return mkRoot(t, rootSpec{version: 2, roles: map[string]roleSpec{
		RoleRoot: {w.rootK, 2}, RoleTimestamp: {[]tkey{newTS}, 1}, RoleSnapshot: {[]tkey{w.sn}, 1}, RoleTargets: {[]tkey{w.tg}, 1}}, signers: signers})
}

func TestRootRotation(t *testing.T) {
	w, fl, q := setup(t)
	newTS := newKey(t)
	good := rotate(t, w, newTS, w.rootK[:2])
	w.rootV = 2
	oldTS := w.ts
	w.ts = newTS
	in := w.input()
	in.RootChain = [][]byte{w.rootRaw, good} // bundle includes the oldest root
	if _, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), in); err != nil {
		t.Fatalf("valid rotation: %v", err)
	}
	if fl.F.Root != 2 {
		t.Fatalf("root floor %d", fl.F.Root)
	}

	// fewer than the old threshold
	w.ts = newTS
	fl2 := &MemoryFloor{}
	weak := rotate(t, w, newTS, w.rootK[:1])
	in.RootChain = [][]byte{weak}
	_, err := w.verifier(fl2, DirQuarantine{q}).Verify(context.Background(), in)
	wantRefusal(t, err, ReasonUnsignedByRoot)

	// metadata signed by the key the new root removed
	w.ts = oldTS
	in = w.input()
	in.RootChain = [][]byte{good}
	_, err = w.verifier(&MemoryFloor{}, DirQuarantine{q}).Verify(context.Background(), in)
	wantRefusal(t, err, ReasonRevokedKey)
}

func TestRootRotationNeedsNewKeysToo(t *testing.T) {
	w, _, q := setup(t)
	k := []tkey{newKey(t), newKey(t)}
	// new root declares a new root-role key set but is signed only by the old keys
	bad := mkRoot(t, rootSpec{version: 2, roles: map[string]roleSpec{
		RoleRoot: {k, 2}, RoleTimestamp: {[]tkey{w.ts}, 1}, RoleSnapshot: {[]tkey{w.sn}, 1}, RoleTargets: {[]tkey{w.tg}, 1}}, signers: w.rootK[:2]})
	w.rootV = 2
	in := w.input()
	in.RootChain = [][]byte{bad}
	_, err := w.verifier(&MemoryFloor{}, DirQuarantine{q}).Verify(context.Background(), in)
	wantRefusal(t, err, ReasonUnsignedByRoot)
}

func TestRevokedKeyCannotBeReAdded(t *testing.T) {
	w, _, q := setup(t)
	newTS := newKey(t)
	r2 := rotate(t, w, newTS, w.rootK[:2])
	r3 := mkRoot(t, rootSpec{version: 3, roles: map[string]roleSpec{
		RoleRoot: {w.rootK, 2}, RoleTimestamp: {[]tkey{w.ts}, 1}, RoleSnapshot: {[]tkey{w.sn}, 1}, RoleTargets: {[]tkey{w.tg}, 1}}, signers: w.rootK[:2]})
	w.rootV = 3
	in := w.input()
	in.RootChain = [][]byte{r2, r3}
	_, err := w.verifier(&MemoryFloor{}, DirQuarantine{q}).Verify(context.Background(), in)
	wantRefusal(t, err, ReasonRevokedKey)
}

func TestRootRollbackAndExpiry(t *testing.T) {
	w, _, q := setup(t)
	_, err := w.verifier(&MemoryFloor{F: Floor{Root: 2}}, DirQuarantine{q}).Verify(context.Background(), w.input())
	wantRefusal(t, err, ReasonRollback)
	w.rootRaw = mkRoot(t, rootSpec{version: 1, expires: t0.Add(-time.Hour), roles: map[string]roleSpec{
		RoleRoot: {w.rootK, 2}, RoleTimestamp: {[]tkey{w.ts}, 1}, RoleSnapshot: {[]tkey{w.sn}, 1}, RoleTargets: {[]tkey{w.tg}, 1}}, signers: w.rootK[:2]})
	_, err = w.verifier(&MemoryFloor{}, DirQuarantine{q}).Verify(context.Background(), w.input())
	wantRefusal(t, err, ReasonFreeze)
}

// AC-7
func TestServerKeyOnlyRefusedAndWithdrawn(t *testing.T) {
	w, fl, q := setup(t)
	server := newKey(t)
	w.tg = server // targets signed by the server's own key; the consumer's pinned root does not list it
	in := w.input()
	_, err := w.verifier(fl, DirQuarantine{q}).Verify(context.Background(), in)
	wantRefusal(t, err, ReasonUnsignedByRoot)
	if len(ls(t, q)) != 0 {
		t.Fatal("something written to quarantine")
	}

	w2, fl2, _ := setup(t)
	w2.rel.Withdrawn = true
	_, err = w2.verifier(fl2, DirQuarantine{q}).Verify(context.Background(), w2.input())
	wantRefusal(t, err, ReasonWithdrawn)
}

func TestPinnedRootMustBeSelfSigned(t *testing.T) {
	w := newWorld(t)
	_, err := New(Config{PinnedRoot: mkRoot(t, rootSpec{version: 1, roles: map[string]roleSpec{
		RoleRoot: {w.rootK, 2}, RoleTimestamp: {[]tkey{w.ts}, 1}, RoleSnapshot: {[]tkey{w.sn}, 1}, RoleTargets: {[]tkey{w.tg}, 1}}, signers: w.rootK[:1]}),
		Floor: &MemoryFloor{}, Quarantine: DirQuarantine{t.TempDir()}, NoPlatformCheck: true})
	if err == nil {
		t.Fatal("pinned root under threshold accepted")
	}
	if _, err := New(Config{PinnedRoot: w.rootRaw, Floor: &MemoryFloor{}, Quarantine: DirQuarantine{t.TempDir()}}); err == nil {
		t.Fatal("missing PlatformCheck must be a construction error")
	}
}

func TestPlatformCheckRunsBeforeReturn(t *testing.T) {
	w, fl, q := setup(t)
	v, err := New(Config{PinnedRoot: w.rootRaw, Floor: fl, Quarantine: DirQuarantine{q}, Now: func() time.Time { return t0 },
		PlatformCheck: func(context.Context, string, Release) error { return errors.New("bad authenticode") }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(context.Background(), w.input())
	wantRefusal(t, err, ReasonTamper)
	if len(ls(t, q)) != 0 {
		t.Fatal("artefact kept after platform failure")
	}
}

func TestReasonsClosedEnum(t *testing.T) {
	want := []Reason{"tamper", "rollback", "freeze", "revoked_key", "unsigned_by_root", "withdrawn"}
	got := Reasons()
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal(got)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		w    int
	}{{"1.5", "1.6", -1}, {"1.10", "1.9", 1}, {"1.6", "1.6.0", 0}, {"2", "1.99", 1}} {
		if g, _ := compareVersions(c.a, c.b); g != c.w {
			t.Fatalf("%v: %d", c, g)
		}
	}
	if _, err := compareVersions("1.x", "1"); err == nil {
		t.Fatal("non-numeric accepted")
	}
}
