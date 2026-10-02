package blob_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/blob"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newStore(t *testing.T) (*blob.FS, *clock, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "blobs")
	c := &clock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	s, err := blob.NewFS(dir, blob.WithClock(c.now))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, c, dir
}

func put(t *testing.T, s blob.Store, id tenant.ID, key, body string, opts blob.PutOptions) blob.Info {
	t.Helper()
	info, err := s.Put(context.Background(), id, key, strings.NewReader(body), opts)
	if err != nil {
		t.Fatalf("Put(%q): %v", key, err)
	}
	return info
}

func read(t *testing.T, s blob.Store, id tenant.ID, key string) (string, blob.Info, error) {
	t.Helper()
	rc, info, err := s.Get(context.Background(), id, key)
	if err != nil {
		return "", blob.Info{}, err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), info, nil
}

func TestPutGetRoundTrip(t *testing.T) {
	s, c, _ := newStore(t)
	a := tenant.New()
	exp := c.now().Add(time.Hour)
	body := "id,name\n1,alice\n"
	pi := put(t, s, a, "reports/r-1/result.csv", body, blob.PutOptions{ExpiresAt: exp, ContentType: "text/csv"})
	sum := sha256.Sum256([]byte(body))
	if pi.Size != int64(len(body)) || pi.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("Put info = %+v", pi)
	}
	got, gi, err := read(t, s, a, "reports/r-1/result.csv")
	if err != nil || got != body {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if gi.Size != int64(len(body)) || gi.ContentType != "text/csv" || !gi.ExpiresAt.Equal(exp) || gi.Key != "reports/r-1/result.csv" {
		t.Fatalf("Get info = %+v", gi)
	}
}

func TestPutReplacesAndHandlesEmptyBody(t *testing.T) {
	s, _, _ := newStore(t)
	a := tenant.New()
	put(t, s, a, "k", "one", blob.PutOptions{})
	put(t, s, a, "k", "", blob.PutOptions{})
	got, info, err := read(t, s, a, "k")
	if err != nil || got != "" || info.Size != 0 {
		t.Fatalf("after replace: %q %+v %v", got, info, err)
	}
}

// Acceptance 1: given tenant A's key, tenant B cannot read it.
func TestTenantCannotReadAnotherTenantsBlob(t *testing.T) {
	s, _, _ := newStore(t)
	a, b := tenant.New(), tenant.New()
	put(t, s, a, "exports/x.csv", "secret-of-A", blob.PutOptions{})

	if _, _, err := s.Get(context.Background(), b, "exports/x.csv"); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("tenant B Get = %v, want ErrNotFound", err)
	}
	// B cannot reach A's data by naming A's tenant in the key, nor by traversal.
	for _, key := range []string{
		a.String() + "/exports/x.csv",
		"../" + a.String() + "/exports/x.csv",
		"../../" + a.String(),
		"/" + a.String() + "/exports/x.csv",
	} {
		if _, _, err := s.Get(context.Background(), b, key); err == nil || (!errors.Is(err, blob.ErrInvalidKey) && !errors.Is(err, blob.ErrNotFound)) {
			t.Errorf("tenant B Get(%q) = %v", key, err)
		}
	}
	// B's delete of the same key does not remove A's blob.
	if err := s.Delete(context.Background(), b, "exports/x.csv"); err != nil {
		t.Fatal(err)
	}
	if got, _, err := read(t, s, a, "exports/x.csv"); err != nil || got != "secret-of-A" {
		t.Fatalf("A's blob after B's delete: %q %v", got, err)
	}
	// B writing the same key does not overwrite A's.
	put(t, s, b, "exports/x.csv", "B-data", blob.PutOptions{})
	if got, _, _ := read(t, s, a, "exports/x.csv"); got != "secret-of-A" {
		t.Fatalf("A's blob overwritten: %q", got)
	}
	if got, _, _ := read(t, s, b, "exports/x.csv"); got != "B-data" {
		t.Fatalf("B's blob: %q", got)
	}
}

// A file moved by hand between tenant directories is not served under the wrong tenant.
func TestMisplacedFileIsNotServed(t *testing.T) {
	s, _, dir := newStore(t)
	a, b := tenant.New(), tenant.New()
	put(t, s, a, "k", "A", blob.PutOptions{})
	var src string
	_ = filepath.WalkDir(filepath.Join(dir, a.String()), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			src = p
		}
		return nil
	})
	rel, _ := filepath.Rel(filepath.Join(dir, a.String()), src)
	dst := filepath.Join(dir, b.String(), rel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(src, dst); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(context.Background(), b, "k"); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("Get misplaced = %v, want ErrNotFound", err)
	}
}

func TestGetAbsentAndExpired(t *testing.T) {
	s, c, _ := newStore(t)
	a := tenant.New()
	if _, _, err := s.Get(context.Background(), a, "nope"); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("absent = %v", err)
	}
	put(t, s, a, "k", "v", blob.PutOptions{ExpiresAt: c.now().Add(time.Minute)})
	c.advance(time.Minute - time.Nanosecond)
	if _, _, err := read(t, s, a, "k"); err != nil {
		t.Fatalf("just before expiry: %v", err)
	}
	c.advance(time.Nanosecond)
	if _, _, err := s.Get(context.Background(), a, "k"); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("at expiry (unswept) = %v, want ErrNotFound", err)
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	s, _, _ := newStore(t)
	a := tenant.New()
	put(t, s, a, "k", "v", blob.PutOptions{})
	for i := 0; i < 2; i++ {
		if err := s.Delete(context.Background(), a, "k"); err != nil {
			t.Fatalf("delete #%d: %v", i, err)
		}
	}
	if _, _, err := s.Get(context.Background(), a, "k"); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("after delete = %v", err)
	}
}

// Acceptance 2: given an expired blob, the sweep removes it.
func TestSweepRemovesExpiredAndKeepsTheRest(t *testing.T) {
	s, c, dir := newStore(t)
	a, b := tenant.New(), tenant.New()
	put(t, s, a, "old", "1", blob.PutOptions{ExpiresAt: c.now().Add(time.Hour)})
	put(t, s, b, "old", "2", blob.PutOptions{ExpiresAt: c.now().Add(time.Hour)})
	put(t, s, a, "fresh", "3", blob.PutOptions{ExpiresAt: c.now().Add(48 * time.Hour)})
	put(t, s, a, "forever", "4", blob.PutOptions{})
	if before := countBlobFiles(t, dir); before != 4 {
		t.Fatalf("files before = %d", before)
	}

	c.advance(2 * time.Hour)
	res, err := s.Sweep(context.Background())
	if err != nil || res.Removed != 2 {
		t.Fatalf("Sweep = %+v, %v; want 2 removed", res, err)
	}
	if after := countBlobFiles(t, dir); after != 2 {
		t.Fatalf("files after = %d, want 2 (the sweep must remove the files, not only hide them)", after)
	}
	for _, k := range []string{"fresh", "forever"} {
		if _, _, err := read(t, s, a, k); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
	// A second sweep has nothing left to do.
	if res, err := s.Sweep(context.Background()); err != nil || res.Removed != 0 {
		t.Fatalf("second sweep = %+v, %v", res, err)
	}
}

func TestSweepCleansStaleTemporaryFilesOnly(t *testing.T) {
	s, c, dir := newStore(t)
	a := tenant.New()
	put(t, s, a, "k", "v", blob.PutOptions{})
	tmp := filepath.Join(dir, ".tmp")
	stale, young := filepath.Join(tmp, "stale.part"), filepath.Join(tmp, "young.part")
	for _, p := range []string{stale, young} {
		if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := c.now().Add(-2 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(young, c.now(), c.now()); err != nil {
		t.Fatal(err)
	}
	res, err := s.Sweep(context.Background())
	if err != nil || res.Abandoned != 1 || res.Removed != 0 {
		t.Fatalf("Sweep = %+v, %v", res, err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stale partial write survived: %v", err)
	}
	if _, err := os.Stat(young); err != nil {
		t.Errorf("in-flight write was removed: %v", err)
	}
}

func TestSweepReportsCorruptFileAndContinues(t *testing.T) {
	s, c, dir := newStore(t)
	a := tenant.New()
	put(t, s, a, "exp", "v", blob.PutOptions{ExpiresAt: c.now().Add(time.Minute)})
	bad := filepath.Join(dir, a.String(), "zz", strings.Repeat("0", 64)+".blob")
	if err := os.MkdirAll(filepath.Dir(bad), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Hour)
	res, err := s.Sweep(context.Background())
	if res.Removed != 1 || !errors.Is(err, blob.ErrCorrupt) {
		t.Fatalf("Sweep = %+v, %v; want 1 removed and ErrCorrupt", res, err)
	}
}

// A sweep that has read an expired header must not delete a blob a concurrent Put replaced it with.
func TestSweepRacingPutNeverLosesAFreshBlob(t *testing.T) {
	s, c, _ := newStore(t)
	a := tenant.New()
	exp := c.now().Add(time.Minute)
	put(t, s, a, "k", "v0", blob.PutOptions{ExpiresAt: exp})
	c.advance(time.Hour)
	fresh := c.now().Add(24 * time.Hour)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = s.Sweep(context.Background()) }()
		go func() {
			defer wg.Done()
			_, _ = s.Put(context.Background(), a, "k", strings.NewReader("v1"), blob.PutOptions{ExpiresAt: fresh})
		}()
	}
	wg.Wait()
	// The last Put's blob is fresh; whichever interleaving happened, a Put after the sweeps wins.
	put(t, s, a, "k", "v2", blob.PutOptions{ExpiresAt: fresh})
	if _, err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _, err := read(t, s, a, "k"); err != nil || got != "v2" {
		t.Fatalf("after race: %q, %v", got, err)
	}
}

func TestInvalidArguments(t *testing.T) {
	s, _, _ := newStore(t)
	ctx := context.Background()
	if _, err := s.Put(ctx, tenant.ID{}, "k", strings.NewReader("x"), blob.PutOptions{}); !errors.Is(err, blob.ErrInvalidTenant) {
		t.Errorf("zero tenant Put = %v", err)
	}
	if _, _, err := s.Get(ctx, tenant.ID{}, "k"); !errors.Is(err, blob.ErrInvalidTenant) {
		t.Errorf("zero tenant Get = %v", err)
	}
	if err := s.Delete(ctx, tenant.ID{}, "k"); !errors.Is(err, blob.ErrInvalidTenant) {
		t.Errorf("zero tenant Delete = %v", err)
	}
	a := tenant.New()
	if _, err := s.Put(ctx, a, "../x", strings.NewReader("x"), blob.PutOptions{}); !errors.Is(err, blob.ErrInvalidKey) {
		t.Errorf("bad key Put = %v", err)
	}
}

func TestValidateKey(t *testing.T) {
	ok := []string{"a", "report.csv", "reports/2026/10/r-1_final.v2.csv", "A-Z_0-9", strings.Repeat("a", 128), "a/b.c/d"}
	bad := []string{
		"", "/", "/a", "a/", "a//b", ".", "..", "a/..", "../a", "a/../b", ".hidden", "a/.hidden", "a\\b",
		"a\x00b", "a b", "a:b", "é", "a%2e%2e", "a?b", "a*b", strings.Repeat("a", 129),
		strings.Repeat("a/", 300) + "a",
	}
	for _, k := range ok {
		if err := blob.ValidateKey(k); err != nil {
			t.Errorf("ValidateKey(%q) = %v, want ok", k, err)
		}
	}
	for _, k := range bad {
		if err := blob.ValidateKey(k); !errors.Is(err, blob.ErrInvalidKey) {
			t.Errorf("ValidateKey(%q) = %v, want ErrInvalidKey", k, err)
		}
	}
}

func TestCancelledPutLeavesPreviousBlobAndNoPartial(t *testing.T) {
	s, _, dir := newStore(t)
	a := tenant.New()
	put(t, s, a, "k", "original", blob.PutOptions{})

	ctx, cancel := context.WithCancel(context.Background())
	_, err := s.Put(ctx, a, "k", &cancelAfter{cancel: cancel, data: strings.Repeat("x", 1<<20)}, blob.PutOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Put = %v, want context.Canceled", err)
	}
	if got, _, err := read(t, s, a, "k"); err != nil || got != "original" {
		t.Fatalf("after cancelled Put: %q %v", got, err)
	}
	if n := countFiles(t, filepath.Join(dir, ".tmp")); n != 0 {
		t.Fatalf("%d partial files left", n)
	}
}

type cancelAfter struct {
	cancel context.CancelFunc
	data   string
	off    int
}

func (c *cancelAfter) Read(p []byte) (int, error) {
	if c.off >= 4096 {
		c.cancel()
	}
	n := copy(p, c.data[c.off:min(c.off+1024, len(c.data))])
	c.off += n
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func TestFailingReaderLeavesNoPartial(t *testing.T) {
	s, _, dir := newStore(t)
	a := tenant.New()
	boom := errors.New("source failed")
	_, err := s.Put(context.Background(), a, "k", io.MultiReader(strings.NewReader("abc"), errReader{boom}), blob.PutOptions{})
	if !errors.Is(err, boom) {
		t.Fatalf("Put = %v", err)
	}
	if _, _, err := s.Get(context.Background(), a, "k"); !errors.Is(err, blob.ErrNotFound) {
		t.Fatalf("Get after failed Put = %v", err)
	}
	if n := countFiles(t, filepath.Join(dir, ".tmp")); n != 0 {
		t.Fatalf("%d partial files left", n)
	}
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestErrorsDoNotLeakPaths(t *testing.T) {
	s, _, dir := newStore(t)
	a := tenant.New()
	put(t, s, a, "k", "v", blob.PutOptions{})
	// Make the tenant directory unreadable as a file so Get fails with an I/O error.
	if err := os.RemoveAll(filepath.Join(dir, a.String())); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, a.String()), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Put(context.Background(), a, "k2", strings.NewReader("v"), blob.PutOptions{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), a.String()) {
		t.Fatalf("error leaks a path or tenant id: %v", err)
	}
}

func TestFilesAreOwnerOnlyAndSymlinkEscapeIsRefused(t *testing.T) {
	s, _, dir := newStore(t)
	a := tenant.New()
	put(t, s, a, "k", "v", blob.PutOptions{})
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		info, _ := d.Info()
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %v, want owner-only", p, info.Mode().Perm())
		}
		return nil
	})

	// A symlinked tenant directory pointing outside the root must not be followed.
	outside := t.TempDir()
	b := tenant.New()
	if err := os.Symlink(outside, filepath.Join(dir, b.String())); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := s.Put(context.Background(), b, "k", strings.NewReader("v"), blob.PutOptions{}); err == nil {
		t.Fatal("Put followed a symlink out of the root")
	}
	if n := countFiles(t, outside); n != 0 {
		t.Fatalf("%d files written outside the root", n)
	}
}

func TestNewFSRequiresAbsolutePath(t *testing.T) {
	if _, err := blob.NewFS("relative/dir"); err == nil {
		t.Fatal("relative root accepted")
	}
}

func TestConcurrentPutsAreEachConsistent(t *testing.T) {
	s, _, _ := newStore(t)
	a := tenant.New()
	var wg sync.WaitGroup
	bodies := []string{strings.Repeat("a", 5000), strings.Repeat("b", 7000), strings.Repeat("c", 100)}
	for _, b := range bodies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Put(context.Background(), a, "k", bytes.NewReader([]byte(b)), blob.PutOptions{}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got, info, err := read(t, s, a, "k")
	if err != nil || int64(len(got)) != info.Size {
		t.Fatalf("Get: len=%d info=%+v err=%v", len(got), info, err)
	}
	if strings.Trim(got, string(got[0])) != "" {
		t.Fatal("body is a mix of two writers")
	}
}

func countBlobFiles(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".blob") {
			n++
		}
		return nil
	})
	return n
}

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0
		}
		t.Fatal(err)
	}
	return len(es)
}
