package export_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/blob"
	"github.com/skenzeriq/activediq/internal/platform/export"
	"github.com/skenzeriq/activediq/internal/platform/export/csv"
	"github.com/skenzeriq/activediq/internal/platform/export/xlsx"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

type gen struct {
	n, i    int64 // n < 0: unbounded
	emitted atomic.Int64
	count   int64 // reported by Count when counted
	counted bool
}

func (g *gen) Columns() []export.Column {
	return []export.Column{{Label: "id"}, {Label: "name"}}
}
func (g *gen) Next(ctx context.Context) ([]export.Cell, error) {
	if g.n >= 0 && g.i >= g.n {
		return nil, io.EOF
	}
	g.i++
	g.emitted.Add(1)
	name := "user"
	if g.i%1000 == 0 {
		name = "=cmd|' /C calc'!A0"
	}
	return []export.Cell{export.Int64(g.i), export.Text(name)}, nil
}

type countedGen struct{ *gen }

func (c countedGen) Count(context.Context) (int64, error) { return c.count, nil }

func newStore(t *testing.T) *blob.FS {
	s, err := blob.NewFS(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func read(t *testing.T, s blob.Store, id tenant.ID, key string) []byte {
	rc, _, err := s.Get(context.Background(), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return b
}

func TestRunToBlobCSVAndReport(t *testing.T) {
	s, id := newStore(t), tenant.New()
	rep, info, err := export.RunToBlob(context.Background(), s, time.Now, export.Job{Tenant: id, Key: "e/1", Retention: time.Hour},
		&gen{n: 5000}, csv.Format(csv.Options{}))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Rows != 5000 || rep.Neutralised != 5 || info.ContentType != "text/csv; charset=utf-8" || info.ExpiresAt.IsZero() {
		t.Fatalf("%+v %+v", rep, info)
	}
	if got := strings.Count(string(read(t, s, id, "e/1")), "\"\t=cmd|"); got != 5 {
		t.Fatalf("neutralised cells in file = %d", got)
	}
}

func TestRunToBlobXLSXIsAValidArchive(t *testing.T) {
	s, id := newStore(t), tenant.New()
	rep, _, err := export.RunToBlob(context.Background(), s, time.Now, export.Job{Tenant: id, Key: "e/2", Retention: time.Hour},
		&gen{n: 3000}, xlsx.Format(xlsx.Options{Title: "t"}))
	if err != nil || rep.Rows != 3000 || rep.Neutralised != 3 {
		t.Fatalf("%+v %v", rep, err)
	}
	b := read(t, s, id, "e/2")
	if _, err := zip.NewReader(bytes.NewReader(b), int64(len(b))); err != nil {
		t.Fatal(err)
	}
}

// Acceptance 2: stops at the row cap. With an unbounded source of unknown size, the job fails with
// RowCapExceeded after the cap, reads no further, and stores nothing.
func TestRowCapStopsUnboundedExport(t *testing.T) {
	for name, f := range map[string]export.Format{"csv": csv.Format(csv.Options{}), "xlsx": xlsx.Format(xlsx.Options{})} {
		t.Run(name, func(t *testing.T) {
			s, id := newStore(t), tenant.New()
			g := &gen{n: -1}
			_, _, err := export.RunToBlob(context.Background(), s, time.Now, export.Job{Tenant: id, Key: "k", Retention: time.Hour, MaxRows: 1000}, g, f)
			if !errors.Is(err, export.ErrRowCapExceeded) {
				t.Fatalf("err = %v", err)
			}
			if e := g.emitted.Load(); e != 1001 {
				t.Fatalf("source pulled %d rows, want exactly cap+1", e)
			}
			if _, _, err := s.Get(context.Background(), id, "k"); !errors.Is(err, blob.ErrNotFound) {
				t.Fatalf("partial export stored: %v", err)
			}
		})
	}
}

func TestCountRefusesBeforeWriting(t *testing.T) {
	g := &gen{n: 10, count: export.MaxDataRows + 1}
	var b bytes.Buffer
	enc, _ := csv.NewWriter(&b, csv.Options{OmitBOM: true})
	_, err := export.Run(context.Background(), countedGen{g}, enc, 0)
	if !errors.Is(err, export.ErrRowCapExceeded) || g.emitted.Load() != 0 || b.Len() != 0 {
		t.Fatalf("err %v emitted %d bytes %d", err, g.emitted.Load(), b.Len())
	}
}

func TestFailedExportKeepsPreviousBlob(t *testing.T) {
	s, id := newStore(t), tenant.New()
	job := export.Job{Tenant: id, Key: "same", Retention: time.Hour}
	if _, _, err := export.RunToBlob(context.Background(), s, time.Now, job, &gen{n: 3}, csv.Format(csv.Options{})); err != nil {
		t.Fatal(err)
	}
	before := read(t, s, id, "same")
	job.MaxRows = 2
	if _, _, err := export.RunToBlob(context.Background(), s, time.Now, job, &gen{n: -1}, csv.Format(csv.Options{})); !errors.Is(err, export.ErrRowCapExceeded) {
		t.Fatal(err)
	}
	if !bytes.Equal(before, read(t, s, id, "same")) {
		t.Fatal("previous blob changed")
	}
}

func TestCancelStopsTheJob(t *testing.T) {
	s, id := newStore(t), tenant.New()
	ctx, cancel := context.WithCancel(context.Background())
	g := &gen{n: -1}
	go func() {
		for g.emitted.Load() < 2000 {
			runtime.Gosched()
		}
		cancel()
	}()
	_, _, err := export.RunToBlob(ctx, s, time.Now, export.Job{Tenant: id, Key: "c", Retention: time.Hour}, g, csv.Format(csv.Options{}))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := s.Get(context.Background(), id, "c"); !errors.Is(err, blob.ErrNotFound) {
		t.Fatal("stored after cancel")
	}
}

func TestRetentionRequired(t *testing.T) {
	_, _, err := export.RunToBlob(context.Background(), newStore(t), time.Now, export.Job{Tenant: tenant.New(), Key: "k"}, &gen{n: 1}, csv.Format(csv.Options{}))
	if err == nil {
		t.Fatal("no retention accepted")
	}
}

// Streaming: bytes reach the consumer long before the source is exhausted, and the heap stays flat.
func TestStreamsWithBoundedMemory(t *testing.T) {
	const total = 500_000
	for name, f := range map[string]export.Format{"csv": csv.Format(csv.Options{}), "xlsx": xlsx.Format(xlsx.Options{})} {
		t.Run(name, func(t *testing.T) {
			g := &gen{n: total}
			var firstAt int64 = -1
			var peak uint64
			var ms runtime.MemStats
			runtime.GC()
			pr, pw := io.Pipe()
			go func() {
				enc, _ := f.New(pw)
				_, err := export.Run(context.Background(), g, enc, 0)
				pw.CloseWithError(err)
			}()
			buf := make([]byte, 32<<10)
			var read, reads int64
			for {
				n, err := pr.Read(buf)
				read += int64(n)
				if n > 0 && firstAt < 0 {
					firstAt = g.emitted.Load()
				}
				if reads++; reads%8 == 0 {
					runtime.ReadMemStats(&ms)
					if ms.HeapAlloc > peak {
						peak = ms.HeapAlloc
					}
				}
				if err != nil {
					if err != io.EOF {
						t.Fatal(err)
					}
					break
				}
			}
			if firstAt > total/10 {
				t.Fatalf("first bytes after %d of %d rows: not streaming", firstAt, total)
			}
			if peak > 64<<20 {
				t.Fatalf("heap peaked at %d MiB", peak>>20)
			}
			t.Logf("%s: %d rows, %d MiB out, first byte after %d rows, peak heap %d MiB", name, total, read>>20, firstAt, peak>>20)
		})
	}
}
