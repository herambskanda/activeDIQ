package export

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/blob"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Source is a stream of rows, typically a cursor over the collected store. It is pulled one row at
// a time, so nothing about an export holds more than a row in memory (O7).
type Source interface {
	// Columns is the header.
	Columns() []Column
	// Next returns the next row, or io.EOF after the last one. It must honour ctx.
	Next(ctx context.Context) ([]Cell, error)
}

// Counter is optional on a Source. When it is there, an export larger than the cap fails with
// ErrRowCapExceeded before a single byte is written ("before the job starts writing", O7).
type Counter interface {
	Count(ctx context.Context) (int64, error)
}

// Format makes an Encoder over a writer and names the media type it produces. export/csv and
// export/xlsx each provide one; the media type is theirs, never the caller's.
type Format struct {
	New         func(w io.Writer) (Encoder, error)
	ContentType string
}

// ctxCheckEvery is how many rows pass between context checks.
const ctxCheckEvery = 512

// Run streams src through enc: header, every row, Close. On any error the encoder is still closed so
// its resources are released, but the error is returned and the output must be discarded.
// maxRows lowers the cap for this run (0 keeps the encoder's own cap).
func Run(ctx context.Context, src Source, enc Encoder, maxRows int64) (RenderReport, error) {
	fail := func(err error) (RenderReport, error) {
		rep, _ := enc.Close()
		return rep, err
	}
	if maxRows <= 0 || maxRows > MaxDataRows {
		maxRows = MaxDataRows
	}
	if c, ok := src.(Counter); ok {
		n, err := c.Count(ctx)
		if err != nil {
			return fail(fmt.Errorf("export: count: %w", err))
		}
		if n > maxRows {
			return fail(ErrRowCapExceeded)
		}
	}
	if err := enc.Header(src.Columns()); err != nil {
		return fail(err)
	}
	var n int64
	for {
		if n%ctxCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return fail(err)
			}
		}
		row, err := src.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fail(fmt.Errorf("export: source: %w", err))
		}
		if n >= maxRows {
			return fail(ErrRowCapExceeded)
		}
		if err := enc.Row(row); err != nil {
			return fail(err)
		}
		n++
	}
	return enc.Close()
}

// Job describes one export for RunToBlob, the body of the async export job kind.
type Job struct {
	Tenant tenant.ID
	// Key is the tenant-relative blob key of the result.
	Key string
	// Retention is how long the result lives; exports must expire (DM-72 I3).
	Retention time.Duration
	// MaxRows lowers the row cap for this export; 0 means MaxDataRows.
	MaxRows int64
}

// RunToBlob runs the export as a stream into the blob store: the encoder writes into a pipe that
// blob.Put reads, so the result is never held in memory or on the heap as a whole. A failed export
// (cap exceeded, source error, cancel) stores nothing: Put sees the pipe fail and leaves any previous
// blob untouched. The returned RenderReport is what the export audit event records (O8).
func RunToBlob(ctx context.Context, store blob.Store, now func() time.Time, j Job, src Source, f Format) (RenderReport, blob.Info, error) {
	if j.Retention <= 0 {
		return RenderReport{}, blob.Info{}, errors.New("export: a retention is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := io.Pipe()
	type result struct {
		rep RenderReport
		err error
	}
	done := make(chan result, 1)
	go func() {
		enc, err := f.New(pw)
		if err != nil {
			pw.CloseWithError(err)
			done <- result{err: err}
			return
		}
		rep, err := Run(ctx, src, enc, j.MaxRows)
		// Closing the pipe with the error makes Put fail instead of storing a truncated file.
		pw.CloseWithError(err)
		done <- result{rep, err}
	}()
	info, putErr := store.Put(ctx, j.Tenant, j.Key, pr, blob.PutOptions{ExpiresAt: now().Add(j.Retention), ContentType: f.ContentType})
	if putErr != nil {
		cancel()
		pr.CloseWithError(putErr)
	}
	r := <-done
	switch {
	case r.err != nil:
		return r.rep, blob.Info{}, r.err
	case putErr != nil:
		return r.rep, blob.Info{}, putErr
	}
	return r.rep, info, nil
}
