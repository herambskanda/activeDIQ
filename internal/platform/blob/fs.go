package blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// The filesystem adapter's layout, under the root directory it is given:
//
//	<tenant-uuid>/<hh>/<sha256(key)>.blob   one file per blob; hh is the first two hex digits
//	.tmp/<random>.part                      a Put in flight
//
// The file name is a hash of the key, so a key never becomes a path component and a path cannot be
// steered by it. Every access goes through os.Root, which refuses to leave the root directory
// through ".." or a symlink. Each file is self-describing: a fixed magic, a 4-byte big-endian header
// length, a JSON header (tenant, key, content type, creation and expiry time), then the body. One
// file means one atomic rename publishes body and metadata together, with no sidecar to disagree
// with it. The header repeats the tenant and key, and Get checks both, so a file that was moved by
// hand is not served under a name it was not stored under.
const (
	magic           = "DIQBLOB1\n"
	maxHeader       = 8 << 10
	tmpDir          = ".tmp"
	blobSuffix      = ".blob"
	staleTmpAge     = time.Hour
	dirMode         = 0o700
	fileMode        = 0o600
	headerLenFieldN = 4
)

type header struct {
	Tenant      string    `json:"tenant"`
	Key         string    `json:"key"`
	ContentType string    `json:"content_type,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (h header) expired(now time.Time) bool {
	return !h.ExpiresAt.IsZero() && !now.Before(h.ExpiresAt)
}

// FS is the filesystem adapter. Create one with NewFS.
type FS struct {
	root *os.Root
	now  func() time.Time
	// mu orders the publish step of a Put against the check-and-remove of a Sweep, so a sweep that
	// read an expired header cannot delete the fresh blob a concurrent Put just renamed over it.
	// It is held only for those two short steps, never while a body is copied.
	mu sync.Mutex
}

// FSOption configures NewFS.
type FSOption func(*FS)

// WithClock replaces the time source, for tests.
func WithClock(now func() time.Time) FSOption { return func(f *FS) { f.now = now } }

var _ Store = (*FS)(nil)

// NewFS opens the filesystem adapter on dir, which must be an absolute path and is created (mode
// 0700) when missing. Blobs are written as owner-only files. dir is operator configuration, never
// a request value.
func NewFS(dir string, opts ...FSOption) (*FS, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("blob: filesystem root must be an absolute path")
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, ioErr("create root", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, ioErr("open root", err)
	}
	f := &FS{root: root, now: time.Now}
	for _, o := range opts {
		o(f)
	}
	return f, nil
}

// Close releases the root directory handle.
func (f *FS) Close() error { return f.root.Close() }

func blobPath(tenantID tenant.ID, key string) (dir, file string) {
	sum := sha256.Sum256([]byte(key))
	h := hex.EncodeToString(sum[:])
	dir = path.Join(tenantID.String(), h[:2])
	return dir, path.Join(dir, h+blobSuffix)
}

// Put implements Store.
func (f *FS) Put(ctx context.Context, tenantID tenant.ID, key string, r io.Reader, opts PutOptions) (Info, error) {
	if err := checkArgs(tenantID, key); err != nil {
		return Info{}, err
	}
	if err := ctx.Err(); err != nil {
		return Info{}, err
	}
	dir, final := blobPath(tenantID, key)
	if err := f.root.MkdirAll(tmpDir, dirMode); err != nil {
		return Info{}, ioErr("put", err)
	}
	if err := f.root.MkdirAll(dir, dirMode); err != nil {
		return Info{}, ioErr("put", err)
	}

	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return Info{}, fmt.Errorf("blob: no entropy: %w", err)
	}
	tmp := path.Join(tmpDir, hex.EncodeToString(rnd[:])+".part")
	tf, err := f.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return Info{}, ioErr("put", err)
	}
	published := false
	defer func() {
		if !published {
			_ = tf.Close()
			_ = f.root.Remove(tmp)
		}
	}()

	created := f.now().UTC()
	hdr := header{Tenant: tenantID.String(), Key: key, ContentType: opts.ContentType, CreatedAt: created}
	if !opts.ExpiresAt.IsZero() {
		hdr.ExpiresAt = opts.ExpiresAt.UTC()
	}
	if err := writeHeader(tf, hdr); err != nil {
		return Info{}, ioErr("put", err)
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(tf, sum), &ctxReader{ctx: ctx, r: r})
	if err != nil {
		if ctx.Err() != nil {
			return Info{}, ctx.Err()
		}
		return Info{}, ioErr("put", err)
	}
	if err := tf.Sync(); err != nil {
		return Info{}, ioErr("put", err)
	}
	if err := tf.Close(); err != nil {
		return Info{}, ioErr("put", err)
	}
	if err := ctx.Err(); err != nil {
		return Info{}, err
	}

	f.mu.Lock()
	err = f.root.Rename(tmp, final)
	f.mu.Unlock()
	if err != nil {
		return Info{}, ioErr("put", err)
	}
	published = true
	return Info{
		Key: key, Size: n, SHA256: hex.EncodeToString(sum.Sum(nil)),
		ContentType: opts.ContentType, CreatedAt: created, ExpiresAt: hdr.ExpiresAt,
	}, nil
}

// Get implements Store.
func (f *FS) Get(ctx context.Context, tenantID tenant.ID, key string) (io.ReadCloser, Info, error) {
	if err := checkArgs(tenantID, key); err != nil {
		return nil, Info{}, err
	}
	if err := ctx.Err(); err != nil {
		return nil, Info{}, err
	}
	_, file := blobPath(tenantID, key)
	fh, err := f.root.Open(file)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, Info{}, ErrNotFound
		}
		return nil, Info{}, ioErr("get", err)
	}
	hdr, bodyAt, err := readHeader(fh)
	if err != nil {
		_ = fh.Close()
		return nil, Info{}, err
	}
	if hdr.Tenant != tenantID.String() || hdr.Key != key || hdr.expired(f.now()) {
		_ = fh.Close()
		return nil, Info{}, ErrNotFound
	}
	st, err := fh.Stat()
	if err != nil {
		_ = fh.Close()
		return nil, Info{}, ioErr("get", err)
	}
	info := Info{
		Key: key, Size: st.Size() - bodyAt, ContentType: hdr.ContentType,
		CreatedAt: hdr.CreatedAt, ExpiresAt: hdr.ExpiresAt,
	}
	return fh, info, nil // fh is positioned at the start of the body
}

// Delete implements Store.
func (f *FS) Delete(ctx context.Context, tenantID tenant.ID, key string) error {
	if err := checkArgs(tenantID, key); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, file := blobPath(tenantID, key)
	if err := f.root.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return ioErr("delete", err)
	}
	return nil
}

// Sweep implements Store.
func (f *FS) Sweep(ctx context.Context) (SweepResult, error) {
	var res SweepResult
	var errs []error
	top, err := f.readDir(".")
	if err != nil {
		return res, ioErr("sweep", err)
	}
	now := f.now()
	for _, e := range top {
		if err := ctx.Err(); err != nil {
			return res, errors.Join(append(errs, err)...)
		}
		if !e.IsDir() {
			continue
		}
		if e.Name() == tmpDir {
			n, err := f.sweepTmp(ctx, now)
			res.Abandoned += n
			if err != nil {
				errs = append(errs, err)
			}
			continue
		}
		n, err := f.sweepTenant(ctx, e.Name(), now)
		res.Removed += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	return res, errors.Join(errs...)
}

func (f *FS) sweepTmp(ctx context.Context, now time.Time) (int, error) {
	entries, err := f.readDir(tmpDir)
	if err != nil {
		return 0, ioErr("sweep", err)
	}
	var errs []error
	n := 0
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return n, errors.Join(append(errs, err)...)
		}
		info, err := e.Info()
		if err != nil || info.IsDir() || now.Sub(info.ModTime()) < staleTmpAge {
			continue // a Put may still be writing it
		}
		if err := f.root.Remove(path.Join(tmpDir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, ioErr("sweep", err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

func (f *FS) sweepTenant(ctx context.Context, tenantDir string, now time.Time) (int, error) {
	shards, err := f.readDir(tenantDir)
	if err != nil {
		return 0, ioErr("sweep", err)
	}
	var errs []error
	n := 0
	for _, s := range shards {
		if !s.IsDir() {
			continue
		}
		shardDir := path.Join(tenantDir, s.Name())
		files, err := f.readDir(shardDir)
		if err != nil {
			errs = append(errs, ioErr("sweep", err))
			continue
		}
		for _, e := range files {
			if err := ctx.Err(); err != nil {
				return n, errors.Join(append(errs, err)...)
			}
			if e.IsDir() || !strings.HasSuffix(e.Name(), blobSuffix) {
				continue
			}
			removed, err := f.sweepFile(path.Join(shardDir, e.Name()), now)
			if err != nil {
				errs = append(errs, err)
			}
			if removed {
				n++
			}
		}
	}
	return n, errors.Join(errs...)
}

// sweepFile removes the blob at p when its header says it has expired. The header is read from an
// open handle and the removal happens only if the path still names that same file, so a blob a
// concurrent Put has just replaced is kept.
func (f *FS) sweepFile(p string, now time.Time) (bool, error) {
	fh, err := f.root.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, ioErr("sweep", err)
	}
	defer fh.Close()
	hdr, _, err := readHeader(fh)
	if err != nil {
		return false, err
	}
	if !hdr.expired(now) {
		return false, nil
	}
	opened, err := fh.Stat()
	if err != nil {
		return false, ioErr("sweep", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	current, err := f.root.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, ioErr("sweep", err)
	}
	if !os.SameFile(opened, current) {
		return false, nil // replaced since it was read
	}
	if err := f.root.Remove(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, ioErr("sweep", err)
	}
	return true, nil
}

func (f *FS) readDir(name string) ([]fs.DirEntry, error) {
	d, err := f.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.ReadDir(-1)
}

func writeHeader(w io.Writer, h header) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString(magic)
	var n [headerLenFieldN]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	buf.Write(n[:])
	buf.Write(b)
	_, err = w.Write(buf.Bytes())
	return err
}

// readHeader reads the framing from the start of r and returns the header and the offset of the
// body, leaving r positioned there.
func readHeader(r io.Reader) (header, int64, error) {
	var fixed [len(magic) + headerLenFieldN]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil || string(fixed[:len(magic)]) != magic {
		return header{}, 0, ErrCorrupt
	}
	n := binary.BigEndian.Uint32(fixed[len(magic):])
	if n == 0 || n > maxHeader {
		return header{}, 0, ErrCorrupt
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return header{}, 0, ErrCorrupt
	}
	var h header
	if err := json.Unmarshal(raw, &h); err != nil {
		return header{}, 0, ErrCorrupt
	}
	return h, int64(len(fixed)) + int64(n), nil
}

// ctxReader stops a copy when the context is cancelled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// ioErr wraps a filesystem error without the path os puts in it: a path would carry the tenant ID
// and the hashed key into logs and API problem details.
func ioErr(op string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		err = le.Err
	}
	return fmt.Errorf("blob: %s: %w", op, err)
}
