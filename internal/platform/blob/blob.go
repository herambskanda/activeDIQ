// Package blob is the kernel's blob store: report results, exports and snapshots, stored outside the
// database under tenant-prefixed keys with an optional expiry (ADR-0002 "Blobs" row, DM-72 I3,
// TM-TB4-T8).
//
// Every operation takes the tenant.ID as a separate argument and the adapter derives the storage
// location from it, so a caller cannot name another tenant's object by choosing a key: a key is a
// tenant-relative name, validated by ValidateKey, and an adapter never receives a raw path or a
// pre-prefixed key from a caller. A tenant that asks for a key that exists only under another
// tenant sees ErrNotFound, the same as for a key that never existed.
//
// Adapters implement Store. This package ships the filesystem adapter (NewFS). The S3-API adapter
// is a separate ticket; the interface carries nothing that is filesystem-specific.
package blob

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Typed errors. Callers match with errors.Is; none of them carries a path, a key or another
// tenant's identifier.
var (
	// ErrNotFound means there is no live blob under that key for that tenant: it was never stored,
	// was deleted, has expired, or belongs to another tenant. The four cases are deliberately not
	// distinguishable.
	ErrNotFound = errors.New("blob: not found")
	// ErrInvalidKey means the key is not a valid tenant-relative blob key (see ValidateKey).
	ErrInvalidKey = errors.New("blob: invalid key")
	// ErrInvalidTenant means the tenant.ID is the zero value.
	ErrInvalidTenant = errors.New("blob: invalid tenant")
)

// PutOptions describes the blob being stored.
type PutOptions struct {
	// ExpiresAt is the instant at and after which the blob is no longer readable and the next sweep
	// removes it. The zero value means the blob is kept until Delete (baseline snapshots); report
	// results and exports must set it (DM-72 I3).
	ExpiresAt time.Time
	// ContentType is recorded and returned by Get. It is informational and never interpreted here.
	ContentType string
}

// Info describes a stored blob.
type Info struct {
	// Key is the tenant-relative key.
	Key string
	// Size is the body length in bytes.
	Size int64
	// SHA256 is the lower-case hex SHA-256 of the body. Put computes it while streaming; Get
	// leaves it empty because the adapter does not re-read the body to verify it.
	SHA256      string
	ContentType string
	CreatedAt   time.Time
	// ExpiresAt is zero for a blob that does not expire.
	ExpiresAt time.Time
}

// SweepResult reports one expiry sweep.
type SweepResult struct {
	// Removed counts blobs removed because they had expired.
	Removed int
	// Abandoned counts partial writes (the leftovers of a crashed Put) cleaned up.
	Abandoned int
}

// Store is the blob adapter interface. Implementations are safe for concurrent use.
type Store interface {
	// Put stores r under key for the tenant, replacing any blob already there, and returns what was
	// stored. A failed or cancelled Put leaves the previous blob, if any, untouched.
	Put(ctx context.Context, tenantID tenant.ID, key string, r io.Reader, opts PutOptions) (Info, error)
	// Get opens the blob. The caller closes the reader. ErrNotFound covers absent, deleted,
	// expired and other-tenant blobs.
	Get(ctx context.Context, tenantID tenant.ID, key string) (io.ReadCloser, Info, error)
	// Delete removes the blob. Deleting a blob that is not there succeeds, so a retried job is safe.
	Delete(ctx context.Context, tenantID tenant.ID, key string) error
	// Sweep removes every expired blob of every tenant. It is a platform operation, run by the
	// platform's scheduled sweep and never on behalf of a tenant request. A failure on one blob
	// does not stop the sweep: the result counts what was done and the error joins what failed.
	Sweep(ctx context.Context) (SweepResult, error)
}

const (
	// MaxKeyLength is the longest key, in bytes.
	MaxKeyLength = 512
	maxSegment   = 128
)

// ValidateKey reports whether key is a valid tenant-relative key. A key is one or more segments
// separated by "/". A segment is 1 to 128 bytes of [a-z A-Z 0-9 . _ -], is not "." or "..", and does
// not start with a dot. There is no leading, trailing or doubled "/", no backslash, no NUL and no
// non-ASCII byte, so a key can never carry a path-traversal sequence or a tenant prefix of its own
// into an adapter. The error wraps ErrInvalidKey and does not echo the key.
func ValidateKey(key string) error {
	if key == "" || len(key) > MaxKeyLength {
		return ErrInvalidKey
	}
	segLen := 0
	for i := 0; i <= len(key); i++ {
		if i == len(key) || key[i] == '/' {
			if segLen == 0 {
				return ErrInvalidKey // empty segment: leading, trailing or doubled "/"
			}
			segLen = 0
			continue
		}
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
		case c == '.':
			if segLen == 0 {
				return ErrInvalidKey // a segment never starts with a dot: no "." or ".."
			}
		default:
			return ErrInvalidKey
		}
		segLen++
		if segLen > maxSegment {
			return ErrInvalidKey
		}
	}
	return nil
}

func checkArgs(tenantID tenant.ID, key string) error {
	if tenantID.IsZero() {
		return ErrInvalidTenant
	}
	return ValidateKey(key)
}

// ErrCorrupt means a stored object's framing is unreadable. It is a fault of the storage, not of
// the caller's request, and is never returned for an absent or expired blob.
var ErrCorrupt = errors.New("blob: stored object is corrupt")
