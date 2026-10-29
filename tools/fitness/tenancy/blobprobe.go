package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/skenzeriq/activediq/internal/platform/blob"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// BlobFactory opens the blob store under test on an empty directory. The default opens the real
// filesystem adapter; tests inject a deliberately leaky one to prove the probe fails.
type BlobFactory func(dir string) (blob.Store, error)

func defaultBlobFactory(dir string) (blob.Store, error) { return blob.NewFS(dir) }

// checkBlob is the blob isolation probe of T4 (TM-Q9, TM-TB4-T8): with two tenants and the same
// tenant-relative key, A's object is never readable, overwritable or deletable by B, B's lookup is
// indistinguishable from "never existed" (blob.ErrNotFound), and every object on disk lives under its
// own tenant's prefix, so listing the storage root as B finds nothing of A's. Rules: blob-read-cross-tenant,
// blob-write-cross-tenant, blob-delete-cross-tenant, blob-prefix.
func checkBlob(ctx context.Context, open BlobFactory) ([]Violation, error) {
	if open == nil {
		open = defaultBlobFactory
	}
	dir, err := os.MkdirTemp("", "diq-blobprobe-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	st, err := open(dir)
	if err != nil {
		return nil, fmt.Errorf("blob probe: open store: %w", err)
	}
	if c, ok := st.(io.Closer); ok {
		defer c.Close()
	}

	var vs []Violation
	add := func(rule, msg string) { vs = append(vs, Violation{"T4", rule, "internal/platform/blob", msg}) }
	a, b := tenant.New(), tenant.New()
	const key, shared = "reports/probe.csv", "reports/shared.csv"
	secretA, bodyB := []byte("tenant-A-secret"), []byte("tenant-B-body")

	if _, err := st.Put(ctx, a, key, bytes.NewReader(secretA), blob.PutOptions{}); err != nil {
		return nil, fmt.Errorf("blob probe: seed A: %w", err)
	}
	if _, err := st.Put(ctx, a, shared, bytes.NewReader(secretA), blob.PutOptions{}); err != nil {
		return nil, fmt.Errorf("blob probe: seed A: %w", err)
	}

	// Read: B asks for A's key.
	rc, _, err := st.Get(ctx, b, key)
	switch {
	case err == nil:
		got, _ := io.ReadAll(rc)
		rc.Close()
		add("blob-read-cross-tenant", fmt.Sprintf("tenant B read tenant A's object (%d bytes)", len(got)))
	case !errors.Is(err, blob.ErrNotFound):
		add("blob-read-cross-tenant", "tenant B's read of A's key does not return blob.ErrNotFound (the answer must equal \"never existed\")")
	}

	// Write: B stores the same key; A's object must be unchanged.
	if _, err := st.Put(ctx, b, shared, bytes.NewReader(bodyB), blob.PutOptions{}); err != nil {
		return nil, fmt.Errorf("blob probe: seed B: %w", err)
	}
	if got, ok := readAll(ctx, st, a, shared); !ok || !bytes.Equal(got, secretA) {
		add("blob-write-cross-tenant", "tenant B's write to the same key changed or removed tenant A's object")
	}
	if got, ok := readAll(ctx, st, b, shared); !ok || !bytes.Equal(got, bodyB) {
		add("blob-write-cross-tenant", "tenant B does not read back its own object under a key tenant A also uses")
	}

	// Delete: B deletes A's key; A's object must survive.
	_ = st.Delete(ctx, b, key)
	if got, ok := readAll(ctx, st, a, key); !ok || !bytes.Equal(got, secretA) {
		add("blob-delete-cross-tenant", "tenant B's delete removed tenant A's object")
	}

	// Prefix / list: walk the storage root. Every object sits under a tenant-ID directory of a tenant
	// that stored it; nothing the tenants stored is outside such a prefix (listing as B shows only B).
	allowed := map[string]bool{a.String(): true, b.String(): true}
	seen := map[string]int{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		first, _, _ := strings.Cut(filepath.ToSlash(rel), "/")
		if first == ".tmp" {
			return nil
		}
		if !allowed[first] {
			add("blob-prefix", "an object is stored outside any tenant prefix (path "+filepath.ToSlash(rel)+")")
			return nil
		}
		seen[first]++
		return nil
	})
	if seen[a.String()] != 2 || seen[b.String()] != 1 {
		add("blob-prefix", fmt.Sprintf("objects per tenant prefix are A=%d (want 2), B=%d (want 1): keys are not tenant-prefixed", seen[a.String()], seen[b.String()]))
	}
	return vs, nil
}

func readAll(ctx context.Context, st blob.Store, t tenant.ID, key string) ([]byte, bool) {
	rc, _, err := st.Get(ctx, t, key)
	if err != nil {
		return nil, false
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	return b, err == nil
}
