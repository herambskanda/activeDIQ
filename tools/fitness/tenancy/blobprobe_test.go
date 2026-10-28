package main

import (
	"context"
	"io"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/blob"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// leaky wraps the real adapter and breaks tenant isolation in one chosen way, so each rule of the
// blob probe is proven to fail on a violation.
type leaky struct {
	blob.Store
	mode string
}

func (l leaky) Get(ctx context.Context, t tenant.ID, key string) (io.ReadCloser, blob.Info, error) {
	if l.mode == "read" {
		// Ignores the tenant: every tenant reads under one fixed tenant ID.
		return l.Store.Get(ctx, firstTenant, key)
	}
	if l.mode == "read-error" {
		if _, _, err := l.Store.Get(ctx, t, key); err != nil {
			return nil, blob.Info{}, io.ErrUnexpectedEOF // distinguishable from "never existed"
		}
	}
	return l.Store.Get(ctx, t, key)
}

func (l leaky) Put(ctx context.Context, t tenant.ID, key string, r io.Reader, o blob.PutOptions) (blob.Info, error) {
	if l.mode == "read" || l.mode == "write" || l.mode == "delete" {
		if firstTenant.IsZero() {
			firstTenant = t
		}
		return l.Store.Put(ctx, firstTenant, key, r, o) // one shared namespace
	}
	return l.Store.Put(ctx, t, key, r, o)
}

func (l leaky) Delete(ctx context.Context, t tenant.ID, key string) error {
	if l.mode == "delete" {
		return l.Store.Delete(ctx, firstTenant, key)
	}
	return l.Store.Delete(ctx, t, key)
}

var firstTenant tenant.ID

func TestBlobProbePassesRealAdapter(t *testing.T) {
	vs, err := checkBlob(context.Background(), nil)
	if err != nil || len(vs) > 0 {
		t.Fatalf("the real adapter must pass: err=%v\n%s", err, format(vs))
	}
}

func TestBlobProbeCatchesLeaks(t *testing.T) {
	for mode, rule := range map[string]string{
		"read":       "blob-read-cross-tenant",
		"read-error": "blob-read-cross-tenant",
		"write":      "blob-write-cross-tenant",
		"delete":     "blob-delete-cross-tenant",
		"prefix":     "blob-prefix",
	} {
		t.Run(mode, func(t *testing.T) {
			firstTenant = tenant.ID{}
			vs, err := checkBlob(context.Background(), func(dir string) (blob.Store, error) {
				fs, err := blob.NewFS(dir)
				if mode == "prefix" {
					return prefixless{fs}, err
				}
				return leaky{fs, mode}, err
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range vs {
				if v.Check == "T4" && v.Rule == rule {
					return
				}
			}
			t.Fatalf("mode %q must raise %s; got:\n%s", mode, rule, format(vs))
		})
	}
}

// prefixless stores everything under a fixed, non-tenant directory name.
type prefixless struct{ *blob.FS }

func (p prefixless) Put(ctx context.Context, _ tenant.ID, key string, r io.Reader, o blob.PutOptions) (blob.Info, error) {
	return p.FS.Put(ctx, tenant.New(), key, r, o) // a fresh random prefix per call: not the caller's tenant
}

