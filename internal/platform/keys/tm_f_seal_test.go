package keys_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// TM-F-SEAL (threat-model §9.2, §15): a sealed value must not open after being moved to another
// tenant, row or column, and a DEK must not unwrap under another tenant's context. Covers
// TM-TB4-T6/T7, TM-TB5-T2, TM-TB7-T1. The attacker model is X6 with database write access: the
// stored blob is copied to where the attacker wants it, and the reader then opens it exactly as the
// product would — with the DEK of the tenant whose row it now sits in, and that row's Context.

// sealedStore models two tenants' rows of one table: the thing X6 can rewrite.
type sealedStore struct {
	t          *testing.T
	kms        *keystest.KMS
	deks       map[tenant.ID]keys.DEK
	wrapped    map[tenant.ID][]byte
	ref        map[tenant.ID]keys.KEKRef
	aTen, bTen tenant.ID
}

const (
	sTable  = "public.directory_credential"
	sColumn = "sealed_key"
	sRowA   = "6f1f5b3e-0000-4000-8000-00000000000a"
	sRowA2  = "6f1f5b3e-0000-4000-8000-00000000000b"
	sRowB   = "6f1f5b3e-0000-4000-8000-0000000000b1"
	version = 2
)

func newSealedStore(t *testing.T) *sealedStore {
	s := &sealedStore{t: t, kms: keystest.New("key-1"), deks: map[tenant.ID]keys.DEK{},
		wrapped: map[tenant.ID][]byte{}, ref: map[tenant.ID]keys.KEKRef{}, aTen: tenant.New(), bTen: tenant.New()}
	for _, ten := range []tenant.ID{s.aTen, s.bTen} {
		d, err := keys.NewDEK(version)
		if err != nil {
			t.Fatal(err)
		}
		w, ref, err := keys.WrapDEK(s.kms, ten, d)
		if err != nil {
			t.Fatal(err)
		}
		s.deks[ten], s.wrapped[ten], s.ref[ten] = d, w, ref
	}
	return s
}

func (s *sealedStore) ctx(ten tenant.ID, row, col string) keys.Context {
	return keys.Context{Tenant: ten, Table: sTable, Row: row, Column: col, Version: version}
}

// open is the product read path: unwrap the tenant's DEK through the KMS, then Open in that tenant's context.
func (s *sealedStore) open(ten tenant.ID, c keys.Context, blob []byte) ([]byte, error) {
	d, err := keys.UnwrapDEK(s.kms, ten, version, s.ref[ten], s.wrapped[ten])
	if err != nil {
		return nil, err
	}
	defer d.Destroy()
	return keys.Open(d, c, blob)
}

func wantOpenFailed(t *testing.T, name string, pt []byte, err error) {
	t.Helper()
	var e *keys.Error
	if pt != nil || !errors.As(err, &e) || e.Code != keys.OpenFailed {
		t.Errorf("%s: pt=%v err=%v; want nil plaintext and typed %s", name, pt, err, keys.OpenFailed)
	}
}

func TestTMFSealSealedValueBoundToTenantRowColumn(t *testing.T) {
	s := newSealedStore(t)
	secretPEM := []byte("-----BEGIN PRIVATE KEY----- tenant A entra key")
	home := s.ctx(s.aTen, sRowA, sColumn)
	blob, err := keys.Seal(s.deks[s.aTen], home, secretPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.open(s.aTen, home, blob); err != nil || !bytes.Equal(got, secretPEM) {
		t.Fatalf("control: home open = %q, %v", got, err)
	}

	// Copy to tenant B's row; B's reader opens with B's DEK and B's row context.
	pt, err := s.open(s.bTen, s.ctx(s.bTen, sRowB, sColumn), blob)
	wantOpenFailed(t, "copied to tenant B row (B's DEK)", pt, err)
	// Same copy, but the reader mistakenly holds A's DEK: the context alone must refuse it.
	pt, err = keys.Open(s.deks[s.aTen], s.ctx(s.bTen, sRowA, sColumn), blob)
	wantOpenFailed(t, "tenant B context, same row id, A's DEK", pt, err)
	// Another row of the same tenant.
	pt, err = s.open(s.aTen, s.ctx(s.aTen, sRowA2, sColumn), blob)
	wantOpenFailed(t, "another row, same tenant", pt, err)
	// Another column of the same row.
	pt, err = s.open(s.aTen, s.ctx(s.aTen, sRowA, "sealed_fallback_password"), blob)
	wantOpenFailed(t, "another column, same row", pt, err)
	// Another table.
	c := home
	c.Table = "public.mfa_seed"
	pt, err = s.open(s.aTen, c, blob)
	wantOpenFailed(t, "another table", pt, err)
}

func TestTMFSealWrongVersionAndOneByteTamper(t *testing.T) {
	s := newSealedStore(t)
	home := s.ctx(s.aTen, sRowA, sColumn)
	blob, _ := keys.Seal(s.deks[s.aTen], home, []byte("v"))

	// Wrong key version: a retired/other-version DEK or a context claiming another version.
	d3, _ := keys.NewDEK(version + 1)
	for name, tc := range map[string]struct {
		dek keys.DEK
		ctx keys.Context
	}{
		"DEK of another version":      {d3, func() keys.Context { c := home; c.Version = version + 1; return c }()},
		"context claims version only": {s.deks[s.aTen], func() keys.Context { c := home; c.Version = version + 1; return c }()},
		"version-bound DEK, old ctx":  {d3, home},
	} {
		pt, err := keys.Open(tc.dek, tc.ctx, blob)
		if pt != nil || keys.Code(err) != keys.KeyVersionMismatch {
			t.Errorf("%s: pt=%v code=%q", name, pt, keys.Code(err))
		}
	}

	// One flipped bit anywhere in the blob (header, nonce, ciphertext, tag) never opens.
	for i := range blob {
		m := append([]byte(nil), blob...)
		m[i] ^= 0x01
		pt, err := keys.Open(s.deks[s.aTen], home, m)
		if pt != nil || err == nil || keys.Code(err) == "" {
			t.Fatalf("flip at byte %d: pt=%v err=%v", i, pt, err)
		}
	}
	// Truncation and extension never open either.
	for name, m := range map[string][]byte{"truncated": blob[:len(blob)-1], "extended": append(append([]byte(nil), blob...), 0)} {
		if pt, err := keys.Open(s.deks[s.aTen], home, m); pt != nil || keys.Code(err) == "" {
			t.Errorf("%s: pt=%v err=%v", name, pt, err)
		}
	}
}

func TestTMFSealDEKBoundToTenantContext(t *testing.T) {
	s := newSealedStore(t)

	// Tenant A's wrapped DEK (and its kek_ref) presented as tenant B's.
	got, err := keys.UnwrapDEK(s.kms, s.bTen, version, s.ref[s.aTen], s.wrapped[s.aTen])
	if keys.Code(err) != keys.UnwrapFailed || got.Version != 0 {
		t.Fatalf("A's DEK unwrapped under B's context: version=%d err=%v", got.Version, err)
	}
	// Wrong version context for the right tenant.
	if _, err := keys.UnwrapDEK(s.kms, s.aTen, version+1, s.ref[s.aTen], s.wrapped[s.aTen]); keys.Code(err) != keys.UnwrapFailed {
		t.Fatalf("A's DEK unwrapped as another version: %v", err)
	}
	// Substituted KEK reference (TM-TB5-T2: kek_ref pinned per DEK version).
	if _, err := keys.UnwrapDEK(s.kms, s.aTen, version, keys.KEKRef{Provider: "fakekms", KeyID: "attacker-key"}, s.wrapped[s.aTen]); keys.Code(err) != keys.UnwrapFailed {
		t.Fatalf("substituted kek_ref unwrapped: %v", err)
	}
	// Tampered / unknown wrapped bytes.
	bad := append([]byte(nil), s.wrapped[s.aTen]...)
	bad[0] ^= 1
	if _, err := keys.UnwrapDEK(s.kms, s.aTen, version, s.ref[s.aTen], bad); keys.Code(err) != keys.UnwrapFailed {
		t.Fatalf("tampered wrap unwrapped: %v", err)
	}
	if s.kms.Unwraps != 0 {
		t.Fatalf("KMS performed %d successful decrypts for failed attempts", s.kms.Unwraps)
	}

	// End to end: a swapped wrapped-DEK column. X6 writes A's wrapped DEK into B's slot; B's values
	// (sealed under B's DEK) become unreadable rather than being opened with A's key.
	bHome := s.ctx(s.bTen, sRowB, sColumn)
	bBlob, _ := keys.Seal(s.deks[s.bTen], bHome, []byte("tenant B secret"))
	s.wrapped[s.bTen], s.ref[s.bTen] = s.wrapped[s.aTen], s.ref[s.aTen]
	if pt, err := s.open(s.bTen, bHome, bBlob); pt != nil || err == nil {
		t.Fatalf("B's value opened via swapped wrapped DEK: %v %v", pt, err)
	}
}

// Installation scope (T-0715, ADR-0008): a value sealed under the installation DEK is bound to its table,
// row, column and version, never opens through the tenant API or under a tenant DEK, and the installation
// DEK's wrap never unwraps as a tenant's (nor a tenant's as it).
func TestTMFSealInstallationScope(t *testing.T) {
	s := newSealedStore(t)
	inst, err := keys.NewDEK(version)
	if err != nil {
		t.Fatal(err)
	}
	home := keys.InstallationContext{Table: "public.fleet_server_ca", Row: sRowA, Column: sColumn, Version: version}
	blob, err := keys.SealInstallation(inst, home, []byte("server ca key"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := keys.OpenInstallation(inst, home, blob); err != nil || string(got) != "server ca key" {
		t.Fatalf("control: %q %v", got, err)
	}
	for name, c := range map[string]keys.InstallationContext{
		"another table":  {Table: sTable, Row: sRowA, Column: sColumn, Version: version},
		"another row":    {Table: home.Table, Row: sRowA2, Column: sColumn, Version: version},
		"another column": {Table: home.Table, Row: sRowA, Column: "other", Version: version},
	} {
		pt, err := keys.OpenInstallation(inst, c, blob)
		wantOpenFailed(t, name, pt, err)
	}
	// A tenant DEK (same key bytes are irrelevant: a different key) and the tenant API both refuse it.
	pt, err := keys.OpenInstallation(s.deks[s.aTen], home, blob)
	wantOpenFailed(t, "tenant DEK", pt, err)
	tctx := keys.Context{Tenant: s.aTen, Table: home.Table, Row: sRowA, Column: sColumn, Version: version}
	pt, err = keys.Open(inst, tctx, blob)
	wantOpenFailed(t, "tenant context, installation DEK", pt, err)
	// And the reverse: a tenant-sealed blob does not open as an installation value.
	tb, _ := keys.Seal(inst, tctx, []byte("x"))
	pt, err = keys.OpenInstallation(inst, home, tb)
	wantOpenFailed(t, "tenant blob as installation value", pt, err)
	// Other version / one flipped bit.
	if pt, err := keys.OpenInstallation(inst, keys.InstallationContext{Table: home.Table, Row: sRowA, Column: sColumn, Version: version + 1}, blob); pt != nil || keys.Code(err) != keys.KeyVersionMismatch {
		t.Errorf("other version: %v %v", pt, err)
	}
	for i := range blob {
		m := append([]byte(nil), blob...)
		m[i] ^= 1
		if pt, err := keys.OpenInstallation(inst, home, m); pt != nil || keys.Code(err) == "" {
			t.Fatalf("flip at %d opened", i)
		}
	}

	// Wrap domains: installation wrap <-> tenant wrap.
	raw := make([]byte, keys.DEKSize)
	wrapped, ref, err := keys.WrapPlatform(s.kms, keys.InstallationPurpose, version, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.UnwrapDEK(s.kms, s.aTen, version, ref, wrapped); keys.Code(err) != keys.UnwrapFailed {
		t.Fatalf("installation wrap unwrapped as tenant DEK: %v", err)
	}
	if _, err := keys.UnwrapPlatform(s.kms, keys.InstallationPurpose, version, s.ref[s.aTen], s.wrapped[s.aTen]); keys.Code(err) != keys.UnwrapFailed {
		t.Fatalf("tenant wrap unwrapped as installation DEK: %v", err)
	}
	if _, err := keys.UnwrapPlatform(s.kms, "api-tls", version, ref, wrapped); keys.Code(err) != keys.UnwrapFailed {
		t.Fatalf("installation wrap unwrapped under another purpose: %v", err)
	}
}
