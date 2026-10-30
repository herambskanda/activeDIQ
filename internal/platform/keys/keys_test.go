package keys_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/keys/keystest"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

var plain = []byte("entra-private-key-pem")

func base(t *testing.T) (keys.DEK, keys.Context) {
	t.Helper()
	d, err := keys.NewDEK(3)
	if err != nil {
		t.Fatal(err)
	}
	return d, keys.Context{Tenant: tenant.New(), Table: "public.directory_credential", Row: "row-1", Column: "sealed_key", Version: 3}
}

func TestSealOpenRoundTrip(t *testing.T) {
	d, c := base(t)
	blob, err := keys.Seal(d, c, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, plain) {
		t.Fatal("plaintext visible in blob")
	}
	if v, err := keys.BlobVersion(blob); err != nil || v != 3 {
		t.Fatalf("BlobVersion = %d, %v", v, err)
	}
	got, err := keys.Open(d, c, blob)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	b2, _ := keys.Seal(d, c, plain)
	if bytes.Equal(blob, b2) {
		t.Fatal("nonce reused: identical blobs")
	}
}

// AC1: any different component fails with a typed error and returns no plaintext.
func TestOpenFailsOnAnyDifferentComponent(t *testing.T) {
	d, c := base(t)
	blob, _ := keys.Seal(d, c, plain)
	other, _ := keys.NewDEK(3)
	d4, _ := keys.NewDEK(4)
	cases := map[string]struct {
		dek  keys.DEK
		ctx  keys.Context
		want string
	}{
		"tenant":           {d, withCtx(c, func(x *keys.Context) { x.Tenant = tenant.New() }), keys.OpenFailed},
		"table":            {d, withCtx(c, func(x *keys.Context) { x.Table = "public.other" }), keys.OpenFailed},
		"row":              {d, withCtx(c, func(x *keys.Context) { x.Row = "row-2" }), keys.OpenFailed},
		"column":           {d, withCtx(c, func(x *keys.Context) { x.Column = "other_col" }), keys.OpenFailed},
		"version":          {d4, withCtx(c, func(x *keys.Context) { x.Version = 4 }), keys.KeyVersionMismatch},
		"version-ctx-only": {d, withCtx(c, func(x *keys.Context) { x.Version = 4 }), keys.KeyVersionMismatch},
		"wrong-key":        {other, c, keys.OpenFailed},
		// boundary shifting between adjacent components must not collide
		"shifted": {d, withCtx(c, func(x *keys.Context) { x.Table, x.Row = c.Table+"r", "ow-1" }), keys.OpenFailed},
	}
	for name, tc := range cases {
		pt, err := keys.Open(tc.dek, tc.ctx, blob)
		if pt != nil || keys.Code(err) != tc.want {
			t.Errorf("%s: pt=%v code=%q want %q", name, pt, keys.Code(err), tc.want)
		}
	}
}

func TestOpenRejectsTamperingAndRewrittenHeader(t *testing.T) {
	d, c := base(t)
	blob, _ := keys.Seal(d, c, plain)
	for i := range blob {
		m := append([]byte(nil), blob...)
		m[i] ^= 1
		pt, err := keys.Open(d, c, m)
		if pt != nil || err == nil {
			t.Fatalf("byte %d flip opened", i)
		}
		var e *keys.Error
		if !errors.As(err, &e) {
			t.Fatalf("byte %d: untyped error %v", i, err)
		}
	}
	for _, short := range [][]byte{nil, {1}, blob[:20]} {
		if pt, err := keys.Open(d, c, short); pt != nil || keys.Code(err) != keys.MalformedBlob {
			t.Errorf("short blob: %v %v", pt, err)
		}
	}
}

func TestInvalidContextRefused(t *testing.T) {
	d, c := base(t)
	for name, bad := range map[string]keys.Context{
		"zero tenant": withCtx(c, func(x *keys.Context) { x.Tenant = tenant.ID{} }),
		"no table":    withCtx(c, func(x *keys.Context) { x.Table = "" }),
		"no row":      withCtx(c, func(x *keys.Context) { x.Row = "" }),
		"no column":   withCtx(c, func(x *keys.Context) { x.Column = "" }),
		"no version":  withCtx(c, func(x *keys.Context) { x.Version = 0 }),
	} {
		if b, err := keys.Seal(d, bad, plain); b != nil || keys.Code(err) != keys.InvalidContext {
			t.Errorf("%s: Seal %v %v", name, b, err)
		}
	}
	var zero keys.DEK
	if _, err := keys.Seal(zero, c, plain); err == nil {
		t.Error("zero DEK sealed")
	}
}

func TestDestroyedDEKCannotSeal(t *testing.T) {
	d, c := base(t)
	d.Destroy()
	if _, err := keys.Seal(d, c, plain); err == nil {
		t.Error("destroyed DEK still seals")
	}
}

// AC2: a DEK wrapped under tenant A's context fails to unwrap under tenant B's (fake KMS and local).
func TestUnwrapUnderOtherTenantFails(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i)
	}
	local, err := keys.NewLocalProvider("k1", secret.FromBytes(kek))
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]keys.Provider{"fakekms": keystest.New("key-1"), "local": local} {
		t.Run(name, func(t *testing.T) {
			a, b := tenant.New(), tenant.New()
			d, _ := keys.NewDEK(2)
			c := keys.Context{Tenant: a, Table: "t", Row: "r", Column: "c", Version: 2}
			blob, _ := keys.Seal(d, c, plain)
			w, ref, err := keys.WrapDEK(p, a, d)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := keys.UnwrapDEK(p, b, 2, ref, w); keys.Code(err) != keys.UnwrapFailed || got.Version != 0 {
				t.Fatalf("tenant B unwrapped: %v %v", got, err)
			}
			if _, err := keys.UnwrapDEK(p, a, 3, ref, w); keys.Code(err) != keys.UnwrapFailed {
				t.Fatalf("other version unwrapped: %v", err)
			}
			got, err := keys.UnwrapDEK(p, a, 2, ref, w)
			if err != nil {
				t.Fatal(err)
			}
			pt, err := keys.Open(got, c, blob)
			if err != nil || !bytes.Equal(pt, plain) {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
}

func TestLocalProviderTamperAndForeignKEK(t *testing.T) {
	mk := func(b byte, id string) *keys.LocalProvider {
		k := bytes.Repeat([]byte{b}, 32)
		p, err := keys.NewLocalProvider(id, secret.FromBytes(k))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p, other := mk(1, "k1"), mk(2, "k1")
	ten := tenant.New()
	d, _ := keys.NewDEK(1)
	w, ref, _ := keys.WrapDEK(p, ten, d)
	if _, err := keys.UnwrapDEK(other, ten, 1, ref, w); keys.Code(err) != keys.UnwrapFailed {
		t.Errorf("foreign KEK: %v", err)
	}
	if _, err := keys.UnwrapDEK(p, ten, 1, keys.KEKRef{Provider: "local", KeyID: "k2"}, w); keys.Code(err) != keys.UnwrapFailed {
		t.Errorf("unpinned kek_ref: %v", err)
	}
	w[len(w)-1] ^= 1
	if _, err := keys.UnwrapDEK(p, ten, 1, ref, w); keys.Code(err) != keys.UnwrapFailed {
		t.Errorf("tampered wrap: %v", err)
	}
	if _, err := keys.NewLocalProvider("k", secret.FromBytes([]byte("short"))); keys.Code(err) != keys.InvalidKey {
		t.Errorf("short kek: %v", err)
	}
}

func TestProviderOutageFailsClosed(t *testing.T) {
	kms := keystest.New("key-1")
	ten := tenant.New()
	d, _ := keys.NewDEK(1)
	w, ref, err := keys.WrapDEK(kms, ten, d)
	if err != nil {
		t.Fatal(err)
	}
	kms.SetDown(true)
	if got, err := keys.UnwrapDEK(kms, ten, 1, ref, w); keys.Code(err) != keys.ProviderUnavailable || got.Version != 0 {
		t.Fatalf("outage unwrap: %v %v", got, err)
	}
	if _, _, err := keys.WrapDEK(kms, ten, d); keys.Code(err) != keys.ProviderUnavailable {
		t.Fatalf("outage wrap: %v", err)
	}
}

func TestKEKRotationKeepsOldWrapsReadable(t *testing.T) {
	kms := keystest.New("key-1")
	ten := tenant.New()
	d, _ := keys.NewDEK(1)
	w, ref, _ := keys.WrapDEK(kms, ten, d)
	kms.Rotate("key-2")
	if _, err := keys.UnwrapDEK(kms, ten, 1, ref, w); err != nil {
		t.Fatalf("old wrap after rotation: %v", err)
	}
	if _, ref2, _ := keys.WrapDEK(kms, ten, d); ref2.KeyID != "key-2" {
		t.Fatalf("new wrap uses %q", ref2.KeyID)
	}
	if kms.Unwraps != 1 {
		t.Fatalf("Unwraps = %d", kms.Unwraps)
	}
}

func withCtx(c keys.Context, f func(*keys.Context)) keys.Context { f(&c); return c }

func TestDEKFromBytesZeroesArgument(t *testing.T) {
	ok := bytes.Repeat([]byte{7}, keys.DEKSize)
	if _, err := keys.DEKFromBytes(1, ok); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ok, make([]byte, keys.DEKSize)) {
		t.Fatal("argument not zeroed on success")
	}
	short := bytes.Repeat([]byte{7}, keys.DEKSize-1)
	if _, err := keys.DEKFromBytes(1, short); err == nil {
		t.Fatal("expected error")
	}
	if !bytes.Equal(short, make([]byte, keys.DEKSize-1)) {
		t.Fatal("argument not zeroed on wrong length")
	}
	v0 := bytes.Repeat([]byte{7}, keys.DEKSize)
	if _, err := keys.DEKFromBytes(0, v0); err == nil {
		t.Fatal("expected error")
	}
	if !bytes.Equal(v0, make([]byte, keys.DEKSize)) {
		t.Fatal("argument not zeroed on version 0")
	}
}

func TestPlatformAndTenantWrapsAreDomainSeparated(t *testing.T) {
	kek := secret.FromBytes(bytes.Repeat([]byte{7}, 32))
	p, err := keys.NewLocalProvider("k", kek)
	if err != nil {
		t.Fatal(err)
	}
	w, ref, err := keys.WrapPlatform(p, "api-tls", 1, []byte("platform secret"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := keys.UnwrapPlatform(p, "api-tls", 1, ref, w); err != nil || string(got) != "platform secret" {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := keys.UnwrapPlatform(p, "other", 1, ref, w); err == nil {
		t.Fatal("unwrapped under another purpose")
	}
	// A platform blob is not a tenant DEK, for any tenant.
	tn := tenant.New()
	if _, err := p.Unwrap(keys.WrapRequest{Tenant: tn, Version: 1}, ref, w); err == nil {
		t.Fatal("platform blob unwrapped as tenant DEK")
	}
	// And the reverse: a tenant blob does not unwrap as a platform secret.
	tw, tref, err := p.Wrap(keys.WrapRequest{Tenant: tn, Version: 1}, []byte("tenant"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.UnwrapPlatform(p, "api-tls", 1, tref, tw); err == nil {
		t.Fatal("tenant blob unwrapped as platform secret")
	}
	// Both or neither is invalid.
	for _, r := range []keys.WrapRequest{{Tenant: tn, Purpose: "x", Version: 1}, {Version: 1}} {
		if _, _, err := p.Wrap(r, []byte("x")); keys.Code(err) != keys.InvalidContext {
			t.Fatalf("%+v: want InvalidContext, got %v", r, err)
		}
	}
}
