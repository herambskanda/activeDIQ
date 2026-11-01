package authn

import (
	"bytes"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

func TestNormaliseUsername(t *testing.T) {
	for name, c := range map[string]struct {
		in, want string
		ok       bool
	}{
		"case folded":            {"Break.Glass", "break.glass", true},
		"trimmed":                {"  admin \t", "admin", true},
		"NFC composed":           {"Café", "café", true},
		"empty":                  {"", "", false},
		"blank":                  {"   ", "", false},
		"too long":               {strings.Repeat("a", 129), "", false},
		"invalid utf8":           {"a\xffb", "", false},
		"sharp s folds":          {"STRASSE", "strasse", true},
		"max length is accepted": {strings.Repeat("a", 128), strings.Repeat("a", 128), true},
	} {
		got, ok := NormaliseUsername(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: NormaliseUsername(%q) = %q, %v; want %q, %v", name, c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestPasswordHashRoundTrip(t *testing.T) {
	h, err := hashPassword([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=") {
		t.Fatalf("not a PHC argon2id string: %q", h)
	}
	if !verifyHash(h, []byte("correct horse battery staple")) {
		t.Error("the right password did not verify")
	}
	if verifyHash(h, []byte("correct horse battery stapl")) || verifyHash(h, nil) {
		t.Error("a wrong or empty password verified")
	}
	h2, _ := hashPassword([]byte("correct horse battery staple"))
	if h == h2 {
		t.Error("two hashes of one password share a salt")
	}
	for _, bad := range []string{"", "x", "$argon2id$v=19$m=1,t=0,p=1$AA$AA", "$argon2i$v=19$m=64,t=1,p=1$AA$AA", "$argon2id$v=19$m=99999999,t=1,p=1$AA$AA", "$argon2id$v=19$m=64,t=1,p=1$!!$AA"} {
		if verifyHash(bad, []byte("x")) {
			t.Errorf("malformed hash %q verified", bad)
		}
	}
}

func TestDummyHashIsWellFormedAndNeverMatches(t *testing.T) {
	d := dummy()
	if verifyHash(d, []byte("")) || verifyHash(d, []byte("password")) {
		t.Error("the dummy hash matched")
	}
	if d != dummy() {
		t.Error("the dummy hash changes between calls: its cost would not be a constant")
	}
}

func TestThrottleKeyIsKeyedAndTenantScoped(t *testing.T) {
	a, b := tenant.New(), tenant.New()
	p1, p2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	if bytes.Equal(throttleKey(p1, a, "x"), throttleKey(p2, a, "x")) {
		t.Error("the key does not depend on the pepper")
	}
	if bytes.Equal(throttleKey(p1, a, "x"), throttleKey(p1, b, "x")) {
		t.Error("the key does not depend on the tenant")
	}
	if bytes.Equal(throttleKey(p1, a, "ab"), throttleKey(p1, a, "a")) {
		t.Error("distinct names share a key")
	}
	if !bytes.Equal(throttleKey(p1, a, "x"), throttleKey(p1, a, "x")) {
		t.Error("the key is not deterministic")
	}
}
