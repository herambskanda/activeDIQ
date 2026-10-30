package keys_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/keys"
	"github.com/skenzeriq/activediq/internal/platform/secret"
)

func pass(s string) secret.Secret { return secret.FromBytes([]byte(s)) }

func TestKeystoreRoundTrip(t *testing.T) {
	file, id, err := keys.CreateKeystore(pass("correct horse battery"), keys.FloorKDF)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]any
	if err := json.Unmarshal(file, &shape); err != nil {
		t.Fatal(err)
	}
	kdf, _ := shape["kdf"].(map[string]any)
	if shape["format"] != float64(1) || kdf["alg"] != "argon2id" || kdf["salt"] == nil || kdf["m"] == nil ||
		kdf["t"] == nil || kdf["p"] == nil || shape["key_id"] != id || shape["sealed_kek"] == nil || len(shape) != 4 {
		t.Fatalf("unexpected shape: %s", file)
	}
	if bytes.Contains(file, []byte("correct horse")) {
		t.Fatal("passphrase in keystore")
	}
	p, err := keys.OpenKeystore(file, pass("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Ref().KeyID != id {
		t.Fatalf("key id %q, want %q", p.Ref().KeyID, id)
	}
	// The unlocked provider is the same KEK every time: what one wraps, a second unlock opens.
	wrapped, ref, err := keys.WrapPlatform(p, "kek-selftest", 1, []byte("canary"))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := keys.OpenKeystore(file, pass("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := keys.UnwrapPlatform(p2, "kek-selftest", 1, ref, wrapped); err != nil || string(got) != "canary" {
		t.Fatalf("unwrap = %q, %v", got, err)
	}
}

func TestKeystoreFailuresAreOneCode(t *testing.T) {
	file, _, err := keys.CreateKeystore(pass("correct horse battery"), keys.FloorKDF)
	if err != nil {
		t.Fatal(err)
	}
	edit := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(file, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	kdf := func(m map[string]any) map[string]any { return m["kdf"].(map[string]any) }
	cases := map[string]struct {
		file []byte
		pass string
	}{
		"wrong passphrase": {file, "wrong passphrase!"},
		"empty passphrase": {file, ""},
		"empty file":       {nil, "correct horse battery"},
		"garbage":          {[]byte("not json"), "correct horse battery"},
		"trailing data":    {append(bytes.Clone(file), []byte("{}")...), "correct horse battery"},
		"unknown field":    {edit(func(m map[string]any) { m["extra"] = 1 }), "correct horse battery"},
		"format 2":         {edit(func(m map[string]any) { m["format"] = 2 }), "correct horse battery"},
		"key_id edited":    {edit(func(m map[string]any) { m["key_id"] = "other" }), "correct horse battery"},
		"t edited":         {edit(func(m map[string]any) { kdf(m)["t"] = 3 }), "correct horse battery"},
		"m below floor":    {edit(func(m map[string]any) { kdf(m)["m"] = 8 }), "correct horse battery"},
		"m above ceiling":  {edit(func(m map[string]any) { kdf(m)["m"] = 1 << 22 }), "correct horse battery"},
		"alg argon2i":      {edit(func(m map[string]any) { kdf(m)["alg"] = "argon2i" }), "correct horse battery"},
		"short sealed":     {edit(func(m map[string]any) { m["sealed_kek"] = "AAAA" }), "correct horse battery"},
		"oversize":         {bytes.Repeat([]byte(" "), keys.MaxKeystoreBytes+1), "correct horse battery"},
	}
	for name, c := range cases {
		p, err := keys.OpenKeystore(c.file, pass(c.pass))
		if p != nil || keys.Code(err) != keys.UnwrapFailed || err.Error() != "keys: UnwrapFailed" {
			t.Errorf("%s: got (%v, %v), want UnwrapFailed only", name, p, err)
		}
	}
}

func TestKeystoreSealedKEKFlippedByteFails(t *testing.T) {
	file, _, _ := keys.CreateKeystore(pass("correct horse battery"), keys.FloorKDF)
	var m struct {
		SealedKEK []byte `json:"sealed_kek"`
	}
	_ = json.Unmarshal(file, &m)
	flipped := strings.Replace(string(file), "\"sealed_kek\": \"", "\"sealed_kek\": \"A", 1)
	if _, err := keys.OpenKeystore([]byte(flipped), pass("correct horse battery")); keys.Code(err) != keys.UnwrapFailed {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateKeystoreRefusesWeakInput(t *testing.T) {
	if _, _, err := keys.CreateKeystore(secret.Secret{}, keys.FloorKDF); keys.Code(err) != keys.InvalidKey {
		t.Fatalf("empty passphrase: %v", err)
	}
	if _, _, err := keys.CreateKeystore(pass("x"), keys.KDFParams{M: 1024, T: 1, P: 1}); keys.Code(err) != keys.InvalidKey {
		t.Fatalf("weak kdf: %v", err)
	}
	a, ida, _ := keys.CreateKeystore(pass("same passphrase"), keys.FloorKDF)
	b, idb, _ := keys.CreateKeystore(pass("same passphrase"), keys.FloorKDF)
	if ida == idb || bytes.Equal(a, b) {
		t.Fatal("two keystores must differ (fresh KEK, salt and id)")
	}
}
