// Command sign signs and verifies release files with a detached Ed25519 signature (T-0261).
//
//	sign   -sig f.sig f        key: base64 32-byte seed in $RELEASE_SIGNING_KEY (never a file, never a flag)
//	verify -pub key.pub -sig f.sig f
//	keygen                     prints "seed <b64>" and "public <b64>"; the seed goes straight into the secret store
//
// Interim signer: the production key custody (offline root, HSM/KMS, TUF metadata) is T-0140/T-0141 and
// replaces the key source, not the file layout. The tool fails closed: no key, a malformed key or a
// signature that does not verify is a non-zero exit, never a skip. Standard library only.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

const keyEnv = "RELEASE_SIGNING_KEY"

// Sign returns the base64 detached signature of msg.
func Sign(seedB64 string, msg []byte) (string, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedB64))
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", errors.New("signing key is not a base64 32-byte Ed25519 seed") // never echo the value
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg)), nil
}

// Verify checks a base64 detached signature against a base64 public key.
func Verify(pubB64, sigB64 string, msg []byte) error {
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("public key is not base64 of 32 bytes")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("signature is not base64 of 64 bytes")
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("signature does not match the file and public key")
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sign:", err)
	os.Exit(1)
}

func opts(args []string) (map[string]string, string) {
	m := map[string]string{}
	var file string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-sig", "-pub":
			if i+1 >= len(args) {
				fail(fmt.Errorf("%s needs a value", args[i]))
			}
			m[args[i]] = args[i+1]
			i++
		default:
			file = args[i]
		}
	}
	return m, file
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: sign|verify|keygen"))
	}
	switch os.Args[1] {
	case "keygen":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fail(err)
		}
		fmt.Println("seed", base64.StdEncoding.EncodeToString(priv.Seed()))
		fmt.Println("public", base64.StdEncoding.EncodeToString(pub))
	case "sign":
		o, file := opts(os.Args[2:])
		if file == "" || o["-sig"] == "" {
			fail(errors.New("usage: sign -sig out.sig file"))
		}
		msg, err := os.ReadFile(file)
		if err != nil {
			fail(err)
		}
		sig, err := Sign(os.Getenv(keyEnv), msg)
		if err != nil {
			fail(fmt.Errorf("%v (set %s)", err, keyEnv))
		}
		if err := os.WriteFile(o["-sig"], []byte(sig+"\n"), 0o644); err != nil {
			fail(err)
		}
		fmt.Println("sign: wrote", o["-sig"])
	case "verify":
		o, file := opts(os.Args[2:])
		if file == "" || o["-sig"] == "" || o["-pub"] == "" {
			fail(errors.New("usage: verify -pub key.pub -sig f.sig file"))
		}
		msg, err1 := os.ReadFile(file)
		sig, err2 := os.ReadFile(o["-sig"])
		pub, err3 := os.ReadFile(o["-pub"])
		if err := errors.Join(err1, err2, err3); err != nil {
			fail(err)
		}
		if err := Verify(string(pub), string(sig), msg); err != nil {
			fail(err)
		}
		fmt.Println("sign: verified", file)
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}
