package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func keys(t *testing.T) (seed, pub string) {
	t.Helper()
	p, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k.Seed()), base64.StdEncoding.EncodeToString(p)
}

func TestRoundTrip(t *testing.T) {
	seed, pub := keys(t)
	sig, err := Sign(seed, []byte("sbom"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, sig, []byte("sbom")); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsTamperingAndWrongKey(t *testing.T) {
	seed, pub := keys(t)
	_, otherPub := keys(t)
	sig, _ := Sign(seed, []byte("sbom"))
	if Verify(pub, sig, []byte("sbom!")) == nil {
		t.Fatal("tampered file accepted")
	}
	if Verify(otherPub, sig, []byte("sbom")) == nil {
		t.Fatal("wrong key accepted")
	}
	if Verify(pub, "AAAA", []byte("sbom")) == nil || Verify("x", sig, []byte("sbom")) == nil {
		t.Fatal("malformed input accepted")
	}
}

func TestSignFailsClosedAndNeverEchoesKey(t *testing.T) {
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		_, err := Sign(bad, []byte("x"))
		if err == nil {
			t.Fatalf("accepted key %q", bad)
		}
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Fatal("error echoes the key")
		}
	}
}
