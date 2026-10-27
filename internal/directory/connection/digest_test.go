package connection

import (
	"bytes"
	"testing"
)

func TestDigestsAreDomainSeparatedAndOrderIndependent(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a := OverrideDigest(salt, []string{"b", "a"})
	if !bytes.Equal(a, OverrideDigest(salt, []string{"a", "b"})) {
		t.Fatal("digest depends on input order")
	}
	if bytes.Equal(a, findingsDigest(salt, []string{"a", "b"})) {
		t.Fatal("override and findings digests collide across domains")
	}
	if bytes.Equal(a, OverrideDigest([]byte("fedcba9876543210"), []string{"a", "b"})) {
		t.Fatal("salt does not affect the digest")
	}
}
