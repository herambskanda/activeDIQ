//go:build !unix

package dial

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/credentials"
)

// On hosts without the owner-only ACL implementation nothing is written or read (T-0291).
func TestNonUnixFailsClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if _, err := Load(dir); !errors.Is(err, ErrState) {
		t.Fatalf("Load = %v, want ErrState", err)
	}
	ex := func(context.Context, credentials.TransportCredentials, string, string, []byte) (Response, error) {
		t.Fatal("exchange reached")
		return Response{}, nil
	}
	m := Material{Address: "localhost:1", Token: "t", Pin: "sha256:" + strings.Repeat("ab", 32)}
	if _, err := Enroll(context.Background(), m, dir, ex); !errors.Is(err, ErrState) {
		t.Fatalf("Enroll = %v, want ErrState", err)
	}
	assertNothingPersisted(t, dir)
}
