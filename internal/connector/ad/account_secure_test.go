package ad

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/unicodepwd"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// A password write on a connection that is not TLS fails with CodeInsecure before any search or
// Modify: the peer here never answers, so a search would hang until the context deadline.
func TestModifyAccountNeedSecureOnPlainConnFailsBeforeAnySearch(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	conn := ldap.NewConn(a, false)
	conn.Start()
	go io.Copy(io.Discard, b)
	s := &Session{conn: conn, server: "dc.example.test:389"}
	defer s.Close()

	called := false
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := s.ModifyAccount(ctx, dn.GUIDRef(guid.GUID{1}),
		func(AccountState) error { called = true; return nil },
		func(Modifier, string, unicodepwd.SecureConn) error { called = true; return nil }, true)
	if CodeOf(err) != CodeInsecure {
		t.Fatalf("got %v, want %s", err, CodeInsecure)
	}
	if called || ctx.Err() != nil {
		t.Fatalf("check or sender ran, or a search was attempted (ctx err %v)", ctx.Err())
	}
}

func TestMapModifyErrKeepsClassifiedSenderError(t *testing.T) {
	s := &Session{}
	if c := CodeOf(s.mapModifyErr(context.Background(), NewError(CodeInsecure))); c != CodeInsecure {
		t.Fatalf("got %s", c)
	}
}
