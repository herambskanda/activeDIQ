//go:build lab

package read_test

import (
	"context"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/labadmin"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	"github.com/skenzeriq/activediq/internal/testlab"
)

// T-0669 on Samba: `make lab-up && go test -tags lab ./internal/connector/read -run TestLabUserSearch`.
// A real LDAPS session as the delegated svc-activediq, the real read.Handler/ADSource, and the real
// client.UserSearch; only the gRPC hop is in-process. Windows signing/CBT is a Windows-lab case
// (internal/connector/ad/windows_lab_test.go, WIN_LAB_*).

type labPin struct{}

func (labPin) PinnedC13(context.Context) ([]guid.GUID, error) { return nil, nil }
func (labPin) PinC13(context.Context, []guid.GUID) error      { return nil }

func connsFor(forest string) conns {
	c := activeConn()
	c.DirectoryIdentity = connection.DirectoryIdentity(forest)
	return conns{c}
}

func TestLabUserSearch(t *testing.T) {
	le := testlab.Load(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin := labadmin.Dial(t, le.Port, le.Pool, "Administrator@lab.activediq.test", le.Values["LAB_ADMIN_PASSWORD"])
	name := "t0669-" + time.Now().Format("150405")
	admin.CreateUser(name, "CN=Users,DC=lab,DC=activediq,DC=test")
	nc := admin.ObjectGUID("DC=lab,DC=activediq,DC=test")

	sess, err := ad.Open(ctx, ad.Config{Servers: []string{"localhost:" + le.Port}, RootCAs: le.Pool, PageSize: 500,
		Credential: ad.Credential{BindName: "svc-activediq@lab.activediq.test", Password: secret.FromBytes([]byte(le.Values["LAB_SVC_PASSWORD"]))}})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	g, err := guid.FromBytes(nc)
	if err != nil {
		t.Fatal(err)
	}
	ident := &connectorv1.DirectoryIdentity{Identity: &connectorv1.DirectoryIdentity_AdForest{AdForest: &connectorv1.AdForestIdentity{
		ForestRootNcGuid: write.GUIDToWire(g)}}}
	src, err := read.NewADSource(sess, write.NewADProvider(sess, nil, ident, labPin{}))
	if err != nil {
		t.Fatal(err)
	}
	cc := startSource(t, src)
	us, err := client.NewUserSearch(connsFor(g.String()), direct{cc})
	if err != nil {
		t.Fatal(err)
	}
	res, err := us.Users(ctx, tid, connID, name, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Users) != 1 || res.Users[0].SAMAccountName != name {
		t.Fatalf("users: %+v", res.Users)
	}
	// Injection-looking text is a value: no match, no error, no wildcard expansion.
	res, err = us.Users(ctx, tid, connID, `*)(objectClass=*`, 10)
	if err != nil || len(res.Users) != 0 {
		t.Fatalf("injection: %v %+v", err, res.Users)
	}
}
