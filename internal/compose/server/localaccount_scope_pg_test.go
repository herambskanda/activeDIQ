package server

// T-0987: the first console account reads the directory through a naming_context assignment on each active
// AD connection (the tenant-store root grants nothing to directory data), proved through the real
// rbac.ReadScopes producer and the txReadScopes adapter buildDirectory is given.

import (
	"context"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/secret"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// activeAD activates a new AD connection through the real connection service over a connector that passes
// every check (activation_test.go), so its directory identity is the one verification recorded.
func activeAD(t *testing.T, reg *connection.Registry, ten tenant.ID) connection.Connection {
	t.Helper()
	vopts, err := verifyOptions(fixedConnectorSource{&passingConnector{}})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := connection.NewService(reg, client.New(vopts...), nopSink{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := reg.Create(context.Background(), ten, connection.New{Kind: connection.KindADForest, DisplayName: "ad", CredentialID: bkCred, Transport: connection.TransportLDAPS})
	if err != nil {
		t.Fatal(err)
	}
	out, err := svc.Activate(context.Background(), ten, c.ID, authority.Chain{Requester: authority.Principal{ID: "u1", Kind: authority.Human}})
	if err != nil || out.Connection.State != connection.StateActive || out.Connection.DirectoryIdentity == "" {
		t.Fatalf("Activate = %+v, %v", out.Connection, err)
	}
	return out.Connection
}

func TestInitLocalAccountReadsActiveADConnections(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		ctx := context.Background()
		db, ten, ks := hardeningDB(t, s, 0)
		reg := connection.NewRegistry(db)
		active := activeAD(t, reg, ten)
		// A draft AD connection and an Entra connection are not granted: no naming context to name.
		if _, err := reg.Create(ctx, ten, connection.New{Kind: connection.KindADForest, DisplayName: "draft", CredentialID: bkCred, Transport: connection.TransportLDAPS}); err != nil {
			t.Fatal(err)
		}
		if _, err := reg.Create(ctx, ten, connection.New{Kind: connection.KindEntraTenant, DisplayName: "entra", CredentialID: bkCred}); err != nil {
			t.Fatal(err)
		}

		deps := localAccountDeps{DB: db, Sink: nopSink{}, Keys: ks.KeySource()}
		la, err := createLocalAccount(ctx, deps, LocalAccountSpec{Username: "console.reader", Password: secret.FromBytes([]byte(signInPassword))})
		if err != nil {
			t.Fatal(err)
		}
		// The account is inactive until its TOTP is confirmed; the producer treats an inactive owner as dead.
		var seedText string
		la.Seed.Expose(func(b []byte) { seedText = string(b) })
		seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(seedText))
		if err != nil {
			t.Fatal(err)
		}
		if err := confirmTOTP(ctx, deps, la, totpCode(seed, time.Now())); err != nil {
			t.Fatal(err)
		}

		c, _, err := bootReport(ctx, capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning), directory.Services{}, owners.Lookup)
		if err != nil {
			t.Fatal(err)
		}
		az, err := rbacAuthorizer(db, noFacts{})
		if err != nil {
			t.Fatal(err)
		}
		rs, err := buildReadScopes(az, c)
		if err != nil {
			t.Fatal(err)
		}
		chain := authority.Chain{Requester: authority.Principal{ID: authority.PrincipalID(la.ID), Kind: authority.Human}}
		got, err := txReadScopes{db: db, rs: rs}.ReadScope(ctx, ten, chain, "directory.read")
		if err != nil {
			t.Fatal(err)
		}
		conn, _ := authz.ParseObjectID(string(active.ID))
		nc, _ := authz.ParseObjectID(string(active.DirectoryIdentity))
		want := authz.ScopeTerm{Kind: authz.TermNamingContext, Connection: conn, Root: nc}
		grants := got.Terms()
		if len(grants) != 1 || len(grants[0].Include) != 1 || grants[0].Include[0] != want || len(grants[0].Exclude) != 0 {
			t.Fatalf("grants = %+v, want exactly the active AD connection's naming context %+v (reasons %v)", grants, want, got.Reasons())
		}
		if got.Empty() {
			t.Fatal("scope is empty")
		}
	})
}
