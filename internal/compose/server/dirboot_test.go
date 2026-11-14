package server

import (
	"context"
	"errors"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory"
	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/connection"
	"github.com/skenzeriq/activediq/internal/platform"
	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/owners"
)

// bootDirectoryRoutes boots the generated module list the way Run does (ADR-0013): the modules build their
// services in Register from the directory services and Deps, the read-scope producer is bound after Boot,
// and the routes come out of Contributions.API. It names no module: a test of the composed directory
// routes reads what the modules registered.
func bootDirectoryRoutes(ctx context.Context, t *testing.T, db *store.DB, conns *connection.Registry, src client.ConnectorSource, reads client.Reads, az *rbac.Authorizer) []apihost.TagHandlers {
	t.Helper()
	txScopes := rbac.NewTxReadScopes(db)
	c, _, err := bootReport(ctx, capability.NewSet(capability.DirectoryAD, capability.DirectoryEntra, capability.TenantProvisioning),
		directory.Services{Connection: conns, Source: src, Reads: reads}, owners.Lookup,
		func(d *platform.Deps) { d.DB, d.ReadScopes = db, txScopes })
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	rs, err := buildReadScopes(az, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := txScopes.Bind(rs); err != nil {
		t.Fatal(err)
	}
	return c.API()
}

// stubSource and stubReads make the module mount its routes without a connector: the tests that use them
// never reach the directory (inventory search and the scope producer are the subject).
type stubSource struct{}

func (stubSource) Connector(context.Context, string) (connectorv1.ConnectorClient, error) {
	return nil, errors.New("no connector in this test")
}

type stubReads struct{}

func (stubReads) Object(context.Context, authority.Pins, authority.TargetRef, string, bool) (client.ObjectRead, error) {
	return client.ObjectRead{}, errors.New("no directory in this test")
}

// boundScopes is the producer the composed server hands the modules: rbac.TxReadScopes bound to rs.
func boundScopes(t *testing.T, db *store.DB, rs *rbac.ReadScopes) *rbac.TxReadScopes {
	t.Helper()
	tx := rbac.NewTxReadScopes(db)
	if err := tx.Bind(rs); err != nil {
		t.Fatal(err)
	}
	return tx
}

// openPorts authenticates every request as the session principal account names in the install's tenant
// and allows it: the permission check is not the subject of the tests that use it.
type openPorts struct {
	tenant  string
	account *atomic.Pointer[string]
}

func (p openPorts) Authenticate(*http.Request) (apihost.Principal, error) {
	id := p.account.Load()
	if id == nil {
		return apihost.Principal{}, errors.New("no account")
	}
	return apihost.Principal{ID: *id, Tenant: p.tenant, Kind: apihost.KindSession, SessionID: "s"}, nil
}
func (openPorts) CheckCSRF(*http.Request, apihost.Principal) error { return nil }
func (openPorts) Allow(context.Context, apihost.Principal, string, string) (bool, error) {
	return true, nil
}
func (openPorts) AllowPrincipal(context.Context, string, apihost.Principal) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (openPorts) AllowIP(context.Context, string, string) (apihost.Decision, error) {
	return apihost.Decision{Allowed: true}, nil
}
func (openPorts) Fresh(context.Context, apihost.Principal) (bool, error) { return true, nil }
