package server

import (
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authn"
	"github.com/skenzeriq/activediq/internal/platform/operation"
	"github.com/skenzeriq/activediq/internal/platform/rbac"
	"github.com/skenzeriq/activediq/internal/platform/store"
)

// ErrNoMinter is returned at boot when the operation package does not hold the step minter: a write
// step could then be minted elsewhere, or by no one (ADR-0005 rule 2). The server does not start.
var ErrNoMinter = errors.New("server: operation does not hold the step minter (ADR-0005 rule 2): refusing to start")

// ErrNoFacts is returned at boot when the runner would have no live facts reader.
var ErrNoFacts = errors.New("server: no live facts reader wired for the operation runner: refusing to start")

// operationKernel is what buildOperation wires: the commit-time audit chainer and the runner that
// appends to it.
type operationKernel struct {
	Chainer *audit.Chainer
	Runner  *operation.Runner
}

// buildOperation wires the operation runner to the audit chain (ADR-0005 rules 2, 7 and 11). It
// asserts the minter first, installs the chainer's commit hook on db (once, as the store opens), and
// hands the runner the chainer as its audit.Sink, the directory client as its LiveFacts and the
// authorizer, and the DC pinner (nil: an AD-target plan then fails closed, no DC is pinned). Any missing piece fails boot.
func buildOperation(holdsMinter func() bool, db *store.DB, facts operation.LiveFacts, authzr operation.Authorizer, reg *operation.Registry, pinner operation.Pinner) (*operationKernel, error) {
	if !holdsMinter() {
		return nil, ErrNoMinter
	}
	if facts == nil {
		return nil, ErrNoFacts
	}
	ch := audit.NewChainer(db)
	r, err := operation.NewRunner(operation.Config{DB: db, Audit: ch, Authz: authzr, Registry: reg, Facts: facts, Pinner: pinner, Component: "server"})
	if err != nil {
		return nil, fmt.Errorf("server: operation runner: %w", err)
	}
	return &operationKernel{Chainer: ch, Runner: r}, nil
}

// directoryReads builds the connector read adapter (client.ConnectorReads) over the connection
// registry, so a read resolves its connection under the context's tenant. The Tier-0 verdict is not a
// separate source: it arrives in the Read header from the connector (T-0433), and a response without
// it is an error. A nil src returns nil reads, which directoryFacts turns into fail-closed ErrNoReads;
// the server always supplies the tunnel source, so only a test passes nil.
func directoryReads(conns client.ConnectionSource, src client.ConnectorSource) (client.Reads, error) {
	if src == nil {
		return nil, nil
	}
	tr, err := client.NewGRPCReadTransport(src)
	if err != nil {
		return nil, fmt.Errorf("server: read transport: %w", err)
	}
	r, err := client.NewConnectorReads(conns, tr)
	if err != nil {
		return nil, fmt.Errorf("server: connector reads: %w", err)
	}
	return r, nil
}

// directoryFacts is the live facts reader: the directory client's read half over the connector-backed
// facts reader (client.ConnectorFacts). reads is the connector's read adapter (directoryReads); with a
// nil reads a directory target fails closed with client.ErrNoReads, while a tier0_scope target or a
// store target is answered without a read.
func directoryFacts(reads client.Reads, opts ...client.Option) *client.Client {
	return client.New(append([]client.Option{client.WithFacts(client.NewConnectorFacts(reads))}, opts...)...)
}

// rbacAuthorizer is the operation Authorizer: RBAC persistence read through authz.Evaluator, with the
// TM-D19 rule 5 backing-object guard wired to the account and correlation stores and a live root
// resolver over facts, and the TM-D18 group-membership guard over inventory's group edges. Without a
// guard its permissions are refused.
func rbacAuthorizer(db *store.DB, facts rbac.FactsReader) (*rbac.Authorizer, error) {
	src, err := rbac.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("server: rbac store: %w", err)
	}
	idx, err := authn.NewAccountIndex(db)
	if err != nil {
		return nil, fmt.Errorf("server: account index: %w", err)
	}
	backing, err := rbac.NewBacking(accountAdapter{idx}, peerAdapter{inventory.NewReader(db, nil)})
	if err != nil {
		return nil, fmt.Errorf("server: rbac backing: %w", err)
	}
	roots, err := rbac.NewRootResolver(facts)
	if err != nil {
		return nil, fmt.Errorf("server: rbac root resolver: %w", err)
	}
	az, err := rbac.New(src, rbac.WithBackingGuard(backing, roots), rbac.WithGroupGuard(inventory.NewReach(inventory.NewGroups(db))))
	if err != nil {
		return nil, fmt.Errorf("server: rbac authorizer: %w", err)
	}
	return az, nil
}
