package server

import (
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/platform/audit"
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
// authorizer. Any missing piece fails boot.
func buildOperation(holdsMinter func() bool, db *store.DB, facts operation.LiveFacts, authzr operation.Authorizer, reg *operation.Registry) (*operationKernel, error) {
	if !holdsMinter() {
		return nil, ErrNoMinter
	}
	if facts == nil {
		return nil, ErrNoFacts
	}
	ch := audit.NewChainer(db)
	r, err := operation.NewRunner(operation.Config{DB: db, Audit: ch, Authz: authzr, Registry: reg, Facts: facts, Component: "server"})
	if err != nil {
		return nil, fmt.Errorf("server: operation runner: %w", err)
	}
	return &operationKernel{Chainer: ch, Runner: r}, nil
}

// directoryFacts is the live facts reader: the directory client's read half over the connector-backed
// facts reader (client.ConnectorFacts). reads is the connector's read adapter; until the gRPC adapter
// lands (a nil reads) a directory target fails closed with client.ErrNoReads, while a tier0_scope
// target or a store target is answered without a read.
func directoryFacts(reads client.Reads) operation.LiveFacts {
	return client.New(client.WithFacts(client.NewConnectorFacts(reads)))
}

// rbacAuthorizer is the operation Authorizer: RBAC persistence read through authz.Evaluator.
func rbacAuthorizer(db *store.DB) (operation.Authorizer, error) {
	src, err := rbac.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("server: rbac store: %w", err)
	}
	az, err := rbac.New(src)
	if err != nil {
		return nil, fmt.Errorf("server: rbac authorizer: %w", err)
	}
	return az, nil
}
