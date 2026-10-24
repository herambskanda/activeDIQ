package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/skenzeriq/activediq/internal/directory/client"
	"github.com/skenzeriq/activediq/internal/platform/audit"
	"github.com/skenzeriq/activediq/internal/platform/authority"
	"github.com/skenzeriq/activediq/internal/platform/authz"
	"github.com/skenzeriq/activediq/internal/platform/operation"
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

// directoryFacts is the live facts reader: the directory client's read half. Until the connector
// transport and facts reader are wired (T-0174) it refuses every read with client.ErrNoFacts, so a
// directory step fails closed rather than authorising on guessed facts.
func directoryFacts() operation.LiveFacts { return client.New() }

// errNoRBAC is the refusal every operation gets until RBAC persistence lands.
var errNoRBAC = errors.New("server: no RBAC store wired: operation refused")

// denyAuthorizer is the Authorizer until RBAC persistence loads principals and assignments for
// authz.Evaluator: it refuses every permission, and asks for the Tier-0 fact so nothing is waved
// through. The runner records each refusal as a denied event.
type denyAuthorizer struct{}

func (denyAuthorizer) FactsQuery(_ authority.Chain, _ authz.Permission, t authority.TargetRef) authority.FactsQuery {
	return authority.FactsQuery{Target: t, Tier0: true}
}

func (denyAuthorizer) Authorize(context.Context, authority.Chain, authz.Permission, authority.TargetRef, authority.Facts) error {
	return errNoRBAC
}
