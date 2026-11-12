// Package moduletest is the test kit for module unit tests (ADR-0003 rule 5). Register runs a
// module through the same validations as module.Boot, against a real, private Registrar, and hands
// the contributions back. It touches no host, so nothing it does reaches a running process.
package moduletest

import (
	"context"
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
	"github.com/skenzeriq/activediq/internal/platform/capability"
	"github.com/skenzeriq/activediq/internal/platform/module"
)

// Register boots m alone, with every capability it requires enabled, and returns what it
// contributed. Any Boot validation failure (namespacing, duplicates, ID rules) is the error.
//
// A module that registers datasets passes module.WithTableOwners with the ownership map it wants
// the table check to read.
func Register(m module.Module, opts ...module.BootOption) (*module.Contributions, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nil module", module.ErrInvalid)
	}
	enabled := capability.NewSet(m.Requires()...)
	return module.Boot(context.Background(), []module.Entry{{ID: m.ID(), Module: m}}, enabled, opts...)
}

// Tag returns an API contribution for tag with one route per permission, for tests that register
// API tags. The routes have no handlers and are never mounted.
func Tag(tag string, permissions ...string) apihost.TagHandlers {
	routes := make([]apihost.Route, 0, len(permissions))
	for i, p := range permissions {
		routes = append(routes, apihost.NewRoute(apihost.RouteMeta{
			OperationID: fmt.Sprintf("%sOp%d", tag, i), Tag: tag, Method: "GET",
			Path: fmt.Sprintf("/%s/%d", tag, i), Permission: p,
		}, nil, nil))
	}
	return apihost.NewTagHandlers(tag, routes...)
}
