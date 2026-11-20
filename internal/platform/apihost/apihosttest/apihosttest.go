// Package apihosttest is the test kit for code that needs apihost route values without a generated
// Bind. It lives under apihost, the one place besides generated code allowed to build routes
// (ADR-0004 A6). Nothing here is mounted by a running process.
package apihosttest

import (
	"fmt"

	"github.com/skenzeriq/activediq/internal/platform/apihost"
)

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
