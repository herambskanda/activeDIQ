// Package authztest is the test kit for code that consumes authz.ReadScope. ReadScope is opaque on
// purpose (the zero value grants nothing, no field is exported); tests in other packages build one
// here. Production code must never import this package.
package authztest

import "github.com/skenzeriq/activediq/internal/platform/authz"

// ReadScope builds a scope with no token layer and no reasons from the given grants. With no
// grants it is the empty scope.
func ReadScope(grants ...authz.ScopeGrant) authz.ReadScope {
	return authz.NewReadScope(grants, nil, nil, "test scope")
}

// ReadScopeWithToken is ReadScope with a token layer AND-ed with the grants.
func ReadScopeWithToken(token authz.TokenLayer, grants ...authz.ScopeGrant) authz.ReadScope {
	return authz.NewReadScope(grants, &token, nil, "test scope")
}

// ReadScopeWithReasons is ReadScope carrying scope reasons, for testing how a consumer reports them.
func ReadScopeWithReasons(reasons []authz.ScopeReason, grants ...authz.ScopeGrant) authz.ReadScope {
	return authz.NewReadScope(grants, nil, reasons, "test scope")
}
