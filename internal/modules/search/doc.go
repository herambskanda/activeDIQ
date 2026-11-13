// Package search is the universal directory search service (ADR-0011, T-1096): it classifies the typed text
// with platform/searchkey, takes the caller's read scope from the one producer (rbac.ReadScopes.For, reached
// through the ReadScopes port the composition root implements), asks the inventory index with that scope,
// and returns the permitted hits as groups in rank order.
//
// What this package never does (fitness-search SE1): render a scope, call ReadScope.Admits or SearchRoots,
// build SQL, or touch the directory. The scope is handed to inventory.Searcher.Search, whose one statement
// trims by it before ranking, counting, limiting and paging. Search text is never logged or echoed: a
// refusal carries a code, a served query is logged as its length, shapes and classes only (rule 15).
//
// The HTTP mapping of searchDirectory lives in modules/directory, which owns the tag.
package search
