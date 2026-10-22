// Package ldapfilter is P1 of the safe primitives (safe-primitives §3): the only producer of an LDAP
// filter string. A filter is an AST of typed assertions; Render turns it into RFC 4515 text in which
// no value can add, remove or reorder a component, attribute names come from the schema, and the
// matching rules come from a closed set.
//
// This package implements RFC 4515 itself. The LDAP library is imported only under internal/connector
// (FF-SP1), and its filter compiler is used only by the FF-SP6 oracle that checks this renderer.
//
// Errors carry a stable code (Error.Code) and never the offending value: the value may be hostile or
// secret-adjacent. Constructors never fail; every check runs in Render, so a Filter that rendered once
// against a schema is known good and a Filter that did not has said why.
//
// Not in this package yet: the admin-filter parser (ParseAdminFilter, ParseFilterAST) and the scope
// package (ScopedSearch, ReadSecret). They build on the AST here.
package ldapfilter
