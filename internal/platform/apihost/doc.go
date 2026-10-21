// Package apihost serves the public API: the one place that reads a request body, writes an HTTP
// status, and mounts a route (ADR-0004 rule 5).
//
// Generated per-tag packages return TagHandlers (route.go). Build (build.go) checks them against the
// embedded contract (document.go) and the security policy (policy.go) and returns the Server: a
// net/http.ServeMux whose every route runs the one fixed chain in chain.go. Body buffering and the
// strict JSON pass are in body.go; problem and response rendering in render.go. apihost depends on
// ports (ports.go), not on authn or authz: compose/server injects the implementations.
package apihost
