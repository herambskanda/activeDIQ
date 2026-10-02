// Package apihost serves the public API: the one place that reads a request body, writes an HTTP
// status, and mounts a route (ADR-0004 rule 5).
//
// This file set is the minimal slice T-0147 needs so generated per-tag packages have something to
// return: TagHandlers and the route rows. The middleware chain, strict decode, problem rendering,
// Ports and Build arrive with T-0086.
package apihost
