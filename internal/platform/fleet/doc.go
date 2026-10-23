// Package fleet is the owner key of DM-12 Component and its EnrollmentToken (blueprint §2 rule 6).
//
// It holds the gateway's transport rules and per-RPC authentication (gateway.go, identity.go),
// including revocation checks and stream teardown (TM-TB6-T9), and the tunnel multiplexer (mux.go
// and neighbours, TM-D24). Both are contract-agnostic and never import the generated stubs. The SQL
// lives in fleet/fleetsql, which only the server links, so cmd/connector and cmd/agent never carry a
// store (blueprint §2 rule 7).
package fleet
