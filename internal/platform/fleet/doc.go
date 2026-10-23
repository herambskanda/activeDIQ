// Package fleet is the owner key of DM-12 Component and its EnrollmentToken (blueprint §2 rule 6).
//
// The root holds the gateway transport and per-RPC authentication (gateway.go), including revocation
// checks and stream teardown (TM-TB6-T9). The tunnel and the component-side dial arrive with their
// own tickets. The SQL lives in fleet/fleetsql, which only the server links, so cmd/connector and
// cmd/agent never carry a store (blueprint §2 rule 7).
package fleet
