// Package fleet is the owner key of DM-12 Component and its EnrollmentToken (blueprint §2 rule 6).
//
// The root holds no code yet: the gateway, the tunnel and the component-side dial arrive with their
// own tickets. The SQL lives in fleet/fleetsql, which only the server links, so cmd/connector and
// cmd/agent never carry a store (blueprint §2 rule 7).
package fleet
