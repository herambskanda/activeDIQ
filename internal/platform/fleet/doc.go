// Package fleet is the owner key of DM-12 Component and its EnrollmentToken (blueprint §2 rule 6).
//
// The root holds the certificate identity; the gateway and the tunnel arrive with their own tickets.
// The component side (enrollment client, pinned CA, dial-out) is fleet/dial. The SQL lives in fleet/fleetsql, which only the server links, so cmd/connector and
// cmd/agent never carry a store (blueprint §2 rule 7).
package fleet
