// Package client is the server's only door to a connector's write group (ADR-0005 rule 2, fitness
// function O2). Every exported write method takes a step.Step; the Plan and Apply RPCs go out only
// behind the step.Clearance the Step's authorisation re-check issued, and only with a Tier0Context
// the server built at that moment.
//
// This is the skeleton: the Write seam, the consumer-side ports the Tier0Context builder reads
// (T-0109 fills them), the Transport and FactsReader ports the gRPC transport implements, and the
// mapper from a ConnectorError to a step outcome. There is no Tier-0 logic here: with no builder
// wired, Write refuses (fail closed).
//
// VerifyConnection (verify.go) is the read-only run: it implements connection.ConnectorClient over the
// VerifyTransport port and folds the response stream into a connection.VerifyResult.
//
// It imports connection (the registry), never the reverse (blueprint §5.2), and the kernel leaves
// authority and operation/step. It does not import operation.
package client
