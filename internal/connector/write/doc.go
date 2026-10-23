// Package write is the connector's write group: the Plan and Apply handlers of connector contract
// §8 and the independent Tier-0 guard that stands in front of every directory or Graph write
// (threat-model §6.2 TM-D2, TM-F-T0GUARD).
//
// One Handler serves both transports. The in-process transport calls Handler.Plan and
// Handler.Apply directly (they satisfy directory/client.Transport); the remote transport registers
// the same Handler on a gRPC server through Register. Refusals are *Refusal values that carry the
// ConnectorError as a gRPC status detail, so both transports present identical errors.
//
// The guard has no way around: operation bodies live in an operation table (ops.go) and take an
// Authorised token that only the guard mints after it has passed every step of §8.1. The table is
// empty in this ticket, so no write path exists; a fitness test (fitness_test.go) fails when a
// write call appears anywhere in internal/connector outside the table's package.
package write
