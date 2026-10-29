// Package inventory is the directory inventory (blueprint §5.2): the current state the sync ingester
// writes and every module reads. This first slice holds two read-only pieces that the Tier-0 context
// of a write is built from (connector-contract §8.3, T-0109):
//
//   - DM-20 Correlation: the AD↔Entra identity assertions, in every state but removed, with the
//     peer's tier0 facts, the anchor and the SID evidence (CorrelationSource);
//   - DM-16.I8 customer tier0 designations (Designations).
//
// Both are declared here as consumer-friendly ports, so directory/client depends on the interface
// and takes a fake in tests. This package imports no transport client (the dependency DAG is
// sync → inventory → connection ← client) and nothing in it builds a filter or a DN.
//
// Every read fails closed. A store error is an error, never an empty result: a caller that treats
// "no correlation" as "not tier0" would unprotect an object (TM §6.4, contract §8.3 F1 and F6).
// Nothing is truncated either: a result over the bound is ErrTooMany.
//
// The writers (the gate, the correlation writer, designations) are in writer.go and gate.go.
package inventory
