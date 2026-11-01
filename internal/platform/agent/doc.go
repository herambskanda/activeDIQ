// Package agent is the skenzeriq agent host that lives inside cmd/agent (blueprint §13, EP-13):
// module lifecycle, the durable bounded outbox, the policy and keyset store, health, and the server
// callable surface skenzeriq.agent.v1.Host (agent-host-addc-contract.md §1 and §2).
//
// What the host refuses to be, by construction:
//
//   - It has no listener. The only network activity is the dial-out the role package makes; the host
//     serves on whatever grpc.ServiceRegistrar the tunnel gives it, and the Mux refuses any method
//     outside the bound contract (TM-D24).
//   - A module cannot open its own listener, spawn a process or write a file: ModuleDeps offers an
//     event sink, a small named-blob store, a logger and a clock, and no path, file or process
//     capability (C2, C3). A module is also not given the policy verifier.
//   - Policy is verified before it is looked at (agentpolicy.Verifier), applied transactionally on a
//     copy, and persisted before it is activated. A refused document changes nothing.
//   - Nothing in the host can fail a customer's domain controller: every error on the event path is
//     counted and reported through GetStatus, and the outbox drops its oldest records, never blocks
//     the subscription (§5).
//
// It carries no password, hash or credential field anywhere (C15) and no fail mode (C16).
package agent
