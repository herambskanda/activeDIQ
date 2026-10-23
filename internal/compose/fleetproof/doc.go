// Package fleetproof is the CI proof of threat-model case TM-F-FLEET (threat-model.md §15; TB6-T1,
// T2, T6, T8, T9, T13; TB12-T1, T2). It holds tests only. Each test drives the real subject code
// (the fleet gateway, the component-side dial package, the fleetsql enrollment store and the
// generated fleet contract) and fails if one of the case's conditions holds:
//
//   - an RPC other than Enroll succeeds without a client certificate;
//   - an enrollment token works twice or after expiry;
//   - a component accepts an unpinned server;
//   - a revoked component keeps a stream;
//   - the fleet contract gains a secret-bearing message type.
//
// The tunnel cases (A) to (D) of TM-D24 are proven where their subjects live: internal/platform/fleet
// (method corpus, frame sequences, hostile text) and internal/platform/fleet/dial (bundle corpus,
// pin-mismatch MITM). This package adds the cross-package proofs that no single subject can make.
package fleetproof
