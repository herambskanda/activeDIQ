// Package agentpolicy is the trust format of ADR-0007: the signed, sequenced, bounded policy document
// an agent module (addc, fileserver) applies, and the keyset chain that carries the policy key through
// rotation. It holds no private key and no SQL: signing and storage are in package signer, the one
// package that can read the sealed policy key (ADR-0007 P8).
//
// Three things live here, all pure:
//
//   - the canonical byte encodings that get signed (a domain-separation prefix, length-prefixed
//     fields, no map or float, one encoding per value);
//   - AddcPolicy, the policy body, with the bounds of agent-host-addc-contract §3 enforced on decode,
//     so a document outside them is rejected whole;
//   - Verifier, the agent-side acceptance rules P1 to P7. The server never runs it to decide anything;
//     it exists so the signer's output is tested against the rules the agent applies, and so the agent
//     module links the same code instead of a second copy.
//
// A signature gives tenant binding, replay and rollback protection and integrity across the outbox,
// caches and server nodes. It does not protect against a compromised server (TM-D14, TM-R7): the
// bounds are what limit a hostile policy, and they are enforced by the agent, never read from the
// document.
package agentpolicy
