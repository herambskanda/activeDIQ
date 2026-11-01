// Package addc is the agent module for domain controllers (activediq.addc.v1). It holds two things
// and nothing else: the password rule engine, a pure function from a verified policy and a candidate
// password to a verdict, and the Security / Directory Service event collector that hands records to
// the host's outbox.
//
// It has no listener, no process, file, registry, service-control, LDAP, SMB, RPC or SSPI use; its
// only persistence is the host's named blobs, and its only way out is the host's event sink
// (agent-host-addc-contract §1, ADR-0006 decision 4). Event IDs come from a compiled-in catalogue
// that a signed policy can only select from.
package addc
