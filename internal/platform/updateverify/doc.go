// Package updateverify is the one verifier of ENH-07 (spec enh-07-signed-update-protocol.md, ADR-0002
// rule 7): every courier (online, offline bundle) and every consumer (server, connector, agent)
// decides whether an update may be installed by calling Verifier.Verify, and nowhere else.
//
// The chain is root -> timestamp -> snapshot -> targets -> artefact. The caller pins the root it
// trusts (the installer's, for a connector or agent); the verifier never trusts anything the
// transport, the mirror or the server adds, so an artefact signed only by the server's own key is
// refused (unsigned_by_root). Expiries, thresholds, lengths and hashes all come from signed
// metadata; the only constants are the endless-data limits on metadata size.
//
// Signed bytes. A metadata file is {"signed": <object>, "signatures": [{"keyid","sig"}]}. A signature
// is Ed25519 over the exact bytes of the "signed" member as transmitted. No canonicalisation step
// exists to disagree about; the signer's pipeline (T-0140/T-0141) must emit the bytes it signs.
//
// Consumers pin their component (Config.Name, Config.Platform) next to the root; a courier cannot
// choose which signed release is installed. Couriers must always supply the whole root chain after
// the pinned root, ascending: a chain that stops short of the floor's root version is a rollback.
//
// Nothing is extracted by this package. The artefact is streamed into a quarantine directory
// outside the data path while its length and SHA-256 are checked, and Verify returns the quarantine
// path only when the artefact, the manifest and the platform signature have all passed. The quarantine
// directory must be private to the service account (DirQuarantine enforces it). The apply mechanism
// consumes the artefact only through Result.Open, which re-checks length and SHA-256 on the
// descriptor it returns; reopening the path by name is forbidden (TOCTOU).
//
// Refusals are *Refusal values with a closed Reason (tamper, rollback, freeze, revoked_key,
// unsigned_by_root, withdrawn). Any other error is an operational failure (floor unreadable,
// quarantine unwritable) and also means "do not install".
package updateverify
