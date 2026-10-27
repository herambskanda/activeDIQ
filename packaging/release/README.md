# Release signing public key

`release-signing.pub` (base64 Ed25519 public key, one line) is committed here once security-architect
has generated the key pair (`go run ./tools/release/sign keygen`; the seed goes straight into the
repository secret `RELEASE_SIGNING_KEY`, never to disk). Until it exists, `.github/workflows/release.yml`
fails at the verify step on purpose: nothing is published unsigned. Custody target: T-0140/T-0141.
