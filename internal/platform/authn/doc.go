// Package authn is the authentication core of the platform (owner of DM-30..DM-37). This slice is
// the TOTP factor primitive of DM-37 AuthenticatorEnrollment: a seed sealed under the tenant's data
// key and bound to its tenant, table, row and column (TM-F-SEAL), an RFC 6238 verifier (HMAC-SHA-1,
// 6 digits, 30 s step, a window of one step either side) and a used-step guard so a code never
// verifies twice.
//
// There is no HTTP and no enrolment flow here; callers (sign-in, step-up) bring the tenant
// transaction and the audit. The seed leaves Enroll once, as a secret.Secret, for the authenticator
// app to scan; nothing else in the package returns it (DM-37.I1). The RFC primitives use only the
// standard library, so no dependency and no licence-register row is added.
//
// Every refusal of a code is an error the caller must answer identically to the user (ErrCodeRejected
// and ErrCodeReplayed both mean "that code did not work"); the distinction is for the audit trail.
// Throttling failed attempts is the caller's: it must count them (threat model §7.2).
package authn
