// Package authn is the authentication core of the platform (owner of DM-30..DM-37).
//
// Sessions (DM-31; threat model §7.3): console sessions kept in PostgreSQL so any node serves them,
// the session token stored only as a SHA-256 hash, idle and absolute expiry within platform bounds,
// a concurrent-session limit with a policy-chosen eviction, and revocation on account disable, role
// change, password or MFA reset and on demand. The HTTP binding is httpx/authnhttp (this package imports no net/http, ADR-0004 A6): the __Host- cookie
// attributes, the CSRF value derived from the session token, and the Authenticator that apihost's chain
// calls (steps 8 and 9). Callers hold a Store and call Create at sign-in, Lookup on every
// request, and Revoke* when the account changes.
//
// Account events (DM-31.I2, threat model §7.3): the account, RBAC and MFA paths call OnAccountDisabled,
// OnRoleChanged, OnPasswordReset or OnMFAReset with their own transaction, so the change and the
// revocation of the account's sessions commit together (events.go). Every session create, eviction,
// expiry and revocation is an audit event requested in the transaction that causes it (audit.go): actor,
// account and session handle, never the token or its hash. Ended rows are kept for the audit trail and
// removed by the owner-role Purger (purge.go; Purge for sessions, PurgePending for pending sign-ins) once past the retention; the runtime role cannot DELETE.
//
// TOTP (DM-37 AuthenticatorEnrollment): a seed sealed under the tenant's data key and bound to its
// tenant, table, row and column (TM-F-SEAL), an RFC 6238 verifier (HMAC-SHA-1, 6 digits, 30 s step,
// a window of one step either side) and a used-step guard so a code never verifies twice.
//
// There is no HTTP and no enrolment flow here; callers (sign-in, step-up) bring the tenant
// transaction and the audit. The seed leaves Enroll once, as a secret.Secret, for the authenticator
// app to scan; nothing else in the package returns it (DM-37.I1). The RFC primitives use only the
// standard library, so no dependency and no licence-register row is added.
//
// Every refusal of a code is an error the caller must answer identically to the user (ErrCodeRejected,
// ErrCodeReplayed and ErrFactorPaused all mean "that code did not work"); the distinction is for the
// audit trail and for steering a technician to another factor.
//
// Failure budget (ENH-09 §5, DM-37): the package, not the caller, bounds guesses per enrolment, in the
// database so every node shares it: 10 refused codes in a rolling hour pause verification for an hour
// (paused_until; a correct code is then refused unevaluated), and a pending enrolment expires after
// 10 minutes or 5 wrong confirmations. Each attempt is charged BEFORE the code is evaluated, in a
// separate short committed transaction under the enrolment's row lock (Service.Failures, on its own
// connection pool), so a caller rolling back cannot undo it and concurrent guesses cannot exceed the
// budget; a success is refunded in the caller's transaction. Consequences for callers: the enrolment
// must be committed before Verify or Activate (the charge sees only committed rows), and the caller's
// transaction must not hold a lock on the enrolment row. Per-caller limits (sign-in, step-up) are
// additional and do not replace this one.
package authn
