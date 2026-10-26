// Package authn owns the console session store (DM-31; threat model §7.3): sessions kept in PostgreSQL
// so any node serves them, the session token stored only as a SHA-256 hash, idle and absolute expiry
// within platform bounds, a concurrent-session limit with a policy-chosen eviction, and revocation on
// account disable, role change, password or MFA reset and on demand.
//
// It has no HTTP: the cookie, CSRF and the request middleware are the next ticket. Callers hold a
// Store and call Create at sign-in, Lookup on every request, and Revoke* when the account changes.
package authn
