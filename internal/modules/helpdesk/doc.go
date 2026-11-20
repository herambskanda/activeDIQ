// Package helpdesk is the server module for the help desk's caller verification (ENH-09, ADM-136;
// spec knowledge/product/specs/enh-09-otp-and-totp-enrolment.md, DM-38). A technician with no AD rights
// issues a one-time code to a contact factor the directory already holds for the caller, types in what the
// caller reads back, and a verified challenge then satisfies the StepUp requirement of the reset and unlock
// Actions in place of the technician's own MFA (TM-D16): it is the caller, not the technician, who is being
// proved.
//
// Verifier (verifier.go) is the engine: Issue sends on a user act only, Verify charges every attempt
// before it looks at the code, Authorise consumes a verified challenge once for one operation, and the
// Grant it returns binds to an operation.Request (grant.go). Every limit lives in PostgreSQL (migration
// 0079), never in memory, so all nodes share it. The module owns helpdesk_caller_verifications and
// nothing else; it reads the caller's destination and the technician's authority through ports
// (ports.go) and never builds an LDAP filter, DN or message string from caller input.
//
// Handlers (handlers.go, contract api/openapi/modules/helpdesk.yaml) are the HTTP edge: POST only, CSRF through apihost,
// idempotent through IssueOnce and VerifyOnce (idempotency.go), one uniform refusal per route padded to RefusalFloor, and
// per-session and per-IP limits on top of the engine's. Like the directory module it has no Action and no Module value yet,
// so it is not in modules.gen.go; the sheet and the port adapters in the composition root are follow-ups.
package helpdesk
