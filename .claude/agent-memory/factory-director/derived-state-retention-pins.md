---
name: derived-state-retention-pins
description: DM review — derived states plus retention can flip a derivation back; audit events must not carry security-restricted identifiers; spec-type security-sensitive tickets have no security stage
metadata:
  type: feedback
---

When a state is derived from other records, such as "cleared = a later passing run exists", list every record the derivation reads. Each one must be pinned by retention for as long as the derived subject is kept. Otherwise deleting a row can flip the state back, and a cleared Tier-0 override comes back into force.

**Why:** On T-0168 (2026-10-02), DM-25's clearance was derived from a DM-24 run. Retention pinned the override's evidence run but not the run that cleared it, and the author's "age order makes this safe" argument fails on a crash between the two deletes. security-architect caught it, and the ticket was rejected.

**How to apply:**
- For every derived state, ask: "if retention deletes the row this reads, does the derivation change?" Require a pin, or a property test stating that no retention pass changes the derivation.
- Audit events are hash-chained and sent to SIEM, so they can never be redacted. If a view is restricted (e.g. findings behind a verify permission), its identifiers must not appear in the audit event. Allow only counts and a salted digest; an unkeyed digest of enumerable GUIDs can be brute-forced.
- "Interrupted run returns to X" rules must be conditioned on the state the run came from.
- Gates checked at Plan should also be checked at Apply for long or bulk Actions.
- The `spec` flow has no security-architect stage, even for tickets tagged security-sensitive. If the ticket asks for security confirmation, consult a security-architect subagent during review.
- Round 2 (same ticket): a cited invariant in *another* entity (e.g. "DM-11 never re-binds a credential") must actually exist there — grep it. An "ended/cleared" first-event-wins order needs the timestamp of each event on a pinned row.
- An event emitted for a derived transition must use the same predicate as the derivation (`.cleared` ignored the credential, so a credential swap would emit a false clearance).
- A DM rule that adds a pipeline outcome must use edges in the ratified ADR-0005 rule 3 table. There is no `planned → failed`; refusals at Apply are `applying → failed`.

Related: [[domain-model-review-checks]]
