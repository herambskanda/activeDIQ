---
title: "Runbook: emergency policy-key rotation (DC agent re-enrolment sweep)"
date: 2026-10-28
updated: 2026-10-28
status: draft
owner: backend-engineer
ticket: T-0558
---

# Runbook: emergency policy-key rotation

Decision: [ADR-0007](../decisions/0007-agent-policy-trust-and-key-rotation.md) §5 and §7. Contract: [agent-host-addc-contract](../architecture/agent-host-addc-contract.md). Use when the tenant's policy signing key is **believed stolen** (a leaked backup, DB dump or DEK; a database backup restored to a new host). A stolen key can sign a keyset, so the keyset chain cannot recover: the only recovery is the anchor reset, which is re-enrolment of every DC agent.

**Not for scheduled rotation** (every 180 days): that uses the keyset chain and needs no re-enrolment. Rotation protects against key leakage, not against a compromised server (ADR-0007 Context).

## Before you start

- You hold both `fleet.component.revoke` and `fleet.enrollment.issue` for the tenant, and can complete a fresh multi-factor check (step-up). Without either, the sweep refuses and writes nothing.
- You have remote access to every DC (writable and RODC) running `activediq-agent`. Each needs the new token typed or passed once.
- Expect: while an agent is revoked it collects no events and enforces the last installed password policy (installed policy stays in force, ADR-0007 §3). Plan the window; the exposure this bounds is password-rule changes and event collection stopping (TM-R7).

## Steps

1. **Generate the new policy key first.** The sweep does not create keys. The new key must exist and be the one the server delivers on the agents' first authenticated call, otherwise they re-anchor on the compromised key. *Owed:* the policy signer module is not built yet (follow-up ticket), so this flow is not usable end to end until it lands; do not run the sweep before then.
2. **Run the sweep** with reason `suspected_key_exposure` (or `backup_restored_to_new_host`) and a token lifetime (default 1 h, max 24 h). Complete step-up when asked. Entry point today: `fleetsql.Reenroller.ReenrolAddc`; the API/UI surface is a follow-up.
3. **Read the result**: per agent, success with a one-time token, or a failure reason. The token is shown **once**; it is stored only as a hash. Hand each token to the DC's operator over a secure channel. Agents that failed are still enrolled; fix the cause and run the sweep again (it only touches agents still enrolled or active, so it is safe to repeat).
4. **Re-enrol each DC**: on the DC, enrol the agent with its token. The agent gets a new certificate, resets its anchor and accepts the first keyset delivered, which is the new key's. Do this before the token expires; if it does, run the sweep again for the remaining agents (their old components are already revoked, so issue fresh tokens through the normal enrollment-token flow).
5. **Verify**: every addc component of the tenant is `enrolled`/`active` with a new component ID, `GetStatus` shows the new `keyset_seq`, and no old component is usable.

## What the audit trail records

- `fleet.component.revoked` per agent: the human who ran it, old component, serial of the revoked certificate, successor component ID, sweep ID, reason code.
- `fleet.agents.reenrol_sweep` once: the same human, counts found / re-enrolling / failed, outcome.
- The agent's own Windows Application-log entry and audit event for the new keyset (ADR-0007 §8).

## Rehearsal

Not yet rehearsed on the lab: the agent side (anchor reset on re-enrolment, fitness P7) needs the Windows lab. Rehearse before this runbook leaves `draft`.
