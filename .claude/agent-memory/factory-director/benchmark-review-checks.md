---
name: benchmark-review-checks
description: Task-time/competitor benchmark review checks — recompute the time model from its stated formula, sum step lists vs totals, fetch the competitor help page behind headline pains, AD-semantics in "states to design"
metadata:
  type: feedback
---

On a benchmark or competitor-flow review, recompute; don't read. Script the summary table, re-derive every model time from the doc's own formula, and sum the per-task figures against the stated totals.

**Why:** T-0008 (top-20 task benchmark, 2026-10-02) looked complete and well sourced. Recomputing found three problems, and the review was rejected in round 1:
- The per-task activeDIQ "model" values silently included the 1 s/screen wait budget (2.35 s per screen, not the stated 1.35 s), so they summed to 313 s against a stated total of 277 s.
- The ME flows with the biggest headline gaps (T17, T18) listed 10–12 steps against 20–39 counted interactions, with no arithmetic shown.
- The headline pain "memberOf must be a DN" was contradicted by ME's own CSV format page; only the in-product hint said DN.

Round 2 had clean arithmetic: a table-parsing script matched every step table, and klm.py matched every total. It was still rejected:
- The doc's own screenshot (me-12) showed a hint, "Enter multiple names separated by a comma". That is a shorter ME path than the CSV import the doc counted for T11.
- Two "states to design" contradicted the threat model: activeDIQ "keeps an escrowed copy" of BitLocker keys, and "incident mode" exports 200 keys after one step-up. TM-A7 and SP §3.7 say secrets are never stored, are read one object at a time, and come back only from the reveal endpoint.
- A mock row showed "from <workstation> · via ADUC (event 4729)". Event 4729 has only the subject, the logon ID, the member and the group.

**How to apply:**
- Parse every `| # | Step | I | F | S |` table with a script and compare it with its Total row, §2 and the re-total script. Don't eyeball the sums.
- Solve for the formula's weights from 2–3 rows. If they don't match the method section, there is a hidden term.
- Grep for per-step source tags against the method's promise, and print the tasks that have none.
- WebFetch the 3–5 competitor pages behind the key takeaways. Doc-vs-product inconsistencies are themselves the pain point; cite both.
- Read **every word of the hint text** in each competitor screenshot. Hints often document a shorter path that the doc didn't count ("shortest documented path" rule).
- Check the "states to design" bullets against TM and SP, not just AD semantics. Any secret (LAPS, BitLocker, password) that is stored, exported, cached or revealed in bulk contradicts TM-A7, TM §7.4 and SP §3.7. Other AD claims to check: accountExpires is an absolute UTC FILETIME, and a Recycle Bin restore keeps all attributes.
- When a mock row cites an event ID, check that event's field list supports every value the row shows. Workstation names need Logon-ID correlation with 4624, and the tool used is never in the event.
- In round 2+, state that the listed must-fixes are the complete list, so the owner can close in one pass.

Related: [[domain-model-review-checks]], [[review-check-ceo-answers-vs-draft-time]]
