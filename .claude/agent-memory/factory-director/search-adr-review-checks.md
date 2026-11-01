---
name: search-adr-review-checks
description: Search/index ADR review — normaliser step order vs its own examples, "LIMIT bounds work" vs index order (GIN can't order), caps before scope joins leak, query text in URLs/logs
metadata:
  type: feedback
---

On a search or index ADR, test every claimed bound and fold against the index and the examples the ADR gives.

**Why:** T-1093 (ADR-0011, 2026-10-31) looked ratifiable but was rejected with 7 must-fixes:
- Its fold table was lowercase and ran before case folding, so 'Łódź'→'łodz' while 'łódź'→'lodz'. Its own example failed.
- Its 5,000-row candidate cap was "in rank order", but the ranks used columns from the joined table and key length. A GIN trigram index can't return rows in order either (PG docs: GiST yes, GIN no). So the LIMIT capped the rows returned, not the rows examined.
- The cap ran before the scope join. Hidden objects could then crowd out visible ones, and the counts were partial while shown as exact.

**How to apply:**
- Run the normaliser examples in python (unicodedata NFKC/NFD/casefold) in the stated step order, upper and lower case.
- For every "LIMIT N bounds the work": does the ORDER BY match the index's order? If not, the bound is the number of matching rows.
- Any limit applied before the scope predicate is a disclosure and a correctness bug. The scope goes first; use a separate work ceiling with an explicit, caller-independent "refine" state.
- Refusals (secret shapes, length caps) run after NFKC. Query text stays out of URLs and logs.
- Fitness checks that ban LIKE/regex must also ban the trigram operators outside the one template, and views or functions in migrations that read the RBAC tables.
- Re-review: grep main for the new fitness bans before ratifying. T-1093 rev 2's `%` ban hit plpgsql RAISE placeholders, its literal-true set_config hit the SQL-14 probe, and its trigger allow-list left out 0037. Those are nits for the fitness ticket, not a reject.
- A security-architect consult paid off again. Verify its code citations (one was weaker than claimed: Connections() is documented as not RP2-restricted).

Related: [[stored-result-contract-review-checks]], [[erratum-guards-vs-own-examples]]
