---
name: descendant-dn-lessons
description: T-0988 descendant dn rewrite on move — order trap, key delete/insert trap, dn.Rebase
metadata:
  type: project
---

- Run the dn pass BEFORE the ancestry UPDATE: a chain over 128 hops is emptied, and then `ancestry @> moved` no longer finds the row.
- dn swap is by RDN position (`dn.Rebase(d, keep=hops, newParentDN)`), so a descendant already carrying the new dn is unchanged (idempotent in a batch).
- Search-key swap in one statement: the DELETE must spare keys the INSERT wants (as writeSearchKeysSQL), else a new dn normalising to the old key is deleted and lost to ON CONFLICT.
- Rebase renders canonically; moved rows' dn text may differ in escaping from DC output.
- Inventory package tests take ~70 s per focused run; full package runs exceed the 120 s foreground limit — background them.
