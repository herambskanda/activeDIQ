---
name: sd-write-lessons
description: sd.write (T-0583) — corpus gate runs one named test per implementation, oracle pitfalls, insert-position rule
metadata:
  type: feedback
---

- The FF-SP4 gate runs only `-run ^<testName>$` per implementation; a second unit's `corpustest.Run` must be called from that same test (here `TestCorpus` calls `corpusWrite`). A separate TestCorpusWrite gives `no-report`.
- Each unit needs its own FF-SP5 fuzz entry (`corpustest.Seed(f, "<unit>")` first); units outside `requiredProps` need only one property.
- `python3 -I` generators cannot import siblings: copy helpers.
- Whole-object ACE inserts before the first scoped ACE of the same decision type (not at the block end); oracle got this wrong first.
- Pre-existing red at this time: dn/cellsafe/csv/xlsx FF-SP4 undeclared-implementation.
**Why:** cost several debugging rounds. **How to apply:** adding any new corpus unit to an existing implementation.
