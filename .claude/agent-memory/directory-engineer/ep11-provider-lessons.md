---
name: ep11-provider-lessons
description: T-1005 EP-11 extraction - lab run traps on a loaded host, facet design choices
metadata:
  type: reference
---

- Handlers assert facets (DCBound, ObjectReader, RightsSource) on provider.Provider at construction; `refusal` pkg exists so read/rights need not import write.
- Lab on a loaded host (load >10): run lab packages one at a time with `-timeout 9m -run`; a whole-package run times out (rights Refusals ~215 s, read 1600-user seeding test can exceed 9 min).
- Lab tests fail in 0.00s with "lab CA missing" when `make lab-up` was killed early; rerun it and wait for lab/.lab-ca.pem.
- compose/server lab tests hang in storetest Postgres cleanup when many containers run; not caused by the connector.
