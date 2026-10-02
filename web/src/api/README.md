# `src/api`: the console's only way to the API

ADR-0004 rule 12: this directory holds the generated types and `client.ts`, and nothing else.
Outside it, `web/src/**` may not call `fetch`, `XMLHttpRequest` or `EventSource`, import an HTTP
library, or contain a string starting with `/api/`. ESLint enforces that (`web/eslint.config.js`);
`make ci-proof` proves each rule fires.

| File              | What                                                                                                       | Who writes it                                                                                |
| ----------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `schema.gen.d.ts` | `paths` and `components` types from the API bundle, open enums widened to `… \| (string & {})`             | `make gen-api` (openapi-typescript, through `web/scripts/gen-api-types.mjs`). Never by hand. |
| `client.ts`       | `api` (openapi-fetch over `paths`, base URL `/api/v1`), the CSRF header, `unwrap`, `ApiError`, `problemOf` | hand-written, the one exception                                                              |

```ts
import { api, unwrap } from "../api/client";

// Typed from the contract: the path, the method, the parameters and the response.
const page = await unwrap(api.GET("/users", { params: { query: { limit: 50 } } }));
```

A feature that needs data the contract does not offer gets an operation added to `api/openapi/`
first (blueprint §6: no private endpoints), then `make gen-api`.
