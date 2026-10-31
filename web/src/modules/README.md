# `src/modules`: screen modules

One directory per web module (`objects`, `helpdesk`, …), each registering its routes, palette
entries (`r.palette({ id, label, keywords, route })`) and search-result renderers
(`r.searchResults(type, renderer)`) through the `Registrar` in `src/app/modules.ts` (EP-15).
`collectContributions` returns them; start-up throws on a duplicate palette ID or result type and on
a palette entry whose route no module registered. ESLint (rule 8, `eslint/module-boundary.js`) resolves
every import against the importing file, so it bars `src/app` and `src/ds` from importing a module
and bars one module from importing another at any folder depth. Only `src/app/modules.gen.ts` names a
module (edited by hand until `tools/gen/modules` exists).

| Module      | Routes                   | Palette                                   | Reads                                                                                                                                       |
| ----------- | ------------------------ | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `directory` | `/directory/users`       | `directory.search-users` ("Search users") | `searchDirectoryUsers` only                                                                                                                 |
| `reports`   | `/reports`, `/reports/*` | none (its own `/` search)                 | `listReportDefinitions`, `getReportDefinition`, `createReportRun`, `getReportRun`, `cancelReportRun`, `retryReportRun`, `listReportRunRows` |

Routes end in `/*` for a prefix match (`matchRoute` in `src/app/modules.ts`: an exact path wins, then
the longest prefix). Screens move between routes with `navigate()` and read the URL with
`useLocation()` from `src/app/location.ts` (pushState plus a synthetic `popstate`, so back and
forward work); every report view (preset, period, columns, filters, sort, hidden-account choice) is in
the URL: `/reports/<id>?preset=&days=&cols=&f=col:op:value&svc=1&sort=&order=`.
