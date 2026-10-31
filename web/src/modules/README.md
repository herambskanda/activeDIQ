# `src/modules`: screen modules

One directory per web module (`objects`, `helpdesk`, …), each registering its routes through the
`Registrar` in `src/app/modules.ts` (EP-15). Only `src/app/modules.gen.ts` names a module (edited
by hand until `tools/gen/modules` exists).

| Module      | Routes                   | Reads                                                                                                                                       |
| ----------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `directory` | `/directory/users`       | `searchDirectoryUsers` only                                                                                                                 |
| `reports`   | `/reports`, `/reports/*` | `listReportDefinitions`, `getReportDefinition`, `createReportRun`, `getReportRun`, `cancelReportRun`, `retryReportRun`, `listReportRunRows` |

Routes end in `/*` for a prefix match (`matchRoute` in `src/app/modules.ts`: an exact path wins, then
the longest prefix). Screens move between routes with `navigate()` and read the URL with
`useLocation()` from `src/app/location.ts` (pushState plus a synthetic `popstate`, so back and
forward work); every report view (preset, period, columns, filters, sort, hidden-account choice) is in
the URL: `/reports/<id>?preset=&days=&cols=&f=col:op:value&svc=1&sort=&order=`.
