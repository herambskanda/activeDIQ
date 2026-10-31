# `src/modules`: screen modules

One directory per web module (`objects`, `helpdesk`, …), each registering its routes, palette
entries (`r.palette({ id, label, keywords, route })`) and search-result renderers
(`r.searchResults(type, renderer)`) through the `Registrar` in `src/app/modules.ts` (EP-15).
`collectContributions` returns them; start-up throws on a duplicate palette ID or result type and on
a palette entry whose route no module registered. ESLint (rule 8) bars `src/app` and `src/ds` from
importing a module and bars one module from importing another. Only `src/app/modules.gen.ts` names a module (edited
by hand until `tools/gen/modules` exists).

| Module      | Routes             | Palette                                   | Reads                       |
| ----------- | ------------------ | ----------------------------------------- | --------------------------- |
| `directory` | `/directory/users` | `directory.search-users` ("Search users") | `searchDirectoryUsers` only |
