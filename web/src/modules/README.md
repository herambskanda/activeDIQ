# `src/modules`: screen modules

One directory per web module (`objects`, `helpdesk`, …), each registering its routes through the
`Registrar` in `src/app/modules.ts` (EP-15). Only `src/app/modules.gen.ts` names a module (edited
by hand until `tools/gen/modules` exists).

| Module      | Routes             | Reads                       |
| ----------- | ------------------ | --------------------------- |
| `directory` | `/directory/users` | `searchDirectoryUsers` only |
