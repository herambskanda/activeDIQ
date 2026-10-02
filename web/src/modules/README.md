# `src/modules`: screen modules

One directory per web module (`objects`, `helpdesk`, …), each registering its routes through the
`Registrar` in `src/app/modules.ts` (EP-15). Only the generated `src/app/modules.gen.ts`, added with
the first module, names a module. No module exists yet.
