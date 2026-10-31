import { describe, it } from "vitest";
import path from "node:path";
import { RuleTester } from "eslint";
import plugin from "./module-boundary.js";

RuleTester.describe = describe;
RuleTester.it = it;
RuleTester.itOnly = it.only;

const tester = new RuleTester({
  languageOptions: { ecmaVersion: "latest", sourceType: "module" },
});

const at = (rel) => path.resolve("src", rel);
const ok = (filename, code) => ({ filename: at(filename), code });
const bad = (filename, code, messageId) => ({
  filename: at(filename),
  code,
  errors: [{ messageId }],
});

tester.run("module-boundary", plugin.rules["module-boundary"], {
  valid: [
    // a module's own files, at any depth, and the shell/ds it may share through
    ok("modules/directory/a.ts", "import x from './b';"),
    ok("modules/directory/sub/a.ts", "import x from '../b';"),
    ok("modules/directory/sub/deep/a.ts", "import x from '../../b';"),
    ok("modules/directory/a.ts", "import x from '../../app/modules';"),
    ok("modules/directory/sub/a.ts", "import x from '../../../ds/button';"),
    ok("modules/directory/a.ts", "import x from '../../modules/directory/b';"), // its own folder
    ok("modules/directory/a.ts", "import x from 'react';"),
    // the shell and ds importing their own files
    ok("app/shell.tsx", "import x from './modules';"),
    ok("app/shell.tsx", "import x from '../ds/button';"),
    ok("ds/button.tsx", "import x from '../app/x';"),
  ],
  invalid: [
    bad("modules/directory/a.ts", "import x from '../other/x';", "betweenModules"),
    bad("modules/directory/a.ts", "import x from '../../modules/other/x';", "betweenModules"),
    bad("modules/directory/sub/a2.ts", "import x from '../../other/x';", "betweenModules"),
    bad("modules/directory/sub/deep/a.ts", "import x from '../../../other/x';", "betweenModules"),
    bad("modules/directory/sub/a.ts", "import x from '../../../modules/other';", "betweenModules"),
    bad("modules/directory/a.ts", "export * from '../other/x';", "betweenModules"),
    bad("modules/directory/a.ts", "export { y } from '../other/x';", "betweenModules"),
    bad("modules/directory/a.ts", "const m = import('../other/x');", "betweenModules"),
    bad("modules/directory/a.ts", "const m = require('../other/x');", "betweenModules"),
    bad("modules/directory/a.ts", `import x from '${at("modules/other/x")}';`, "betweenModules"),
    bad("modules/directory/a.ts", "import x from '..';", "modulesRoot"),
    bad("modules/directory/sub/a.ts", "import x from '../..';", "modulesRoot"),
    bad("app/shell.tsx", "import x from '../modules/directory';", "fromShell"),
    bad("app/shell.tsx", "import x from '../modules';", "fromShell"),
    bad("app/nested/x.ts", "import x from '../../modules/directory/index';", "fromShell"),
    bad("ds/button.tsx", "import x from '../modules/directory/index';", "fromShell"),
  ],
});
