import { describe, it } from "vitest";
import { RuleTester } from "eslint";
import plugin from "./safe-primitives.js";

RuleTester.describe = describe;
RuleTester.it = it;
RuleTester.itOnly = it.only;

const tester = new RuleTester({
  languageOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
    parserOptions: { ecmaFeatures: { jsx: true } },
  },
});

const run = (name, valid, invalid) => tester.run(name, plugin.rules[name], { valid, invalid });
const err = (n = 1) => Array.from({ length: n }, () => ({ message: /^FF-SP3/ }));

run(
  "no-hand-built-security-string",
  [
    "const a = `(${x})`;",
    "const a = 'plain text ' + x;",
    "const a = `hello ${name}`;",
    "const a = '(&(objectClass=user))';", // a constant is not built
    "const a = 'CN=' + 'x';",
    "const t = `Select all ${n} rows`;", // prose, not SQL
    "const base = '(&(a=b)'; const more = base + '(x=y)';", // constants only
    "let s = 'hello '; s += name;", // not a shape
    "const a = ['plain', x].join(',');",
    "const p = 'progress %s of 10'.replace('%s', n);", // not a security shape
    "const a = 'a'.concat(x);",
  ],
  [
    { code: "const f = `(&(objectClass=user)(cn=${x}))`;", errors: err() },
    { code: "const f = '(&(objectClass=user)(cn=' + x + '))';", errors: err() },
    { code: "const f = `(userAccountControl:1.2.840.113556.1.4.803:=${x})`;", errors: err() },
    { code: "const d = `CN=${name},OU=Staff,DC=corp`;", errors: err() },
    { code: "const d = 'CN=' + name + ',' + parent;", errors: err() },
    { code: "const c = `Get-ADUser -Identity '${u}'`;", errors: err() },
    { code: "const q = 'SELECT id FROM users WHERE name = ' + n;", errors: err() },
    { code: "const q = `DELETE FROM ${t} WHERE id = 1`;", errors: err() },
    // Review rework: the other ordinary spellings.
    { code: "let s = '(&(objectClass=user)(cn='; s += x; s += '))';", errors: err() },
    { code: "let s = ''; s += '(&(objectClass=user)(cn='; s += x;", errors: err() },
    { code: "const f = '(&(objectClass=user)(cn='.concat(x, '))');", errors: err() },
    { code: "const f = ''.concat('(&(objectClass=user)(cn=', x, '))');", errors: err() },
    { code: "const f = ['(&(objectClass=user)(cn=', x, '))'].join('');", errors: err() },
    { code: "const tpl = '(&(objectClass=user)(cn=%s))'; use(tpl, x);", errors: err() },
    { code: "const f = '(&(objectClass=user)(cn={name}))'.replace('{name}', x);", errors: err() },
    { code: "const pre = '(&(objectClass=user)(cn='; const f = pre + x + '))';", errors: err() },
    { code: "let s = 'CN='; s = s + name;", errors: err() },
    { code: "let q = 'SELECT id FROM users WHERE name = '; q += n;", errors: err() },
    { code: "const c = ['Get-ADUser -Identity', u].join(' ');", errors: err() },
  ],
);

run(
  "no-quote-doubling",
  [
    "s.replace(/a/g, 'b');",
    "s.replace(/'/g, '');",
    "s.replaceAll('a', 'aa');",
    "s.replace(/'/g, '\\\\\\'');",
  ],
  [
    { code: "s.replace(/'/g, \"''\");", errors: err() },
    { code: 's.replaceAll("\'", "\'\'");', errors: err() },
    { code: 's.replace(/[‘’]/g, "’’");', errors: err() },
  ],
);

run(
  "no-dn-string-ops",
  [
    "dn.length;",
    "name.split(',');",
    "user.dn.toString();",
    "children.includes(x);",
    "blend.endsWith('x');",
  ],
  [
    { code: "dn.split(',');", errors: err() },
    { code: "node.distinguishedName.endsWith(ou);", errors: err() },
    { code: "parentDn.includes('OU=x');", errors: err() },
    { code: "row.targetDN.startsWith(x);", errors: err() },
  ],
);

run(
  "no-export-media-types",
  ["new Blob(['x'], { type: 'text/plain' });"],
  [
    { code: "new Blob([rows.join('\\n')], { type: 'text/csv' });", errors: err() },
    {
      code: "const t = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';",
      errors: err(),
    },
    { code: "const u = `data:text/csv;base64,${b}`;", errors: err() },
  ],
);

run(
  "no-unsafe-dom-sinks",
  ["setTimeout(fn, 10);", "<iframe src='/x' />;", "el.write(x);", "document.title = 'x';"],
  [
    { code: "el.insertAdjacentHTML('beforeend', h);", errors: err() },
    { code: "document.write(h);", errors: err() },
    { code: "setTimeout('run()', 1);", errors: err() },
    { code: "setInterval(`run(${x})`, 1);", errors: err() },
    { code: "<iframe srcDoc={h} />;", errors: err() },
  ],
);

run(
  "safe-url-attributes",
  [
    "<a href='/users'>x</a>;",
    "<a href={'/users'}>x</a>;",
    "<a href={`/users`}>x</a>;",
    "<a href={safeLink.href}>x</a>;",
    "import logo from './logo.svg'; <img src={logo} />;",
    "<a>no href</a>;",
  ],
  [
    { code: "<a href={u.wWWHomePage}>x</a>;", errors: err() },
    { code: "<img src={x.url} />;", errors: err() },
    { code: "<a href={`/u/${id}`}>x</a>;", errors: err() },
    { code: "const url = get(); <a href={url}>x</a>;", errors: err() },
  ],
);
