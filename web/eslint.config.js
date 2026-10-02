import js from "@eslint/js";
import tseslint from "typescript-eslint";
import safePrimitives from "./eslint/safe-primitives.js";

// Tier W implements no security primitive (blueprint §6): React escapes by default and the console
// never sets raw HTML.
const rawHtmlSyntax = [
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: "dangerouslySetInnerHTML is banned: render server-built values as text.",
  },
  {
    selector: "AssignmentExpression[left.property.name=/^(innerHTML|outerHTML)$/]",
    message: "Assigning innerHTML/outerHTML is banned: render server-built values as text.",
  },
];

// ADR-0004 rule 12: the console reaches the API through the generated client only. Outside
// src/api/, source may not call fetch, XMLHttpRequest or EventSource, import an HTTP library, or
// contain a string that starts with /api/. A feature that needs data gets an operation in the
// contract first (blueprint §6: no private endpoints).
const networkGlobals = ["fetch", "XMLHttpRequest", "EventSource"];
const httpLibraries = [
  "axios",
  "ky",
  "got",
  "superagent",
  "node-fetch",
  "cross-fetch",
  "isomorphic-fetch",
  "whatwg-fetch",
  "ofetch",
  "undici",
  "openapi-fetch",
];
const apiClientMessage =
  "Call the API through the generated client in src/api/ (ADR-0004 rule 12).";
const httpLibraryPattern = `^(${httpLibraries.join("|")})(/.*)?$`;
// esquery regexes cannot hold an unescaped slash, so the dynamic-import selectors match the bare name.
const httpLibraryName = `^(${httpLibraries.join("|")})$`;
const apiClientSyntax = [
  {
    selector: `MemberExpression[object.name=/^(window|globalThis|self)$/][property.name=/^(${networkGlobals.join("|")})$/]`,
    message: apiClientMessage,
  },
  {
    selector: "Literal[value=/^\\/api(\\/|$)/]",
    message: "No string starting with /api/: " + apiClientMessage,
  },
  {
    selector: "TemplateLiteral > TemplateElement:first-child[value.cooked=/^\\/api(\\/|$)/]",
    message: "No template starting with /api/: " + apiClientMessage,
  },
  {
    selector: `ImportExpression > Literal[value=/${httpLibraryName}/]`,
    message: "No HTTP library: " + apiClientMessage,
  },
  {
    selector: `CallExpression[callee.name='require'] > Literal[value=/${httpLibraryName}/]`,
    message: "No HTTP library: " + apiClientMessage,
  },
];

export default tseslint.config(
  // proof/ holds deliberate violations that `make ci-proof` lints with --no-ignore. The generated
  // schema is openapi-typescript's output, not ours to lint.
  { ignores: ["dist/**", "node_modules/**", "proof/**", "src/api/schema.gen.d.ts"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ["src/**/*.{ts,tsx}", "proof/**/*.ts"],
    rules: {
      "no-console": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/consistent-type-imports": "error",
    },
  },
  {
    files: ["src/**/*.{ts,tsx}", "proof/**/*.ts"],
    rules: {
      "no-restricted-syntax": ["error", ...rawHtmlSyntax],
    },
  },
  {
    // Rule 12. This block restates the raw-HTML selectors because a later no-restricted-syntax
    // setting replaces an earlier one rather than adding to it.
    files: ["src/**/*.{ts,tsx}", "proof/**/*.ts"],
    ignores: ["src/api/**"],
    rules: {
      "no-restricted-globals": [
        "error",
        ...networkGlobals.map((name) => ({ name, message: apiClientMessage })),
      ],
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            { regex: httpLibraryPattern, message: "No HTTP library: " + apiClientMessage },
          ],
        },
      ],
      "no-restricted-syntax": ["error", ...rawHtmlSyntax, ...apiClientSyntax],
    },
  },
  {
    // Build-time Node scripts (the API type generator).
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: { process: "readonly", console: "readonly" } },
  },
  {
    // FF-SP3 for tier W (safe-primitives §2.1, §6.2, §12.3, §12.5): the console builds no filter, DN,
    // PowerShell, SQL or export text, and sets no raw HTML sink. Messages start with "FF-SP3".
    // Test files may carry hostile strings on purpose.
    files: ["src/**/*.{ts,tsx}", "proof/**/*.ts"],
    ignores: ["**/*.test.{ts,tsx}"],
    plugins: { "safe-primitives": safePrimitives },
    rules: {
      "safe-primitives/no-hand-built-security-string": "error",
      "safe-primitives/no-quote-doubling": "error",
      "safe-primitives/no-dn-string-ops": "error",
      "safe-primitives/no-export-media-types": "error",
      "safe-primitives/no-unsafe-dom-sinks": "error",
      "safe-primitives/safe-url-attributes": "error",
      "no-script-url": "error",
    },
  },
);
