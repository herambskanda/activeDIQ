import js from "@eslint/js";
import tseslint from "typescript-eslint";
import safePrimitives from "./eslint/safe-primitives.js";

export default tseslint.config(
  // proof/ holds deliberate violations that `make ci-proof` lints with --no-ignore.
  { ignores: ["dist/**", "node_modules/**", "proof/**"] },
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
    // Tier W implements no security primitive (blueprint §6): React escapes by default and the
    // console never sets raw HTML.
    files: ["src/**/*.{ts,tsx}", "proof/**/*.ts"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: "dangerouslySetInnerHTML is banned: render server-built values as text.",
        },
        {
          selector: "AssignmentExpression[left.property.name=/^(innerHTML|outerHTML)$/]",
          message: "Assigning innerHTML/outerHTML is banned: render server-built values as text.",
        },
      ],
    },
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
