import js from "@eslint/js";
import tseslint from "typescript-eslint";

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
);
