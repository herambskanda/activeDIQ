// Blueprint §2 rule 8 (ADR-0003): the web shell and the design system never import a web module, and
// one web module never imports another. The shell reads what modules register from the collected
// registration (collectContributions in src/app/modules.ts); only src/app/modules.gen.ts names a
// module (it is exempted in eslint.config.js).
//
// The rule resolves every relative or absolute import against the importing file and checks where it
// lands, so nesting depth and `../../modules/<other>` spellings cannot slip past. Bare specifiers
// (packages) can never reach src/modules: the project defines no path alias or workspace for it.

import path from "node:path";

const norm = (p) => p.split(path.sep).join("/");

function moduleOf(file, modulesRoot) {
  if (!file.startsWith(modulesRoot + "/")) return null;
  const rest = file.slice(modulesRoot.length + 1);
  return rest.includes("/") ? rest.slice(0, rest.indexOf("/")) : "";
}

const rule = {
  meta: {
    type: "problem",
    schema: [
      {
        type: "object",
        properties: { srcRoot: { type: "string" } },
        additionalProperties: false,
      },
    ],
    messages: {
      fromShell:
        "Rule 8: src/app and src/ds never import src/modules; read the collected registration (collectContributions). Only modules.gen.ts names a module.",
      betweenModules:
        "Rule 8: a web module never imports another module ({{ from }} -> {{ to }}); share through src/app or src/ds.",
      modulesRoot:
        "Rule 8: a web module never imports the src/modules root; share through src/app or src/ds.",
    },
  },
  create(context) {
    const srcRoot = norm(path.resolve(context.cwd, context.options[0]?.srcRoot ?? "src"));
    const modulesRoot = srcRoot + "/modules";
    const file = norm(path.resolve(context.filename));
    const self = moduleOf(file, modulesRoot);

    function check(node, source) {
      if (typeof source !== "string" || !(source.startsWith(".") || path.isAbsolute(source))) {
        return;
      }
      const target = norm(path.resolve(path.dirname(file), source));
      const inModules = target === modulesRoot || target.startsWith(modulesRoot + "/");
      if (!inModules) return;
      const to = target === modulesRoot ? "" : target.slice(modulesRoot.length + 1).split("/")[0];
      if (self === null) {
        context.report({ node, messageId: "fromShell" });
      } else if (to === "") {
        context.report({ node, messageId: "modulesRoot" });
      } else if (to !== self) {
        context.report({ node, messageId: "betweenModules", data: { from: self, to } });
      }
    }

    const literal = (n) => (n && n.type === "Literal" ? n.value : undefined);
    return {
      ImportDeclaration: (n) => check(n.source, n.source.value),
      ExportAllDeclaration: (n) => check(n.source, n.source.value),
      ExportNamedDeclaration: (n) => n.source && check(n.source, n.source.value),
      ImportExpression: (n) => check(n.source, literal(n.source)),
      CallExpression: (n) => {
        if (n.callee.type === "Identifier" && n.callee.name === "require") {
          check(n.arguments[0], literal(n.arguments[0]));
        }
      },
    };
  },
};

export default { rules: { "module-boundary": rule } };
