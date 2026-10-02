// FF-SP3 for the web console (tier W): knowledge/development/architecture/safe-primitives.md §2.1, §6.2,
// §12.3 and §12.5 (W1, W2). Tier W implements no primitive: it never parses, builds or escapes a
// filter, DN, PowerShell or SQL text, and it never assembles an export. These rules make the second
// copy of a primitive a lint error. Every message starts with "FF-SP3" so the CI log names the check.
// Test files and web/e2e are not linted by this plugin (see eslint.config.js).

const FILTER_SHAPE =
  /\(\s*[&|!]\s*\(|\(\s*(?:objectClass|objectCategory|sAMAccountName|userPrincipalName|memberOf|distinguishedName|objectSid|objectGUID)\s*[=~<>:]|:1\.2\.840\.113556\.1\.4\.\d+:=/i;
const DN_SHAPE = /(?:^|[,\s])(?:CN|OU|DC)=/;
const POWERSHELL_SHAPE =
  /\b(?:Get|Set|New|Remove|Add|Disable|Enable|Unlock|Reset|Move|Rename|Invoke|Start|Stop|Import|Export|Search|Clear|Grant|Revoke|Test)-(?:AD|Mailbox|Recipient|DistributionGroup|Gpo|GP[A-Z]|Acl|Item|Content|Process|Service|Command|Expression|Object|Variable|Module|ExecutionPolicy|LocalUser|LocalGroup|Computer)\w*|\s-(?:Identity|LDAPFilter|SearchBase|ArgumentList|ScriptBlock|EncodedCommand)\b/i;
const SQL_SHAPE =
  /\b(?:select\b[\s\S]+\bfrom|insert\s+into|update\s+[\w."]+\s+set|delete\s+from|alter\s+(?:table|role|user)|drop\s+(?:table|role|user))\b|\bwhere\s+[\w."()]+\s*(?:=|<|>|like|ilike|in|is)\b/i;

const SHAPES = [
  [
    "an LDAP filter",
    FILTER_SHAPE,
    "the server returns the filter AST and its canonical text (§2.1)",
  ],
  ["a distinguished name", DN_SHAPE, "the API returns rdns and a display-only dn (§2.1)"],
  [
    "PowerShell text",
    POWERSHELL_SHAPE,
    "the server returns DisplayOnlyPowerShell rendered by pslit (§6.2)",
  ],
  ["SQL text", SQL_SHAPE, "the console sends report ASTs, never SQL (§2.1)"],
];

const QUOTES = /^['‘’‚‛]$/;
const DN_NAME = /^(?:dn|distinguishedName|[a-z0-9_]*[a-z0-9](?:Dn|DN)|[a-z0-9]+_dn)$/;
const DN_METHODS = new Set([
  "split",
  "endsWith",
  "startsWith",
  "includes",
  "indexOf",
  "lastIndexOf",
  "slice",
  "substring",
]);

function shapeOf(text) {
  for (const [what, re, instead] of SHAPES) if (re.test(text)) return { what, instead };
  return null;
}

function stringValue(node) {
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  return null;
}

// Leaves of a `+` chain.
function flattenAdd(node, out) {
  if (node.type === "BinaryExpression" && node.operator === "+") {
    flattenAdd(node.left, out);
    flattenAdd(node.right, out);
  } else out.push(node);
  return out;
}

// A format placeholder inside a literal: printf verbs and {name} / {0} template slots.
const PLACEHOLDER = /%[sdiqxjoO]|\{[A-Za-z0-9_]*\}/;
// Methods that assemble or substitute text.
const JOIN_METHODS = new Set([
  "concat",
  "join",
  "replace",
  "replaceAll",
  "padEnd",
  "padStart",
  "repeat",
]);

const noHandBuiltSecurityString = {
  meta: {
    type: "problem",
    schema: [],
    messages: {
      built:
        "FF-SP3: {{what}} is built from a template literal, concatenation, += append, concat/join or a format placeholder. Tier W builds none of these: {{instead}}.",
    },
  },
  create(context) {
    const reported = new WeakSet();
    const report = (node, shape) => {
      if (reported.has(node)) return;
      reported.add(node);
      context.report({ node, messageId: "built", data: shape });
    };
    // name -> { lits: string-literal nodes bound to it, isConst } for `const s = "..."`, `s = "..."`.
    const bound = new Map();
    const bind = (name, init, isConst) => {
      if (!init || stringValue(init) === null) return;
      const entry = bound.get(name) ?? { lits: [], isConst };
      entry.lits.push(init);
      entry.isConst = entry.isConst && isConst;
      bound.set(name, entry);
    };
    // The string literals a node is, or names: where a shape literal might sit.
    const litsOf = (node) => {
      if (stringValue(node) !== null) return [node];
      if (node.type === "Identifier") return bound.get(node.name)?.lits ?? [];
      return [];
    };
    const isStatic = (node) =>
      stringValue(node) !== null ||
      (node.type === "TemplateLiteral" && node.expressions.length === 0) ||
      (node.type === "Identifier" && bound.get(node.name)?.isConst === true);
    const reportShapes = (nodes) => {
      for (const n of nodes)
        for (const l of litsOf(n)) {
          const shape = shapeOf(stringValue(l));
          if (shape) report(l, shape);
        }
    };
    return {
      VariableDeclarator(node) {
        if (node.id.type === "Identifier")
          bind(node.id.name, node.init, node.parent.kind === "const");
      },
      Literal(node) {
        // A shape literal that is a format template is built text wherever it is used.
        const v = stringValue(node);
        if (v === null || !PLACEHOLDER.test(v)) return;
        const shape = shapeOf(v);
        if (shape) report(node, shape);
      },
      TemplateLiteral(node) {
        if (node.expressions.length === 0) return;
        const text = node.quasis.map((q) => q.value.cooked ?? q.value.raw).join("\u0000");
        const shape = shapeOf(text);
        if (shape) report(node, shape);
      },
      AssignmentExpression(node) {
        if (node.operator === "=" && node.left.type === "Identifier")
          bind(node.left.name, node.right, false);
        if (node.operator !== "+=") return;
        // s += x and s += "(cn=": appending is building. Judge the added piece and what s holds.
        reportShapes([node.right]);
        if (node.left.type === "Identifier") reportShapes([node.left]);
      },
      BinaryExpression(node) {
        if (
          node.operator !== "+" ||
          (node.parent.type === "BinaryExpression" && node.parent.operator === "+")
        )
          return;
        const leaves = flattenAdd(node, []);
        if (leaves.every(isStatic)) return;
        reportShapes(leaves);
      },
      CallExpression(node) {
        const callee = node.callee;
        if (
          callee.type !== "MemberExpression" ||
          callee.computed ||
          !JOIN_METHODS.has(callee.property.name)
        )
          return;
        let pieces;
        if (callee.property.name === "join" && callee.object.type === "ArrayExpression") {
          pieces = callee.object.elements.filter(Boolean);
        } else if (callee.property.name === "join") {
          return;
        } else {
          pieces = [callee.object, ...node.arguments];
        }
        if (pieces.every(isStatic)) return;
        reportShapes(pieces);
      },
    };
  },
};

const noQuoteDoubling = {
  meta: {
    type: "problem",
    schema: [],
    messages: {
      doubling:
        "FF-SP3: quote doubling is the PatchIQ escapePSPath bug (PSQ-06). The console never quotes PowerShell: show the server's DisplayOnlyPowerShell (§6.2).",
    },
  },
  create(context) {
    return {
      CallExpression(node) {
        const callee = node.callee;
        if (callee.type !== "MemberExpression" || callee.computed || node.arguments.length < 2)
          return;
        if (callee.property.name !== "replace" && callee.property.name !== "replaceAll") return;
        const [from, to] = node.arguments;
        const replacement = stringValue(to);
        if (
          replacement === null ||
          replacement.length < 2 ||
          ![...replacement].every((c) => QUOTES.test(c))
        )
          return;
        const fromText =
          from.type === "Literal" && from.regex ? from.regex.pattern : stringValue(from);
        if (fromText !== null && [...fromText].some((c) => QUOTES.test(c) || c === "[")) {
          context.report({ node, messageId: "doubling" });
        }
      },
    };
  },
};

function nameOf(node) {
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression" && !node.computed && node.property.type === "Identifier")
    return node.property.name;
  return null;
}

const noDnStringOps = {
  meta: {
    type: "problem",
    schema: [],
    messages: {
      dn: "FF-SP3: string operation .{{method}}() on a DN value. Never split or match a DN in the console: use the server's rdns and guid (§2.1).",
    },
  },
  create(context) {
    return {
      CallExpression(node) {
        const callee = node.callee;
        if (
          callee.type !== "MemberExpression" ||
          callee.computed ||
          callee.property.type !== "Identifier"
        )
          return;
        const method = callee.property.name;
        if (!DN_METHODS.has(method)) return;
        const name = nameOf(callee.object);
        if (name !== null && DN_NAME.test(name))
          context.report({ node, messageId: "dn", data: { method } });
      },
    };
  },
};

const noExportMediaTypes = {
  meta: {
    type: "problem",
    schema: [],
    messages: {
      media:
        "FF-SP3: a CSV or XLSX media type in the console. The console never assembles download content; Export and copy-rows call the server (§12.5 W5, §12.3).",
    },
  },
  create(context) {
    return {
      Literal(node) {
        const s = stringValue(node);
        if (s !== null && /text\/csv|spreadsheetml/i.test(s))
          context.report({ node, messageId: "media" });
      },
      TemplateElement(node) {
        if (/text\/csv|spreadsheetml/i.test(node.value.raw))
          context.report({ node, messageId: "media" });
      },
    };
  },
};

const noUnsafeDomSinks = {
  meta: {
    type: "problem",
    schema: [],
    messages: {
      sink: "FF-SP3: {{what}} is a raw HTML or code sink (W1). Render server-built values as text through React.",
    },
  },
  create(context) {
    const isStringArg = (arg) =>
      arg !== undefined &&
      ((arg.type === "Literal" && typeof arg.value === "string") || arg.type === "TemplateLiteral");
    return {
      CallExpression(node) {
        const c = node.callee;
        if (c.type === "MemberExpression" && !c.computed && c.property.type === "Identifier") {
          if (c.property.name === "insertAdjacentHTML")
            context.report({ node, messageId: "sink", data: { what: "insertAdjacentHTML" } });
          if (
            (c.property.name === "write" || c.property.name === "writeln") &&
            c.object.type === "Identifier" &&
            c.object.name === "document"
          )
            context.report({ node, messageId: "sink", data: { what: "document.write" } });
        }
        if (
          c.type === "Identifier" &&
          (c.name === "setTimeout" || c.name === "setInterval") &&
          isStringArg(node.arguments[0])
        )
          context.report({ node, messageId: "sink", data: { what: `${c.name} with a string` } });
      },
      JSXAttribute(node) {
        if (node.name.type === "JSXIdentifier" && node.name.name === "srcDoc")
          context.report({ node, messageId: "sink", data: { what: "srcDoc" } });
      },
    };
  },
};

// W2: href and src take a literal, a router link, or a server-built SafeLink's href. User-editable
// URL attributes display as text, never as anchors.
const safeUrlAttributes = {
  meta: {
    type: "problem",
    schema: [],
    messages: {
      url: "FF-SP3: {{attr}} is not a literal, an imported asset or a SafeLink href (W2). Show user-editable URLs as text, or use <SafeLink>.",
    },
  },
  create(context) {
    const isSafeExpr = (expr) => {
      if (expr.type === "Literal") return true;
      if (expr.type === "TemplateLiteral") return expr.expressions.length === 0;
      if (expr.type === "MemberExpression" && !expr.computed && expr.property.name === "href") {
        const base = nameOf(expr.object);
        return base !== null && /^safeLink$/i.test(base);
      }
      if (expr.type === "Identifier") {
        let scope = context.sourceCode.getScope(expr);
        while (scope) {
          const v = scope.set.get(expr.name);
          if (v) return v.defs.some((d) => d.type === "ImportBinding");
          scope = scope.upper;
        }
      }
      return false;
    };
    return {
      JSXAttribute(node) {
        if (
          node.name.type !== "JSXIdentifier" ||
          (node.name.name !== "href" && node.name.name !== "src")
        )
          return;
        const v = node.value;
        if (v === null || v.type === "Literal") return;
        if (
          v.type === "JSXExpressionContainer" &&
          v.expression.type !== "JSXEmptyExpression" &&
          isSafeExpr(v.expression)
        )
          return;
        context.report({ node, messageId: "url", data: { attr: node.name.name } });
      },
    };
  },
};

export default {
  meta: { name: "safe-primitives" },
  rules: {
    "no-hand-built-security-string": noHandBuiltSecurityString,
    "no-quote-doubling": noQuoteDoubling,
    "no-dn-string-ops": noDnStringOps,
    "no-export-media-types": noExportMediaTypes,
    "no-unsafe-dom-sinks": noUnsafeDomSinks,
    "safe-url-attributes": safeUrlAttributes,
  },
};
