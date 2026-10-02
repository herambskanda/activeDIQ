// A deliberately small YAML-frontmatter reader: top-level `key: value` pairs, quoted strings and
// block scalars. Enough for agent definitions and knowledge-base documents; nothing else.

/**
 * Split a markdown document into frontmatter data and body.
 * @param {string} text
 * @returns {{data: Record<string, string>, body: string}}
 */
export function parseFrontmatter(text) {
  const match = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(text);
  if (!match) return { data: {}, body: text };
  return { data: parseBlock(match[1]), body: text.slice(match[0].length) };
}

function unquote(value) {
  const v = value.trim();
  if (v.length >= 2 && ((v[0] === '"' && v.endsWith('"')) || (v[0] === "'" && v.endsWith("'")))) return v.slice(1, -1);
  return v;
}

function parseBlock(block) {
  const data = {};
  let key = null;
  let first = '';
  let continuation = [];

  const flush = () => {
    if (key === null) return;
    const indicator = /^([|>])[+-]?$/.exec(first);
    if (indicator) {
      const lines = continuation.map((l) => l.trim());
      data[key] = (indicator[1] === '|' ? lines.join('\n') : lines.join(' ')).trim();
    } else {
      data[key] = unquote([first, ...continuation.map((l) => l.trim())].filter(Boolean).join(' '));
    }
    key = null;
  };

  for (const line of block.split(/\r?\n/)) {
    const entry = /^([A-Za-z0-9_-]+):[ \t]*(.*)$/.exec(line);
    if (entry && !/^\s/.test(line)) {
      flush();
      key = entry[1];
      first = entry[2];
      continuation = [];
    } else if (key !== null && (/^\s/.test(line) || line === '')) {
      continuation.push(line);
    }
  }
  flush();
  return data;
}
