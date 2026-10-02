// Tiny template renderer: `{{var}}` and `{{#flag}}…{{/flag}}`.

/**
 * Render a template. Block tags alone on their line leave no blank line behind. Values are
 * substituted in a single pass, so a value containing `{{x}}` is never expanded again.
 * @param {string} template
 * @param {Record<string, unknown>} vars
 * @returns {string}
 */
export function render(template, vars) {
  let out = template.replace(
    /^[ \t]*\{\{#(\w+)\}\}[ \t]*\r?\n([\s\S]*?)^[ \t]*\{\{\/\1\}\}[ \t]*(?:\r?\n|$)/gm,
    (_, key, inner) => (vars[key] ? inner : ''),
  );
  out = out.replace(/\{\{#(\w+)\}\}([\s\S]*?)\{\{\/\1\}\}/g, (_, key, inner) => (vars[key] ? inner : ''));
  return out.replace(/\{\{(\w+)\}\}/g, (_, key) => (vars[key] == null ? '' : String(vars[key])));
}
