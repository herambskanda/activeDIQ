import { describe, expect, it } from "vitest";
import tokensCss from "./tokens.css?raw";

// WCAG 2.2 contrast gate for the activeDIQ tokens (T-0043). Every text/background pair the design
// system uses must pass in BOTH themes: 4.5:1 for text, 3:1 for UI boundaries and focus rings
// (https://www.w3.org/TR/WCAG22/#dfn-contrast-ratio). Add a pair here when a component starts using one.

type Theme = Record<string, string>;

function declarations(block: string): Theme {
  const out: Theme = {};
  for (const m of block.matchAll(/--diq-([a-z0-9-]+):\s*(#[0-9A-Fa-f]{6})\b/g)) {
    out[m[1] as string] = (m[2] as string).toUpperCase();
  }
  return out;
}

function blockAfter(marker: RegExp): string {
  const start = tokensCss.search(marker);
  if (start < 0) throw new Error(`tokens.css: missing ${String(marker)}`);
  const open = tokensCss.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < tokensCss.length; i++) {
    if (tokensCss[i] === "{") depth++;
    if (tokensCss[i] === "}" && --depth === 0) return tokensCss.slice(open + 1, i);
  }
  throw new Error(`tokens.css: unterminated ${String(marker)}`);
}

// The base `:root` block also holds structural tokens; only its hex values are colours.
const light = declarations(blockAfter(/:root \{/));
const darkAttr = declarations(blockAfter(/:root\[data-theme=["']dark["']\]/));
const darkMedia = declarations(blockAfter(/:root:not\(\[data-theme=["']light["']\]\)/));

const linear = (c: number): number => {
  const s = c / 255;
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
};
const luminance = (hex: string): number => {
  const n = parseInt(hex.slice(1), 16);
  return 0.2126 * linear(n >> 16) + 0.7152 * linear((n >> 8) & 255) + 0.0722 * linear(n & 255);
};
export const contrast = (a: string, b: string): number => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
};

// [label, foreground token, background token, minimum ratio]
const PAIRS: ReadonlyArray<readonly [string, string, string, number]> = [
  ["Body text on page", "text", "bg", 4.5],
  ["Body text on surface", "text", "surface", 4.5],
  ["Secondary text on surface", "text-2", "surface", 4.5],
  ["Secondary text on page", "text-2", "bg", 4.5],
  ["Muted text on surface", "text-3", "surface", 4.5],
  ["Muted text on page", "text-3", "bg", 4.5],
  ["Muted text on sunken surface (table header)", "text-3", "surface-2", 4.5],
  ["Secondary text on sunken surface", "text-2", "surface-2", 4.5],
  ["Body text on selected row", "text", "signal-soft", 4.5],
  ["Muted text on selected row", "text-3", "signal-soft", 4.5],
  ["Signal as link or key number on surface", "signal-text", "surface", 4.5],
  ["Signal as link on page", "signal-text", "bg", 4.5],
  ["Signal as text on sunken surface", "signal-text", "surface-2", 4.5],
  ["Signal as text on selected row", "signal-text", "signal-soft", 4.5],
  ["Primary button label on signal", "signal-ink", "signal", 4.5],
  ["Primary button label on hover fill", "signal-ink", "signal-hover", 4.5],
  ["Primary button label on pressed fill", "signal-ink", "signal-active", 4.5],
  ["Status OK chip", "ok", "ok-bg", 4.5],
  ["Status warning chip", "warn", "warn-bg", 4.5],
  ["Status critical chip", "crit", "crit-bg", 4.5],
  ["Status disabled or neutral chip", "muted", "muted-bg", 4.5],
  ["OK text on surface", "ok", "surface", 4.5],
  ["Warning text on surface", "warn", "surface", 4.5],
  ["Critical text on surface", "crit", "surface", 4.5],
  ["Critical text on page", "crit", "bg", 4.5],
  ["Body text on warning banner", "text", "warn-bg", 4.5],
  ["Body text on success banner", "text", "ok-bg", 4.5],
  ["Body text on critical banner", "text", "crit-bg", 4.5],
  ["Control border on surface (UI boundary)", "line-strong", "surface", 3],
  ["Control border on page (UI boundary)", "line-strong", "bg", 3],
  ["Focus ring on surface", "focus", "surface", 3],
  ["Focus ring on page", "focus", "bg", 3],
  ["Focus ring on sunken surface", "focus", "surface-2", 3],
  ["Focus ring on selected row", "focus", "signal-soft", 3],
  ["Signal fill against surface (button boundary)", "signal", "surface", 3],
  ["Signal fill against page", "signal", "bg", 3],
];

const THEMES: ReadonlyArray<readonly [string, Theme]> = [
  ["light", light],
  ["dark", darkAttr],
];

describe("activeDIQ tokens: WCAG 2.2 AA in both themes", () => {
  for (const [name, theme] of THEMES) {
    describe(`${name} theme`, () => {
      it.each(PAIRS)("%s", (label, fg, bg, min) => {
        const f = theme[fg];
        const b = theme[bg];
        if (f === undefined || b === undefined)
          throw new Error(`${name}: token missing for "${label}" (${fg}/${bg})`);
        expect(contrast(f, b), `${label}: ${f} on ${b}`).toBeGreaterThanOrEqual(min);
      });
    });
  }

  it("defines the same colour tokens in both themes", () => {
    expect(Object.keys(darkAttr).sort()).toEqual(Object.keys(light).sort());
  });

  it("keeps the OS-preference dark block identical to the data-theme dark block", () => {
    expect(darkMedia).toEqual(darkAttr);
  });

  it("is activeDIQ's own palette: no skenzeriq indigo", () => {
    for (const theme of [light, darkAttr]) expect(Object.values(theme)).not.toContain("#6E5BFF");
    expect(tokensCss).not.toMatch(/--sk-|Geist/);
  });
});
