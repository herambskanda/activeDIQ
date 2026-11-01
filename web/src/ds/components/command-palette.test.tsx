// @vitest-environment jsdom
import axe from "axe-core";
import { act, useState } from "react";
import { type Root, createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import baseCss from "../base.css?raw";
import tokensCss from "../tokens.css?raw";
import componentsCss from "./components.css?raw";
import source from "./command-palette.tsx?raw";
import {
  CommandPalette,
  type PaletteGroup,
  type PaletteItem,
  type PaletteStatus,
  highlightRanges,
  resultsAnnouncement,
  truncateMiddle,
  usePaletteShortcut,
} from "./index";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// ---- Fixtures: invented people, test-only --------------------------------------------------
const priya: PaletteItem = {
  id: "u1",
  typeTag: "User",
  name: "Priya Raman",
  identifier: "praman · priya.raman@example.test",
  chips: [{ tone: "warn", label: "Locked 09:12" }],
  disambiguator: "Service desk lead · London",
  dn: "CN=Priya Raman,OU=Service Desk,OU=London,OU=Staff,DC=corp,DC=example,DC=test",
  domain: "corp.example.test",
  expandable: true,
};
const priya2: PaletteItem = {
  id: "u2",
  typeTag: "User",
  name: "Priya Raman",
  identifier: "praman2 · p.raman@example.test",
  chips: [{ tone: "muted", label: "Disabled" }],
  disambiguator: "Finance analyst · Leeds",
  dn: "CN=Priya Raman,OU=Finance,OU=Leeds,OU=Staff,DC=corp,DC=example,DC=test",
};
const grp: PaletteItem = {
  id: "g1",
  typeTag: "Group",
  name: "Raman Reviewers",
  identifier: "GG-Raman-Reviewers",
};
const act1: PaletteItem = {
  id: "a1",
  typeTag: "Action",
  name: "Reset password",
  disabled: true,
  disabledReason: "Needs the Password Admin role",
};
const GROUPS: PaletteGroup[] = [
  { id: "users", label: "Users", items: [priya, priya2], total: 7 },
  { id: "groups", label: "Groups", items: [grp] },
  { id: "actions", label: "Actions", items: [act1] },
];

interface Spies {
  onSelect: ReturnType<typeof vi.fn<(i: PaletteItem) => void>>;
  onExpand: ReturnType<typeof vi.fn<(i: PaletteItem) => void>>;
  onShowAll: ReturnType<typeof vi.fn<(g: PaletteGroup) => void>>;
  onClose: ReturnType<typeof vi.fn<() => void>>;
  onQuery: ReturnType<typeof vi.fn<(q: string) => void>>;
}
function spies(): Spies {
  return {
    onSelect: vi.fn(),
    onExpand: vi.fn(),
    onShowAll: vi.fn(),
    onClose: vi.fn(),
    onQuery: vi.fn(),
  };
}

function Harness(props: {
  readonly s: Spies;
  readonly status?: PaletteStatus;
  readonly groups?: PaletteGroup[];
  readonly query?: string;
  readonly onRetry?: () => void;
  readonly announceDelay?: number;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState(props.query ?? "");
  usePaletteShortcut(() => setOpen(true), !open);
  return (
    <>
      <button id="opener" type="button" onClick={() => setOpen(true)}>
        Search
      </button>
      <CommandPalette
        open={open}
        onClose={() => {
          props.s.onClose();
          setOpen(false);
        }}
        query={query}
        onQueryChange={(q) => {
          props.s.onQuery(q);
          setQuery(q);
        }}
        status={props.status ?? "results"}
        groups={props.groups ?? GROUPS}
        onSelect={props.s.onSelect}
        onExpand={props.s.onExpand}
        onShowAll={props.s.onShowAll}
        {...(props.onRetry ? { onRetry: props.onRetry } : {})}
        {...(props.announceDelay !== undefined ? { announceDelay: props.announceDelay } : {})}
      />
    </>
  );
}

const roots: Root[] = [];
function render(node: React.ReactNode) {
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  roots.push(root);
  act(() => root.render(node));
}
/** Unmounts every root, so document-level listeners from an earlier render cannot answer. */
function cleanup() {
  act(() => roots.splice(0).forEach((r) => r.unmount()));
  document.body.replaceChildren();
}
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

const q = <T extends HTMLElement = HTMLElement>(sel: string): T => {
  const el = document.querySelector<T>(sel);
  if (!el) throw new Error(`no element matches ${sel}`);
  return el;
};
const input = () => q<HTMLInputElement>("[role=combobox]");
const opts = () => Array.from(document.querySelectorAll<HTMLElement>("[role=option]"));
const key = (k: string, init: KeyboardEventInit = {}) =>
  act(() => {
    input().dispatchEvent(
      new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true, ...init }),
    );
  });
const press = (target: EventTarget, k: string, init: KeyboardEventInit = {}) =>
  act(() => {
    target.dispatchEvent(
      new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true, ...init }),
    );
  });
const activeOption = () =>
  document.getElementById(input().getAttribute("aria-activedescendant") ?? "");
const open = () => {
  q("#opener").focus();
  press(document.body, "k", { ctrlKey: true });
};
const axeRun = async (root: ParentNode = document.body) => {
  const r = await axe.run(root as Element, { rules: { "color-contrast": { enabled: false } } });
  return r.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
};

describe("CommandPalette: dialog and combobox structure", () => {
  it("is a modal dialog holding an ARIA 1.2 combobox that controls a grouped listbox", () => {
    render(<Harness s={spies()} query="raman" />);
    open();
    const dlg = q("[role=dialog]");
    expect(dlg.getAttribute("aria-modal")).toBe("true");
    expect(dlg.getAttribute("aria-label")).toBe("Search");
    const cb = input();
    const list = q("[role=listbox]");
    expect(cb.getAttribute("aria-expanded")).toBe("true");
    expect(cb.getAttribute("aria-controls")).toBe(list.id);
    expect(cb.getAttribute("aria-autocomplete")).toBe("list");
    const groups = Array.from(list.querySelectorAll("[role=group]"));
    expect(groups).toHaveLength(3);
    for (const g of groups) {
      const label = document.getElementById(g.getAttribute("aria-labelledby") ?? "");
      expect(label?.textContent).toBeTruthy();
    }
    const first = q("[role=group]").getAttribute("aria-labelledby") ?? "";
    expect(document.getElementById(first)?.textContent).toBe("Users7");
  });

  it("focuses the input on open and makes the page behind inert", () => {
    render(<Harness s={spies()} />);
    open();
    expect(document.activeElement).toBe(input());
    expect(q("#opener").closest("[inert]")).not.toBeNull();
  });

  it("opens from Ctrl+K and from / outside a field, not from / inside a field", () => {
    render(
      <>
        <input id="plain" aria-label="Plain" />
        <Harness s={spies()} />
      </>,
    );
    q("#plain").focus();
    press(q("#plain"), "/");
    expect(document.querySelector("[role=dialog]")).toBeNull();
    q("#opener").focus();
    press(q("#opener"), "/");
    expect(document.querySelector("[role=dialog]")).not.toBeNull();
  });
});

describe("CommandPalette: keyboard", () => {
  it("highlights the first row, and aria-activedescendant follows Up/Down (wrapping), Home and End", () => {
    render(<Harness s={spies()} />);
    open();
    const all = opts();
    expect(all).toHaveLength(5); // 2 users + "Show all 7" + group + disabled action
    expect(activeOption()).toBe(all[0]);
    expect(all[0]?.getAttribute("aria-selected")).toBe("true");
    key("ArrowDown");
    expect(activeOption()).toBe(all[1]);
    expect(all[0]?.getAttribute("aria-selected")).toBe("false");
    key("End");
    expect(activeOption()).toBe(all[4]);
    key("ArrowDown");
    expect(activeOption()).toBe(all[0]);
    key("ArrowUp");
    expect(activeOption()).toBe(all[4]);
    key("Home");
    expect(activeOption()).toBe(all[0]);
    expect(document.activeElement).toBe(input());
  });

  it("Enter runs the highlighted row; a disabled row and a Show-all row do the right thing", () => {
    const s = spies();
    render(<Harness s={s} />);
    open();
    key("Enter");
    expect(s.onSelect).toHaveBeenCalledWith(priya);
    key("ArrowDown");
    key("ArrowDown"); // Show all 7
    key("Enter");
    expect(s.onShowAll).toHaveBeenCalledWith(GROUPS[0]);
    key("End"); // the disabled action
    key("Enter");
    expect(s.onSelect).toHaveBeenCalledTimes(1);
    expect(opts()[4]?.getAttribute("aria-disabled")).toBe("true");
    expect(opts()[4]?.textContent).toContain("Needs the Password Admin role");
  });

  it("Right arrow expands only when the caret is at the end and the row is expandable", () => {
    const s = spies();
    render(<Harness s={s} query="raman" />);
    open();
    input().setSelectionRange(2, 2);
    key("ArrowRight");
    expect(s.onExpand).not.toHaveBeenCalled();
    input().setSelectionRange(5, 5);
    key("ArrowRight");
    expect(s.onExpand).toHaveBeenCalledWith(priya);
    key("ArrowDown"); // priya2 is not expandable
    key("ArrowRight");
    expect(s.onExpand).toHaveBeenCalledTimes(1);
  });

  it("Escape closes and returns focus to the opener", () => {
    const s = spies();
    render(<Harness s={s} />);
    open();
    key("Escape");
    expect(s.onClose).toHaveBeenCalledTimes(1);
    expect(document.querySelector("[role=dialog]")).toBeNull();
    expect(document.activeElement).toBe(q("#opener"));
    expect(q("#opener").closest("[inert]")).toBeNull();
  });

  it("Tab and Shift+Tab never leave the combobox", () => {
    render(<Harness s={spies()} />);
    open();
    const tab = (shiftKey: boolean) => {
      const ev = new KeyboardEvent("keydown", {
        key: "Tab",
        shiftKey,
        bubbles: true,
        cancelable: true,
      });
      act(() => {
        input().dispatchEvent(ev);
      });
      return ev.defaultPrevented;
    };
    expect(tab(false)).toBe(true);
    expect(tab(true)).toBe(true);
    expect(document.activeElement).toBe(input());
  });

  it("Tab cycles between the input and an error Try again button", () => {
    const retry = vi.fn();
    render(<Harness s={spies()} status="error" groups={[]} onRetry={retry} />);
    open();
    const btn = q("button.diq-btn");
    const tab = (shiftKey: boolean, from: Element) => {
      const ev = new KeyboardEvent("keydown", {
        key: "Tab",
        shiftKey,
        bubbles: true,
        cancelable: true,
      });
      act(() => {
        from.dispatchEvent(ev);
      });
    };
    tab(false, input()); // not last: the browser would move to the button; we only guard the ends
    btn.focus();
    tab(false, btn);
    expect(document.activeElement).toBe(input());
    tab(true, input());
    expect(document.activeElement).toBe(btn);
    act(() => btn.click());
    expect(retry).toHaveBeenCalledTimes(1);
  });

  it("typing reports the query and resets the highlight to the first row", () => {
    const s = spies();
    render(<Harness s={s} />);
    open();
    key("End");
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    act(() => {
      setter?.call(input(), "ram");
      input().dispatchEvent(new Event("input", { bubbles: true }));
    });
    expect(s.onQuery).toHaveBeenCalledWith("ram");
    expect(activeOption()).toBe(opts()[0]);
  });

  it("ignores Arrow keys while an IME composition is open", () => {
    render(<Harness s={spies()} />);
    open();
    key("ArrowDown", { isComposing: true } as KeyboardEventInit);
    expect(activeOption()).toBe(opts()[0]);
  });

  it("a click on a row runs it and keeps focus in the input", () => {
    const s = spies();
    render(<Harness s={s} />);
    open();
    act(() => opts()[1]?.click());
    expect(s.onSelect).toHaveBeenCalledWith(priya2);
    expect(document.activeElement).toBe(input());
  });
});

describe("CommandPalette: announcements", () => {
  beforeEach(() => vi.useFakeTimers());

  it("announces 'N results, M groups' politely, only after the delay", () => {
    render(<Harness s={spies()} query="raman" announceDelay={400} />);
    open();
    const live = q("[role=status][aria-live=polite]");
    expect(live.textContent).toBe("");
    act(() => vi.advanceTimersByTime(399));
    expect(live.textContent).toBe("");
    act(() => vi.advanceTimersByTime(2));
    expect(live.textContent).toBe("4 results, 3 groups");
  });

  it("says nothing for idle, and 'No results' for an empty answer", () => {
    render(<Harness s={spies()} status="idle" />);
    open();
    act(() => vi.advanceTimersByTime(1000));
    expect(q("[role=status][aria-live=polite]").textContent).toBe("");
    cleanup();
    render(<Harness s={spies()} groups={[]} query="kowalski" />);
    open();
    act(() => vi.advanceTimersByTime(1000));
    expect(q("[role=status][aria-live=polite]").textContent).toBe("No results");
  });

  it("formats singular and plural", () => {
    expect(resultsAnnouncement({ results: 1, groups: 1 })).toBe("1 result, 1 group");
    expect(resultsAnnouncement({ results: 12, groups: 3 })).toBe("12 results, 3 groups");
    expect(resultsAnnouncement({ results: 0, groups: 0 })).toBe("No results");
  });
});

describe("CommandPalette: states", () => {
  const states: ReadonlyArray<readonly [string, PaletteStatus, PaletteGroup[]]> = [
    ["idle", "idle", [{ id: "recent", label: "Recent", items: [priya] }]],
    ["loading", "loading", []],
    ["results", "results", GROUPS],
    ["no results", "results", []],
    ["error", "error", []],
    ["denied", "denied", []],
  ];

  it.each(states)(
    "%s: renders and has no serious or critical axe violation",
    async (_n, status, groups) => {
      render(<Harness s={spies()} status={status} groups={groups} query="kowalski" />);
      open();
      expect(await axeRun()).toEqual([]);
    },
  );

  it("no results names the query; error is an alert; denied makes the input read-only", () => {
    render(<Harness s={spies()} groups={[]} query="kowalski" />);
    open();
    expect(q("[role=dialog]").textContent).toContain("No results for “kowalski”");
    expect(input().getAttribute("aria-expanded")).toBe("false");
    expect(input().hasAttribute("aria-controls")).toBe(false);
    cleanup();
    render(<Harness s={spies()} status="error" groups={[]} />);
    open();
    expect(q("[role=alert]").textContent).toContain("Search failed");
    cleanup();
    render(<Harness s={spies()} status="denied" groups={[]} />);
    open();
    expect(input().readOnly).toBe(true);
    expect(input().getAttribute("aria-disabled")).toBe("true");
    expect(q("[role=dialog]").textContent).toContain("not available to your account");
  });

  it("loading shows a status skeleton and no listbox", () => {
    render(<Harness s={spies()} status="loading" groups={GROUPS} />);
    open();
    expect(q("[role=status][aria-label=Searching]")).toBeTruthy();
    expect(document.querySelector("[role=listbox]")).toBeNull();
  });

  it("is clean under axe in the dark theme too", async () => {
    document.documentElement.dataset["theme"] = "dark";
    render(<Harness s={spies()} query="raman" />);
    open();
    expect(await axeRun()).toEqual([]);
    delete document.documentElement.dataset["theme"];
  });
});

describe("CommandPalette: row content", () => {
  it("shows tag, highlighted name and identifier, chips as text, disambiguator, DN and domain", () => {
    render(<Harness s={spies()} query="raman" />);
    open();
    const row = opts()[0] as HTMLElement;
    expect(row.querySelector(".diq-pal__tag")?.textContent).toBe("User");
    expect(Array.from(row.querySelectorAll("mark")).map((m) => m.textContent)).toEqual([
      "Raman",
      "raman",
      "raman",
    ]);
    expect(row.textContent).toContain("Locked 09:12");
    expect(row.textContent).toContain("Service desk lead · London");
    expect(row.textContent).toContain("corp.example.test");
  });

  it("truncates the DN in the middle with the full value as the tooltip; the highlighted row shows it whole", () => {
    render(<Harness s={spies()} />);
    open();
    const rows = opts();
    const second = rows[1]?.querySelector<HTMLElement>(".diq-pal__dn");
    expect(second?.title).toBe(priya2.dn);
    expect(second?.querySelector("[aria-hidden=true]")?.textContent).toContain("…");
    expect(second?.querySelector(".diq-sr-only")?.textContent).toBe(priya2.dn);
    expect(rows[0]?.querySelector(".diq-pal__dn")?.textContent).toBe(priya.dn);
    key("ArrowDown");
    expect(opts()[1]?.querySelector(".diq-pal__dn")?.textContent).toBe(priya2.dn);
  });

  it("renders a 200-character unbroken name and hostile markup as text", () => {
    const long = "W".repeat(200);
    const hostile = `<img src=x onerror="alert(1)"><script>alert(2)</script>`;
    const g: PaletteGroup[] = [
      {
        id: "x",
        label: "Users",
        items: [
          { id: "1", typeTag: "User", name: long, dn: `CN=${long},DC=${long}` },
          { id: "2", typeTag: "User", name: hostile, identifier: hostile, disambiguator: hostile },
        ],
      },
    ];
    render(<Harness s={spies()} groups={g} query="img" />);
    open();
    const list = q("[role=listbox]");
    expect(list.querySelector("img, script")).toBeNull();
    expect(opts()[1]?.querySelector(".diq-pal__name")?.textContent).toBe(hostile);
    expect(opts()[0]?.querySelector(".diq-pal__name")?.textContent).toBe(long);
    expect(source).not.toMatch(/dangerouslySetInnerHTML|innerHTML/);
  });
});

describe("helpers", () => {
  it("highlightRanges: case-insensitive words, merged, never a pattern", () => {
    expect(highlightRanges("Priya Raman", "raman, priya")).toEqual([
      [0, 5],
      [6, 11],
    ]);
    expect(highlightRanges("a.b", ".*")).toEqual([]);
    expect(highlightRanges("a.b", ".")).toEqual([[1, 2]]);
    expect(highlightRanges("abcd", "ab bc")).toEqual([[0, 3]]);
    expect(highlightRanges("İstanbul", "stan")).toEqual([]);
    expect(highlightRanges("anything", "  ")).toEqual([]);
  });

  it("truncateMiddle keeps both ends and never splits a code point", () => {
    expect(truncateMiddle("short", 10)).toBe("short");
    const t = truncateMiddle("CN=Priya,OU=Staff,DC=corp,DC=example,DC=test", 20);
    expect(Array.from(t)).toHaveLength(20);
    expect(t.startsWith("CN=Priya")).toBe(true);
    expect(t.endsWith("=test")).toBe(true);
    expect(truncateMiddle("😀".repeat(30), 9)).toBe(`${"😀".repeat(4)}…${"😀".repeat(4)}`);
  });
});

describe("CommandPalette: styling contract", () => {
  const css = componentsCss.slice(componentsCss.indexOf("/* ---- CommandPalette"));

  it("uses tokens only: no colour literal, no raw pixel or time value", () => {
    expect(css).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(css).not.toMatch(/\b(rgb|rgba|hsl|hsla|oklch|oklab)\(/);
    expect(css).not.toMatch(/\d(px|ms|s|rem|em)\b/);
    for (const m of css.matchAll(/(?:^|\s)(?:animation|transition)\s*:([^;]+);/gm)) {
      expect(m[1], m[0]).toMatch(/var\(--diq-dur/);
    }
    expect(source).not.toMatch(/#[0-9a-fA-F]{3,8}\b|style=\{/);
  });

  it("only references tokens that exist", () => {
    const defined = new Set([...tokensCss.matchAll(/(--diq-[a-z0-9-]+)\s*:/g)].map((m) => m[1]));
    const used = [...css.matchAll(/var\((--diq-[a-z0-9-]+)/g)].map((m) => m[1]);
    expect(used.length).toBeGreaterThan(20);
    expect(used.filter((u) => !defined.has(u))).toEqual([]);
  });

  it("respects reduced motion: the entry animation runs on --diq-dur, which collapses to 0, and the global rule backs it", () => {
    expect(css).toMatch(/animation:\s*diq-pal-in var\(--diq-dur\)/);
    expect(css).toMatch(/\.diq-pal__scrim\s*\{[^}]*animation:\s*diq-fade var\(--diq-dur\)/s);
    const reduced = /@media \(prefers-reduced-motion: reduce\)\s*\{[^}]*--diq-dur:\s*0ms/s;
    expect(tokensCss).toMatch(reduced);
    expect(baseCss).toMatch(
      /@media \(prefers-reduced-motion: reduce\)[\s\S]*animation-duration:\s*0\.01ms !important/,
    );
  });

  it("marks the highlighted row and the match with more than colour", () => {
    expect(css).toMatch(/\.diq-pal__mark\s*\{[^}]*font-weight:\s*var\(--diq-weight-semibold\)/s);
    expect(css).toMatch(/\.diq-pal__opt\[data-active\]\s*\{[^}]*border-inline-start-color/s);
  });
});

describe("design-system boundary", () => {
  it("keeps fixtures out of non-test source: the component imports no fixture or module code", () => {
    expect(source).not.toMatch(/from ["'][^"']*(fixtures?|modules|stories)/);
    expect(source).not.toMatch(/example\.test|Priya/);
  });
});
