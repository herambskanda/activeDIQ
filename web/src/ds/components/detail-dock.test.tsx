// @vitest-environment jsdom
import axe from "axe-core";
import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import css from "./components.css?raw";
import { DataGrid, DetailDock, DockLayout } from "./index";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const roots: Root[] = [];
afterEach(() => {
  for (const r of roots.splice(0)) act(() => r.unmount());
  document.body.replaceChildren();
});
function render(node: React.ReactNode): HTMLElement {
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  roots.push(root);
  act(() => root.render(node));
  return host;
}
function q(host: ParentNode, sel: string): HTMLElement {
  const el = host.querySelector<HTMLElement>(sel);
  if (!el) throw new Error(`no element matches ${sel}`);
  return el;
}
function key(el: HTMLElement, k: string, init: KeyboardEventInit = {}) {
  act(() => {
    el.dispatchEvent(
      new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true, ...init }),
    );
  });
}
const button = (host: ParentNode, name: string): HTMLElement => {
  const b = Array.from(host.querySelectorAll<HTMLElement>("button")).find((x) =>
    x.textContent?.includes(name),
  );
  if (!b) throw new Error(`no button ${name}`);
  return b;
};

interface Change {
  readonly id: string;
  readonly name: string;
}
const CHANGES: Change[] = Array.from({ length: 5 }, (_, i) => ({
  id: `c${i}`,
  name: `Change ${i}`,
}));
const COLS = [{ key: "name", header: "Name", rowHeader: true, cell: (c: Change) => c.name }];

/** The screen's wiring: grid + dock, current row in state (the real screens keep it in `?row=`). */
function Screen(props: { readonly start?: number | null; readonly onClose?: () => void }) {
  const [at, setAt] = useState<number | null>(props.start ?? null);
  const row = at === null ? null : CHANGES[at];
  return (
    <DockLayout
      dock={
        row ? (
          <DetailDock
            title={row.name}
            description="User change"
            position={{ index: (at ?? 0) + 1, total: CHANGES.length }}
            onPrev={() => setAt((a) => Math.max(0, (a ?? 0) - 1))}
            onNext={() => setAt((a) => Math.min(CHANGES.length - 1, (a ?? 0) + 1))}
            onClose={() => {
              props.onClose?.();
              setAt(null);
            }}
            footer={<a href="#row">Copy link</a>}
          >
            <p>Detail of {row.name}</p>
          </DetailDock>
        ) : undefined
      }
    >
      <DataGrid
        caption="Changes, 5 rows"
        columns={COLS}
        rows={CHANGES}
        rowKey={(c) => c.id}
        currentRowKey={row?.id ?? null}
        onRowActivate={(c) => setAt(CHANGES.indexOf(c))}
        onActiveRowChange={(c) => setAt((a) => (a === null ? a : CHANGES.indexOf(c)))}
        onEscape={() => setAt(null)}
      />
    </DockLayout>
  );
}

const cell = (host: ParentNode, r: number, c = 0) => q(host, `[data-r="${r}"][data-c="${c}"]`);

describe("DetailDock", () => {
  it("is a labelled, non-modal complementary landmark", () => {
    const host = render(<Screen start={1} />);
    const dock = q(host, "aside");
    expect(dock.getAttribute("aria-labelledby")).toBe(q(dock, "h2").id);
    expect(q(dock, "h2").textContent).toBe("Change 1");
    expect(dock.getAttribute("role")).toBeNull();
    expect(dock.getAttribute("aria-modal")).toBeNull();
    expect(host.querySelector('[role="dialog"]')).toBeNull();
  });

  it("opens without taking focus, so the grid keeps stepping", () => {
    const host = render(<Screen />);
    const c = cell(host, 1);
    c.focus();
    key(c, "Enter"); // onRowActivate opens the dock
    expect(host.querySelector("aside")).not.toBeNull();
    expect(document.activeElement).toBe(c);
  });

  it("follows ↑/↓ in the grid: the pane shows the row under focus, and the row is aria-current", () => {
    const host = render(<Screen />);
    const c = cell(host, 1);
    c.focus();
    key(c, "Enter");
    expect(q(host, "aside h2").textContent).toBe("Change 0");
    key(c, "ArrowDown");
    expect(q(host, "aside h2").textContent).toBe("Change 1");
    expect(q(host, '[aria-current="true"]').textContent).toBe("Change 1");
    key(document.activeElement as HTMLElement, "ArrowDown");
    expect(q(host, "aside h2").textContent).toBe("Change 2");
    expect(host.querySelectorAll('[aria-current="true"]')).toHaveLength(1);
  });

  it("Esc closes from the dock and from the grid", () => {
    const onClose = vi.fn();
    const host = render(<Screen start={0} onClose={onClose} />);
    key(button(host, "Next"), "Escape");
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(host.querySelector("aside")).toBeNull();

    const host2 = render(<Screen start={2} />);
    const c = cell(host2, 3);
    c.focus();
    key(c, "Escape");
    expect(host2.querySelector("aside")).toBeNull();
  });

  it("does not close on Escape while composing text", () => {
    const onClose = vi.fn();
    const host = render(
      <DetailDock title="X" onClose={onClose}>
        <input aria-label="note" />
      </DetailDock>,
    );
    key(q(host, "input"), "Escape", { isComposing: true } as KeyboardEventInit);
    // jsdom's KeyboardEvent carries isComposing; the guard reads nativeEvent.isComposing.
    expect(onClose).not.toHaveBeenCalled();
  });

  it("steps with Previous / Next, shows 'n of N' and keeps focus on the last row's button", () => {
    const host = render(<Screen start={3} />);
    expect(q(host, ".diq-dock__pos").textContent).toBe("4 of 5");
    const next = button(host, "Next");
    next.focus();
    key(next, "Enter");
    act(() => next.click());
    expect(q(host, "aside h2").textContent).toBe("Change 4");
    expect(next.getAttribute("aria-disabled")).toBe("true");
    act(() => next.click()); // inert at the end
    expect(q(host, "aside h2").textContent).toBe("Change 4");
    expect(document.activeElement).toBe(next); // aria-disabled, not disabled: focus is not dropped
    const prev = button(host, "Previous");
    expect(prev.getAttribute("aria-disabled")).toBeNull();
  });

  it("Previous is inert on the first row", () => {
    const host = render(<Screen start={0} />);
    const prev = button(host, "Previous");
    expect(prev.getAttribute("aria-disabled")).toBe("true");
    act(() => prev.click());
    expect(q(host, "aside h2").textContent).toBe("Change 0");
  });

  it("returns focus to where it was when the dock closes from inside", () => {
    const host = render(<Screen />);
    const c = cell(host, 1);
    c.focus();
    key(c, "Enter");
    button(host, "Close details").focus();
    act(() => button(host, "Close details").click());
    expect(host.querySelector("aside")).toBeNull();
    expect(document.activeElement).toBe(c);
  });

  it("announces on open and when stepping from inside, not when the grid drives it", () => {
    const host = render(<Screen />);
    const c = cell(host, 1);
    c.focus();
    key(c, "Enter");
    const live = () => q(host, 'aside [role="status"]').textContent;
    expect(live()).toBe("Change 0, 1 of 5");
    key(c, "ArrowDown"); // grid-driven: the grid announces its own row
    expect(live()).toBe("Change 0, 1 of 5");
    const next = button(host, "Next");
    next.focus();
    act(() => next.click());
    expect(live()).toBe("Change 2, 3 of 5");
  });

  it("long and Unicode titles and an unknown position render", () => {
    const host = render(
      <DetailDock title={"Åsa ".repeat(16) + "محمد الفاسي"} onClose={() => undefined}>
        <p>x</p>
      </DetailDock>,
    );
    expect(q(host, "h2").textContent?.length).toBeGreaterThan(64);
    expect(host.querySelector(".diq-dock__step")).toBeNull(); // no stepper without position + handlers
  });

  it("has no axe violations (open, long content, with footer)", async () => {
    const host = render(<Screen start={2} />);
    const r = await axe.run(host, { rules: { "color-contrast": { enabled: false } } });
    expect(r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`)).toEqual(
      [],
    );
  });
});

describe("dock CSS", () => {
  const block = (name: string): string => {
    const m = css.match(new RegExp(`/\\* ---- ${name}[\\s\\S]*?(?=/\\* ---- |$)`));
    if (!m) throw new Error(`no ${name} section`);
    return m[0];
  };
  it.each(["DeltaCell", "PinnedBand", "DetailDock"])(
    "%s uses tokens only: no hex colour, pixel length or duration",
    (name) => {
      const body = block(name).replace(/\/\*[\s\S]*?\*\//g, "");
      expect(body).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
      expect(body).not.toMatch(/\b\d+(\.\d+)?px\b/);
      expect(body).not.toMatch(/\b\d+(\.\d+)?m?s\b/);
    },
  );
});
