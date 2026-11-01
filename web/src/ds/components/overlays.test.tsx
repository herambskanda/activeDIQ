// @vitest-environment jsdom
import axe from "axe-core";
import { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  Button,
  Popover,
  PopoverMenu,
  type PopoverMenuItem,
  SideSheet,
  Toast,
  ToastRegion,
} from "./index";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const hosts: HTMLElement[] = [];
function render(node: React.ReactNode): HTMLElement {
  const host = document.createElement("div");
  document.body.append(host);
  hosts.push(host);
  act(() => createRoot(host).render(node));
  return host;
}
afterEach(() => {
  document.body.replaceChildren();
  hosts.length = 0;
});
function q(sel: string, root: ParentNode = document): HTMLElement {
  const el = root.querySelector<HTMLElement>(sel);
  if (!el) throw new Error(`no element matches ${sel}`);
  return el;
}
const maybe = (sel: string) => document.querySelector<HTMLElement>(sel);
const click = (el: HTMLElement) => act(() => el.click());
function key(el: Element, k: string, init: KeyboardEventInit = {}) {
  act(() => {
    el.dispatchEvent(
      new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true, ...init }),
    );
  });
}
const active = () => document.activeElement;
const run = async (root: HTMLElement) => {
  // Colour contrast needs real layout and styles; tokens.test.ts and the Storybook a11y addon cover it.
  const r = await axe.run(root, { rules: { "color-contrast": { enabled: false } } });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`);
};

function Menu(props: {
  readonly onXlsx?: () => void;
  readonly onCsv?: () => void;
  readonly csvDisabled?: boolean;
  readonly onOpenChange?: (o: boolean) => void;
}) {
  const items: PopoverMenuItem[] = [
    {
      id: "xlsx",
      label: "XLSX",
      description: "with About sheet",
      accelerator: "x",
      onSelect: props.onXlsx ?? (() => undefined),
    },
    {
      id: "csv",
      label: "CSV",
      description: props.csvDisabled ? "limit 100,000 rows" : "table only",
      accelerator: "c",
      disabled: props.csvDisabled === true,
      onSelect: props.onCsv ?? (() => undefined),
    },
  ];
  return (
    <>
      <PopoverMenu
        label="Export format"
        header="12,000 rows · 6 columns"
        footer={<p role="alert">Over the limit</p>}
        items={items}
        onOpenChange={props.onOpenChange ?? (() => undefined)}
        trigger={(p) => <Button {...p}>Export</Button>}
      />
      <button type="button" id="elsewhere">
        elsewhere
      </button>
    </>
  );
}
const trigger = () => q("[aria-haspopup]");
const itemEls = () => Array.from(document.querySelectorAll<HTMLElement>('[role="menuitem"]'));

describe("PopoverMenu", () => {
  it("opens from a click, names the menu and puts focus on the first item", () => {
    render(<Menu />);
    expect(trigger().getAttribute("aria-expanded")).toBe("false");
    click(trigger());
    expect(trigger().getAttribute("aria-expanded")).toBe("true");
    expect(q('[role="menu"]').getAttribute("aria-label")).toBe("Export format");
    expect(trigger().getAttribute("aria-controls")).toBe(q(".diq-pop__panel").id);
    expect(active()).toBe(itemEls()[0]);
    expect(itemEls()[0]?.getAttribute("aria-keyshortcuts")).toBe("X");
  });

  it("opens with Arrow Down on the trigger and toggles closed on a second click", () => {
    render(<Menu />);
    trigger().focus();
    key(trigger(), "ArrowDown");
    expect(maybe('[role="menu"]')).not.toBeNull();
    click(trigger());
    expect(maybe('[role="menu"]')).toBeNull();
  });

  it("a pressed accelerator invokes that item once, closes the menu and restores focus first", () => {
    let focusAtCall: Element | null = null;
    const onCsv = vi.fn(() => {
      focusAtCall = active();
    });
    const onXlsx = vi.fn();
    render(<Menu onCsv={onCsv} onXlsx={onXlsx} />);
    click(trigger());
    key(active() as Element, "C"); // case-insensitive
    expect(onCsv).toHaveBeenCalledTimes(1);
    expect(onXlsx).not.toHaveBeenCalled();
    expect(maybe('[role="menu"]')).toBeNull();
    expect(active()).toBe(trigger());
    expect(focusAtCall).toBe(trigger());
  });

  it("ignores accelerators with Ctrl, Alt or Meta held", () => {
    const onCsv = vi.fn();
    render(<Menu onCsv={onCsv} />);
    click(trigger());
    key(active() as Element, "c", { ctrlKey: true });
    key(active() as Element, "c", { metaKey: true });
    expect(onCsv).not.toHaveBeenCalled();
    expect(maybe('[role="menu"]')).not.toBeNull();
  });

  it("Enter, Space and a click on the focused item invoke it (native button) and close", () => {
    const onXlsx = vi.fn();
    render(<Menu onXlsx={onXlsx} />);
    click(trigger());
    click(itemEls()[0] as HTMLElement);
    expect(onXlsx).toHaveBeenCalledTimes(1);
    expect(active()).toBe(trigger());
  });

  it("moves with the arrows, Home and End, wrapping at the ends", () => {
    render(<Menu />);
    click(trigger());
    const [a, b] = itemEls() as [HTMLElement, HTMLElement];
    key(a, "ArrowDown");
    expect(active()).toBe(b);
    key(b, "ArrowDown");
    expect(active()).toBe(a);
    key(a, "ArrowUp");
    expect(active()).toBe(b);
    key(b, "Home");
    expect(active()).toBe(a);
    key(a, "End");
    expect(active()).toBe(b);
  });

  it("Escape closes and restores focus; the Escape does not reach a parent", () => {
    const outer = vi.fn();
    render(
      <div onKeyDown={outer}>
        <Menu />
      </div>,
    );
    click(trigger());
    key(active() as Element, "Escape");
    expect(maybe('[role="menu"]')).toBeNull();
    expect(active()).toBe(trigger());
    expect(outer).not.toHaveBeenCalled();
  });

  it("Tab closes the menu and leaves focus on the trigger", () => {
    render(<Menu />);
    click(trigger());
    key(active() as Element, "Tab");
    expect(maybe('[role="menu"]')).toBeNull();
    expect(active()).toBe(trigger());
  });

  it("closes on a press outside without stealing focus", () => {
    const onOpenChange = vi.fn();
    render(<Menu onOpenChange={onOpenChange} />);
    click(trigger());
    const other = q("#elsewhere");
    other.focus();
    act(() => {
      other.dispatchEvent(new Event("pointerdown", { bubbles: true }));
    });
    expect(maybe('[role="menu"]')).toBeNull();
    expect(active()).toBe(other);
    expect(onOpenChange).toHaveBeenLastCalledWith(false);
  });

  it("a disabled item stays focusable and readable but is never invoked, by key or click", () => {
    const onCsv = vi.fn();
    render(<Menu onCsv={onCsv} csvDisabled />);
    click(trigger());
    const csv = itemEls()[1] as HTMLElement;
    expect(csv.getAttribute("aria-disabled")).toBe("true");
    csv.focus();
    expect(active()).toBe(csv);
    click(csv);
    key(csv, "c");
    expect(onCsv).not.toHaveBeenCalled();
    expect(maybe('[role="menu"]')).not.toBeNull();
    expect(csv.textContent).toContain("limit 100,000 rows");
  });

  it("starts on the first available item when the first is disabled", () => {
    render(
      <PopoverMenu
        label="m"
        defaultOpen
        trigger={(p) => <Button {...p}>Open</Button>}
        items={[
          { id: "a", label: "A", disabled: true, onSelect: () => undefined },
          { id: "b", label: "B", onSelect: () => undefined },
        ]}
      />,
    );
    expect(active()).toBe(itemEls()[1]);
  });

  it("has no axe violations open, with a disabled item and a long label", async () => {
    const host = render(
      <>
        <Menu csvDisabled />
        <PopoverMenu
          label="Long"
          defaultOpen
          trigger={(p) => <Button {...p}>Menu</Button>}
          items={[
            {
              id: "l",
              label: `${"Ünïcödé ".repeat(12)}مجلد`,
              description: "x".repeat(200),
              onSelect: () => undefined,
            },
          ]}
        />
      </>,
    );
    click(host.querySelector<HTMLElement>("[aria-haspopup]") as HTMLElement);
    expect(await run(host)).toEqual([]);
  });
});

describe("Popover", () => {
  const Form = () => (
    <Popover label="Columns" align="end" trigger={(p) => <Button {...p}>Columns</Button>}>
      <label>
        <input type="checkbox" defaultChecked /> Name
      </label>
      <label>
        <input type="checkbox" /> Department
      </label>
    </Popover>
  );
  it("opens as a named non-modal dialog, focuses its first control and keeps open while editing", () => {
    render(<Form />);
    click(trigger());
    expect(q('[role="dialog"]').getAttribute("aria-label")).toBe("Columns");
    expect(q('[role="dialog"]').getAttribute("aria-modal")).toBeNull();
    expect(active()).toBe(q('input[type="checkbox"]'));
    click(q('input[type="checkbox"]'));
    expect(maybe('[role="dialog"]')).not.toBeNull();
  });
  it("Escape closes it and restores focus to the trigger", () => {
    render(<Form />);
    click(trigger());
    key(active() as Element, "Escape");
    expect(maybe('[role="dialog"]')).toBeNull();
    expect(active()).toBe(trigger());
  });
  it("closes when focus moves to something outside it", () => {
    render(
      <>
        <Form />
        <button type="button" id="elsewhere">
          elsewhere
        </button>
      </>,
    );
    click(trigger());
    act(() => q("#elsewhere").focus());
    expect(maybe('[role="dialog"]')).toBeNull();
    expect(active()).toBe(q("#elsewhere"));
  });
  it("has no axe violations", async () => {
    const host = render(<Form />);
    click(trigger());
    expect(await run(host)).toEqual([]);
  });
});

function Sheet(props: { readonly withMenu?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <main>
        <button type="button" id="opener" onClick={() => setOpen(true)}>
          Schedule
        </button>
      </main>
      <SideSheet
        open={open}
        onClose={() => setOpen(false)}
        title="Schedule this report"
        description="Exactly what is on screen."
      >
        <form>
          <input aria-label="Name" id="first" autoFocus />
          {props.withMenu ? (
            <Popover label="Columns" trigger={(p) => <Button {...p}>Columns</Button>}>
              <input aria-label="Filter" />
            </Popover>
          ) : null}
          <button type="submit" id="last">
            Save
          </button>
        </form>
      </SideSheet>
    </>
  );
}
const dialog = () => maybe('[role="dialog"][aria-modal="true"]');

describe("SideSheet", () => {
  it("opens as a modal dialog named by its title, with focus inside (autoFocus wins)", () => {
    render(<Sheet />);
    expect(dialog()).toBeNull();
    q("#opener").focus();
    click(q("#opener"));
    const d = dialog() as HTMLElement;
    expect(d.getAttribute("aria-labelledby")).toBe(q("h2", d).id);
    expect(d.getAttribute("aria-describedby")).toBeTruthy();
    expect(active()).toBe(q("#first"));
  });

  it("falls back to the first tabbable (Close) when nothing asks for focus", () => {
    render(
      <SideSheet open onClose={() => undefined} title="T">
        <p>Read-only</p>
      </SideSheet>,
    );
    expect(active()).toBe(q(".diq-sheet__close"));
  });

  it("traps Tab and Shift+Tab inside, and makes the page behind inert", () => {
    const host = render(<Sheet />);
    click(q("#opener"));
    expect(host.hasAttribute("inert")).toBe(true);
    const close = q(".diq-sheet__close");
    q("#last").focus();
    key(q("#last"), "Tab");
    expect(active()).toBe(close);
    key(close, "Tab", { shiftKey: true });
    expect(active()).toBe(q("#last"));
    // Focus that lands outside (a stray programmatic focus) is pulled back in.
    act(() => q("#opener").focus());
    expect(dialog()?.contains(active())).toBe(true);
  });

  it("Escape closes it and focus returns to the trigger; the page is live again", () => {
    const host = render(<Sheet />);
    q("#opener").focus();
    click(q("#opener"));
    key(active() as Element, "Escape");
    expect(dialog()).toBeNull();
    expect(active()).toBe(q("#opener"));
    expect(host.hasAttribute("inert")).toBe(false);
  });

  it("the Close button and a press on the scrim close it; a press inside does not", () => {
    render(<Sheet />);
    q("#opener").focus();
    click(q("#opener"));
    const press = (el: Element) =>
      act(() => {
        el.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
      });
    // A drag that starts inside the sheet and ends on the scrim does not close it.
    press(q("#first"));
    click(q(".diq-sheet__scrim"));
    expect(dialog()).not.toBeNull();
    // The press alone does not close it: closing waits for the click, after the browser has moved
    // focus, so focus can then be restored to the opener.
    press(q(".diq-sheet__scrim"));
    expect(dialog()).not.toBeNull();
    // Simulate the browser's default mousedown action: focus falls to the page.
    act(() => (document.activeElement as HTMLElement).blur());
    click(q(".diq-sheet__scrim"));
    expect(dialog()).toBeNull();
    expect(active()).toBe(q("#opener"));
    click(q("#opener"));
    click(q(".diq-sheet__close"));
    expect(dialog()).toBeNull();
  });

  it("Escape in a popover inside the sheet closes only the popover", () => {
    render(<Sheet withMenu />);
    click(q("#opener"));
    const columns = Array.from(document.querySelectorAll<HTMLElement>("[aria-haspopup]")).find(
      (b) => b.textContent === "Columns",
    ) as HTMLElement;
    click(columns);
    key(active() as Element, "Escape");
    expect(dialog()).not.toBeNull();
    expect(active()).toBe(columns);
    key(columns, "Escape");
    expect(dialog()).toBeNull();
  });

  it("leaves a toast region outside the inert page so announcements still arrive", () => {
    render(
      <>
        <Sheet />
        <ToastRegion />
      </>,
    );
    click(q("#opener"));
    expect(q("[data-diq-live]").hasAttribute("inert")).toBe(false);
  });

  it("has no axe violations (default and wide)", async () => {
    render(<Sheet />);
    click(q("#opener"));
    expect(await run(dialog() as HTMLElement)).toEqual([]);
    render(
      <SideSheet open onClose={() => undefined} title="Wide" width="wide">
        <p>Body</p>
      </SideSheet>,
    );
    expect(await run(document.body)).toEqual([]);
  });
});

describe("Toast", () => {
  function Host(props: { readonly onAction: () => void; readonly onDismiss?: () => void }) {
    const [on, setOn] = useState(false);
    return (
      <>
        <button type="button" id="go" onClick={() => setOn(true)}>
          go
        </button>
        <ToastRegion>
          {on ? (
            <Toast
              tone="ok"
              action={{ label: "Undo", onAction: props.onAction }}
              onDismiss={() => {
                props.onDismiss?.();
                setOn(false);
              }}
            >
              Schedule saved. <b>Nothing sent yet.</b>
            </Toast>
          ) : null}
        </ToastRegion>
      </>
    );
  }
  it("is announced politely: the live region exists before the toast and the toast lands in it", () => {
    render(<Host onAction={() => undefined} />);
    const region = q("[data-diq-live]");
    expect(region.getAttribute("role")).toBe("status");
    expect(region.getAttribute("aria-live")).toBe("polite");
    expect(region.textContent).toBe("");
    click(q("#go"));
    expect(region.textContent).toContain("Schedule saved.");
  });
  it("the action fires once, then the toast is dismissed", () => {
    const onAction = vi.fn();
    const onDismiss = vi.fn();
    render(<Host onAction={onAction} onDismiss={onDismiss} />);
    click(q("#go"));
    const undo = Array.from(document.querySelectorAll<HTMLElement>("button")).find(
      (b) => b.textContent === "Undo",
    ) as HTMLElement;
    click(undo);
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onDismiss).toHaveBeenCalledTimes(1);
    expect(maybe(".diq-toast")).toBeNull();
  });
  it("an action activated from the keyboard hands focus back to where the user came from", () => {
    render(<Host onAction={() => undefined} />);
    click(q("#go"));
    q("#go").focus();
    const undo = Array.from(document.querySelectorAll<HTMLElement>("button")).find(
      (b) => b.textContent === "Undo",
    ) as HTMLElement;
    act(() => undo.focus());
    expect(active()).toBe(undo);
    click(undo);
    expect(maybe(".diq-toast")).toBeNull();
    expect(active()).toBe(q("#go"));
  });
  it("Dismiss closes without running the action", () => {
    const onAction = vi.fn();
    render(<Host onAction={onAction} />);
    click(q("#go"));
    click(q('[aria-label="Dismiss"]'));
    expect(onAction).not.toHaveBeenCalled();
    expect(maybe(".diq-toast")).toBeNull();
  });
  it("has no axe violations (info, ok, with and without action)", async () => {
    render(
      <ToastRegion>
        <Toast>Plain</Toast>
        <Toast
          tone="ok"
          action={{ label: "Run details", onAction: () => undefined }}
          onDismiss={() => undefined}
        >
          {"A very long message ".repeat(20)}
        </Toast>
      </ToastRegion>,
    );
    expect(await run(document.body)).toEqual([]);
  });
});
