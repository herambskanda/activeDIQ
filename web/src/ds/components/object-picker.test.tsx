// @vitest-environment jsdom
import axe from "axe-core";
import { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { navigate } from "../../app/location";
import { Link, ObjectPicker, type PickerAnswer, type PickerObject } from "./index";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const jsmith = (n: number, enabled = true): PickerObject => ({
  id: `00000000-0000-4000-8000-00000000000${n}`,
  name: "J. Smith",
  identifier: `jsmith${n} · jsmith${n}@corp.example.test`,
  path: `OU path Dept ${n}`,
  enabled,
});

function must<T>(v: T | null | undefined): T {
  if (v == null) throw new Error("expected a value");
  return v;
}
let host: HTMLElement;
beforeEach(() => {
  vi.useFakeTimers();
  host = document.createElement("div");
  document.body.append(host);
});
afterEach(() => {
  vi.useRealTimers();
  host.remove();
});

function Harness({
  search,
  max,
}: {
  search: (t: string, s: AbortSignal) => Promise<PickerAnswer>;
  max?: number;
}) {
  const [v, setV] = useState<readonly PickerObject[]>([]);
  return (
    <ObjectPicker
      label="Users"
      kind="user"
      value={v}
      onChange={setV}
      search={search}
      {...(max ? { max } : {})}
    />
  );
}
async function mount(node: React.ReactNode) {
  await act(async () => createRoot(host).render(node));
}
async function typeText(text: string) {
  const input = must(host.querySelector<HTMLInputElement>("input"));
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
const wait = (ms: number) =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });

describe("ObjectPicker", () => {
  it("waits for a pause, asks the server once, and shows path and disabled state", async () => {
    const search = vi.fn<(text: string, signal: AbortSignal) => Promise<PickerAnswer>>(
      async () => ({
        items: [jsmith(1), jsmith(2, false)],
      }),
    );
    await mount(<Harness search={search} />);
    await typeText("js");
    await typeText("jsm");
    await wait(100);
    expect(search).not.toHaveBeenCalled();
    await wait(200);
    expect(search).toHaveBeenCalledTimes(1);
    expect(search.mock.calls[0]?.[0]).toBe("jsm");
    const opts = [...host.querySelectorAll('[role="option"]')];
    expect(opts).toHaveLength(2);
    expect(opts[0]?.textContent).toContain("Dept 1");
    expect(opts[1]?.textContent).toContain("Disabled");
  });

  it("drops an answer to text that has since changed", async () => {
    let first!: (a: PickerAnswer) => void;
    const search = vi
      .fn()
      .mockImplementationOnce(() => new Promise<PickerAnswer>((r) => (first = r)))
      .mockResolvedValueOnce({ items: [jsmith(2)] });
    await mount(<Harness search={search} />);
    await typeText("ab");
    await wait(250);
    await typeText("abc");
    await wait(250);
    await act(async () => first({ items: [jsmith(1)] }));
    const opts = [...host.querySelectorAll('[role="option"]')];
    expect(opts).toHaveLength(1);
    expect(opts[0]?.textContent).toContain("Dept 2");
  });

  it("chooses with the keyboard, then lists the chosen object with a Remove button", async () => {
    await mount(<Harness search={async () => ({ items: [jsmith(1)] })} />);
    await typeText("jsmith");
    await wait(250);
    const input = must(host.querySelector("input"));
    for (const key of ["ArrowDown", "Enter"]) {
      await act(async () => {
        input.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
      });
    }
    expect(host.querySelector('ul[aria-label="Chosen users"]')?.textContent).toContain("J. Smith");
    expect(host.querySelector('button[aria-label="Remove J. Smith"]')).toBeTruthy();
  });

  it("says when the text is too broad, and when nothing matches, and when the search fails", async () => {
    const answers: (PickerAnswer | Error)[] = [
      { items: [], refine: true },
      { items: [] },
      new Error("down"),
    ];
    const search = vi.fn(async () => {
      const a = must(answers.shift());
      if (a instanceof Error) throw a;
      return a;
    });
    await mount(<Harness search={search} />);
    for (const expected of ["Too many matches", "No user matches", "search failed"]) {
      await typeText(`x${answers.length}x`);
      await wait(250);
      expect(host.textContent).toContain(expected);
    }
  });

  it("refuses more than max and says so", async () => {
    await mount(<Harness max={1} search={async () => ({ items: [jsmith(1)] })} />);
    await typeText("jsmith");
    await wait(250);
    await act(async () => {
      must(host.querySelector<HTMLElement>('[role="option"]')).dispatchEvent(
        new MouseEvent("mousedown", { bubbles: true }),
      );
      host.querySelector<HTMLElement>('[role="option"]')?.click();
    });
    expect(host.textContent).toContain("You can choose up to 1 users");
  });

  it("has no automated accessibility violations", async () => {
    vi.useRealTimers();
    await mount(<Harness search={async () => ({ items: [jsmith(1)] })} />);
    const result = await axe.run(host, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations).toEqual([]);
  });
});

describe("Link", () => {
  it("moves inside the console on a plain click, and leaves modified clicks to the browser", async () => {
    window.history.replaceState(null, "", "/");
    await mount(<Link to="/reports/a%20b">Report</Link>);
    const a = must(host.querySelector("a"));
    expect(a.getAttribute("href")).toBe("/reports/a%20b");
    await act(async () => {
      a.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, ctrlKey: true }));
    });
    expect(window.location.pathname).toBe("/");
    await act(async () => {
      a.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    });
    expect(window.location.pathname).toBe("/reports/a%20b");
    navigate("/");
  });

  it("renders anything that is not a console path as plain text", async () => {
    for (const to of ["https://evil.test", "//evil.test", "javascript:alert(1)", "/\\evil.test"]) {
      host.replaceChildren();
      const h = document.createElement("div");
      host.append(h);
      await act(async () => createRoot(h).render(<Link to={to}>x</Link>));
      expect(h.querySelector("a")).toBeNull();
    }
  });
});
