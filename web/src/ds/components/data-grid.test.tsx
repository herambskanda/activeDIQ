// @vitest-environment jsdom
import axe from "axe-core";
import { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";

import tokens from "../tokens.css?raw";
import { FALLBACK_ROW_PX } from "./data-grid";
import { DataGrid, type DataGridColumn, type DataGridSort } from "./index";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

interface Person {
  readonly id: string;
  readonly name: string;
  readonly dept: string;
  readonly n: number;
}
const people = (count: number): Person[] =>
  Array.from({ length: count }, (_, i) => ({
    id: `u${i}`,
    name: `Person ${String(i).padStart(5, "0")} ${"x".repeat(40 - 13)}`,
    dept: `Dept ${i % 7}`,
    n: i,
  }));

const COLS: DataGridColumn<Person>[] = [
  { key: "name", header: "Name", rowHeader: true, sortable: true, width: 12, cell: (p) => p.name },
  { key: "dept", header: "Department", sortable: true, cell: (p) => p.dept },
  { key: "n", header: "Count", align: "end", cell: (p) => p.n },
];

function render(node: React.ReactNode): HTMLElement {
  const host = document.createElement("div");
  document.body.append(host);
  act(() => createRoot(host).render(node));
  return host;
}
const all = (host: ParentNode, sel: string) => Array.from(host.querySelectorAll<HTMLElement>(sel));
function q(host: ParentNode, sel: string): HTMLElement {
  const el = host.querySelector<HTMLElement>(sel);
  if (!el) throw new Error(`no element matches ${sel}`);
  return el;
}
const cell = (host: ParentNode, r: number, c: number) => q(host, `[data-r="${r}"][data-c="${c}"]`);
function key(el: HTMLElement, k: string, init: KeyboardEventInit = {}) {
  act(() => {
    el.dispatchEvent(
      new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true, ...init }),
    );
  });
}

function Sortable({ onSort }: { onSort: (k: string) => void }) {
  const [sort, setSort] = useState<DataGridSort | null>(null);
  return (
    <DataGrid
      caption="People, 3 rows"
      columns={COLS}
      rows={people(3)}
      rowKey={(p) => p.id}
      sort={sort}
      onSort={(k) => {
        onSort(k);
        setSort((s) =>
          s?.key === k && s.dir === "asc" ? { key: k, dir: "desc" } : { key: k, dir: "asc" },
        );
      }}
    />
  );
}

function Selectable({ count = 6 }: { count?: number }) {
  const [sel, setSel] = useState<ReadonlySet<string>>(new Set());
  return (
    <DataGrid
      caption="People"
      columns={COLS}
      rows={people(count)}
      rowKey={(p) => p.id}
      selected={sel}
      onSelectedChange={setSel}
    />
  );
}

describe("DataGrid virtualisation", () => {
  it("renders about 22 of 12,000 rows, and a similar window after scrolling", () => {
    const host = render(
      <DataGrid
        caption="People, 12,000 rows"
        columns={COLS}
        rows={people(12000)}
        rowKey={(p) => p.id}
      />,
    );
    const n = all(host, "tbody tr[data-row]").length;
    expect(n).toBeGreaterThanOrEqual(15);
    expect(n).toBeLessThanOrEqual(24);
    const scroller = q(host, ".diq-grid");
    act(() => {
      scroller.scrollTop = FALLBACK_ROW_PX * 6000;
      scroller.dispatchEvent(new Event("scroll"));
    });
    const rows = all(host, "tbody tr[data-row]");
    expect(rows.length).toBeLessThanOrEqual(24);
    expect(Number(rows[0]?.dataset.row)).toBeGreaterThan(5900);
    expect(q(host, "table").getAttribute("aria-rowcount")).toBe("12001");
  });
  it("keeps the spacer heights equal to the rows not rendered", () => {
    const host = render(
      <DataGrid caption="People" columns={COLS} rows={people(500)} rowKey={(p) => p.id} />,
    );
    const rendered = all(host, "tbody tr[data-row]").length;
    const spacer = q(host, "tbody tr[aria-hidden]");
    expect(parseFloat(spacer.style.height)).toBe((500 - rendered) * FALLBACK_ROW_PX);
  });
  it("fallback row height equals --diq-row-compact", () => {
    expect(tokens).toContain(`--diq-row-compact: ${FALLBACK_ROW_PX}px;`);
  });
});

describe("DataGrid sorting", () => {
  it("click and keyboard each fire onSort once and update aria-sort", () => {
    const onSort = vi.fn();
    const host = render(<Sortable onSort={onSort} />);
    const name = cell(host, 0, 0);
    expect(name.getAttribute("aria-sort")).toBe("none");
    act(() => name.click());
    expect(onSort).toHaveBeenCalledTimes(1);
    expect(onSort).toHaveBeenLastCalledWith("name");
    expect(name.getAttribute("aria-sort")).toBe("ascending");
    name.focus();
    key(name, "Enter");
    expect(onSort).toHaveBeenCalledTimes(2);
    expect(name.getAttribute("aria-sort")).toBe("descending");
    key(cell(host, 0, 1), " ");
    expect(onSort).toHaveBeenCalledTimes(3);
    expect(cell(host, 0, 1).getAttribute("aria-sort")).toBe("ascending");
    expect(q(host, "[role=status]").textContent).toBe("Sorted by Department, ascending");
  });
  it("a column that is not sortable has no aria-sort and ignores activation", () => {
    const onSort = vi.fn();
    const host = render(
      <DataGrid caption="P" columns={COLS} rows={people(2)} rowKey={(p) => p.id} onSort={onSort} />,
    );
    const count = cell(host, 0, 2);
    expect(count.hasAttribute("aria-sort")).toBe(false);
    act(() => count.click());
    key(count, "Enter");
    expect(onSort).not.toHaveBeenCalled();
  });
});

describe("DataGrid truncation and structure", () => {
  it("puts the full text of a 40-character value in title, in a row header", () => {
    const host = render(
      <DataGrid caption="People" columns={COLS} rows={people(2)} rowKey={(p) => p.id} />,
    );
    const rh = q(host, "tbody th");
    expect(rh.getAttribute("scope")).toBe("row");
    expect(rh.getAttribute("title")).toHaveLength(40);
    expect(rh.getAttribute("title")).toBe(rh.textContent);
    expect(q(host, "caption").textContent).toBe("People");
  });
  it("shows the empty slot when there are no rows", () => {
    const host = render(
      <DataGrid
        caption="P"
        columns={COLS}
        rows={[]}
        rowKey={(p) => p.id}
        empty={<p>Nothing here</p>}
      />,
    );
    expect(host.textContent).toContain("Nothing here");
  });
  it("sets aria-busy while busy", () => {
    const host = render(
      <DataGrid caption="P" columns={COLS} rows={people(2)} rowKey={(p) => p.id} busy />,
    );
    expect(q(host, "table").getAttribute("aria-busy")).toBe("true");
  });
});

describe("DataGrid keyboard", () => {
  it("has one tab stop and arrows, Home, End, Page keys and Ctrl+Home/End move between cells", () => {
    const host = render(
      <DataGrid caption="People" columns={COLS} rows={people(100)} rowKey={(p) => p.id} />,
    );
    expect(all(host, '[data-r][tabindex="0"]')).toHaveLength(1);
    const start = cell(host, 0, 0);
    start.focus();
    key(start, "ArrowDown");
    expect(document.activeElement).toBe(cell(host, 1, 0));
    key(document.activeElement as HTMLElement, "ArrowRight");
    expect(document.activeElement).toBe(cell(host, 1, 1));
    key(document.activeElement as HTMLElement, "End");
    expect(document.activeElement).toBe(cell(host, 1, 2));
    key(document.activeElement as HTMLElement, "ArrowRight"); // stops at the edge
    expect(document.activeElement).toBe(cell(host, 1, 2));
    key(document.activeElement as HTMLElement, "Home");
    expect(document.activeElement).toBe(cell(host, 1, 0));
    key(document.activeElement as HTMLElement, "ArrowUp");
    key(document.activeElement as HTMLElement, "ArrowUp"); // header is the top
    expect(document.activeElement).toBe(cell(host, 0, 0));
    key(document.activeElement as HTMLElement, "End", { ctrlKey: true });
    expect(document.activeElement).toBe(cell(host, 100, 2));
    expect(all(host, "tbody tr[data-row]").length).toBeLessThanOrEqual(24);
    key(document.activeElement as HTMLElement, "PageUp");
    expect(Number((document.activeElement as HTMLElement).dataset.r)).toBe(100 - 14);
    key(document.activeElement as HTMLElement, "Home", { ctrlKey: true });
    expect(document.activeElement).toBe(cell(host, 0, 0));
    expect(all(host, '[data-r][tabindex="0"]')).toHaveLength(1);
  });
  it("Enter on a row cell activates the row; Enter on a cell with a widget moves into it and Escape returns", () => {
    const onRowActivate = vi.fn();
    const cols: DataGridColumn<Person>[] = [
      ...COLS.slice(0, 1),
      { key: "act", header: "Action", cell: (p) => <button type="button">Open {p.id}</button> },
    ];
    const host = render(
      <DataGrid
        caption="P"
        columns={cols}
        rows={people(3)}
        rowKey={(p) => p.id}
        onRowActivate={onRowActivate}
      />,
    );
    const nameCell = cell(host, 1, 0);
    nameCell.focus();
    key(nameCell, "Enter");
    expect(onRowActivate).toHaveBeenCalledTimes(1);
    const actCell = cell(host, 1, 1);
    const btn = q(actCell, "button");
    expect(btn.tabIndex).toBe(-1); // not a tab stop until its cell is active
    act(() => actCell.focus());
    expect(btn.tabIndex).toBe(0);
    key(actCell, "Enter");
    expect(document.activeElement).toBe(btn);
    key(btn, "Escape");
    expect(document.activeElement).toBe(actCell);
  });
  it("mirrors the arrows in right-to-left", () => {
    const host = render(
      <div dir="rtl">
        <DataGrid caption="P" columns={COLS} rows={people(3)} rowKey={(p) => p.id} />
      </div>,
    );
    const c0 = cell(host, 1, 0);
    c0.focus();
    key(c0, "ArrowLeft");
    expect(document.activeElement).toBe(cell(host, 1, 1));
  });
});

describe("DataGrid selection", () => {
  it("toggles with the checkbox cell, Space, shift-click ranges and select all", () => {
    const host = render(<Selectable />);
    const isOn = (r: number) => (q(cell(host, r, 0), "input") as HTMLInputElement).checked;
    act(() => cell(host, 2, 0).click());
    expect(isOn(2)).toBe(true);
    expect(all(host, "tr[aria-selected=true]")).toHaveLength(1);
    act(() =>
      cell(host, 5, 0).dispatchEvent(new MouseEvent("click", { bubbles: true, shiftKey: true })),
    );
    expect(all(host, "tr[aria-selected=true]")).toHaveLength(4); // rows 2..5
    const first = cell(host, 1, 1);
    first.focus();
    key(first, " ");
    expect(all(host, "tr[aria-selected=true]")).toHaveLength(5);
    const head = cell(host, 0, 0);
    const box = q(head, "input") as HTMLInputElement;
    expect(box.indeterminate).toBe(true);
    act(() => head.click());
    expect(all(host, "tr[aria-selected=true]")).toHaveLength(6);
    expect(q(host, "[role=status]").textContent).toBe("6 of 6 selected");
    act(() => head.click());
    expect(all(host, "tr[aria-selected=true]")).toHaveLength(0);
    expect(q(host, "table").getAttribute("aria-multiselectable")).toBe("true");
  });
  it("is not selectable without onSelectedChange", () => {
    const host = render(
      <DataGrid caption="P" columns={COLS} rows={people(2)} rowKey={(p) => p.id} />,
    );
    expect(host.querySelector("input")).toBeNull();
    expect(host.querySelector("[aria-multiselectable]")).toBeNull();
  });
});

describe("DataGrid column sizing", () => {
  it("Shift+Arrow on a header resizes by steps and reports it, within limits", () => {
    const onColumnResize = vi.fn();
    const host = render(
      <DataGrid
        caption="P"
        columns={COLS}
        rows={people(2)}
        rowKey={(p) => p.id}
        resizable
        onColumnResize={onColumnResize}
      />,
    );
    const h = cell(host, 0, 0);
    h.focus();
    key(h, "ArrowRight", { shiftKey: true });
    expect(onColumnResize).toHaveBeenLastCalledWith("name", 14);
    expect(q(host, "col:nth-child(1)").style.width).toBe("14ch");
    for (let i = 0; i < 10; i++) key(h, "ArrowLeft", { shiftKey: true });
    expect(onColumnResize).toHaveBeenLastCalledWith("name", 6);
    expect(document.activeElement).toBe(h); // resizing does not move focus
  });
  it("ignores Shift+Arrow when not resizable and moves instead", () => {
    const host = render(
      <DataGrid caption="P" columns={COLS} rows={people(2)} rowKey={(p) => p.id} />,
    );
    const h = cell(host, 0, 0);
    h.focus();
    key(h, "ArrowRight", { shiftKey: true });
    expect(document.activeElement).toBe(cell(host, 0, 1));
  });
});

describe("DataGrid accessibility (axe)", () => {
  // Colour contrast needs real layout and styles; it is covered by tokens.test.ts and the Storybook a11y addon.
  const run = async (host: HTMLElement) => {
    const r = await axe.run(host, { rules: { "color-contrast": { enabled: false } } });
    return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`);
  };
  it("has no violations: plain, sortable+resizable, selectable, busy and empty", async () => {
    const hosts = [
      render(<DataGrid caption="People" columns={COLS} rows={people(30)} rowKey={(p) => p.id} />),
      render(<Sortable onSort={() => undefined} />),
      render(
        <DataGrid
          caption="People"
          columns={COLS}
          rows={people(30)}
          rowKey={(p) => p.id}
          resizable
          busy
        />,
      ),
      render(<Selectable />),
      render(
        <DataGrid
          caption="People"
          columns={COLS}
          rows={[]}
          rowKey={(p) => p.id}
          empty={<p>No people</p>}
        />,
      ),
    ];
    for (const h of hosts) expect(await run(h)).toEqual([]);
  });
});
