// @vitest-environment jsdom
import axe from "axe-core";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import { DataGrid, DeltaCell, type DeltaDirection, PinnedBand } from "./index";

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
const run = async (host: HTMLElement) => {
  const r = await axe.run(host, { rules: { "color-contrast": { enabled: false } } });
  return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`);
};

describe("DeltaCell", () => {
  const spoken = (d: DeltaDirection, amount?: string) => {
    const host = render(
      <DeltaCell
        value="12 characters"
        direction={d}
        amount={amount}
        comparedTo="the domain policy"
      />,
    );
    return q(host, ".diq-sr-only").textContent;
  };
  it("says each direction as a sentence, with the amount", () => {
    expect(spoken("stricter", "+12")).toBe(" (stricter than the domain policy, +12)");
    expect(spoken("weaker", "−2")).toBe(" (weaker than the domain policy, −2)");
    expect(spoken("same")).toBe(" (same as the domain policy)");
    expect(spoken("differs")).toBe(" (differs from the domain policy)");
  });
  it("shows glyph and number, hidden from assistive technology (the sentence replaces them)", () => {
    const host = render(
      <DeltaCell value="8" direction="weaker" amount="−2" comparedTo="the domain" />,
    );
    const visible = q(host, '[aria-hidden="true"]');
    expect(visible.textContent).toBe("▼ −2");
    expect(q(host, ".diq-delta__value").textContent).toBe("8");
  });
  it("has a distinct glyph per direction, so colour is never the only signal", () => {
    const glyphs = (["stricter", "weaker", "same", "differs"] as const).map((d) => {
      const host = render(<DeltaCell value="x" direction={d} comparedTo="b" />);
      return q(host, '[aria-hidden="true"]').textContent;
    });
    expect(new Set(glyphs).size).toBe(4);
  });
  it("only weaker has its own colour class; stricter is plain", () => {
    const cls = (d: DeltaDirection) =>
      q(render(<DeltaCell value="x" direction={d} comparedTo="b" />), ".diq-delta__mark").className;
    expect(cls("weaker")).toContain("diq-delta__mark--weaker");
    expect(cls("stricter")).toContain("diq-delta__mark--stricter");
  });
  it("showWord adds the word to the visible mark", () => {
    const host = render(
      <DeltaCell value="x" direction="stricter" amount="+1" comparedTo="b" showWord />,
    );
    expect(q(host, '[aria-hidden="true"]').textContent).toBe("▲ +1 stricter");
  });
  it("works in a grid cell and has no axe violations", async () => {
    const host = render(
      <DataGrid
        caption="Policies, 2 rows"
        columns={[
          { key: "n", header: "Policy", rowHeader: true, cell: (r: string) => r },
          {
            key: "len",
            header: "Length",
            title: () => "14, stricter",
            cell: () => (
              <DeltaCell
                value="14"
                direction="stricter"
                amount="+4"
                comparedTo="the domain policy"
              />
            ),
          },
        ]}
        rows={["PSO-A", "PSO-B"]}
        rowKey={(r) => r}
      />,
    );
    expect(await run(host)).toEqual([]);
  });
});

describe("PinnedBand", () => {
  const DCS = Array.from({ length: 7 }, (_, i) => ({
    id: `dc${i}`,
    dc: `DC-${i}`,
    why: `RPC unavailable ${i}`,
  }));
  const band = (n: number, limit?: number) => (
    <PinnedBand
      label={`Did not answer (${n})`}
      note="pinned: a blind spot matters more than any row below"
      items={DCS.slice(0, n)}
      itemKey={(d) => d.id}
      limit={limit}
    >
      {(d) => (
        <>
          <b>{d.dc}</b>
          <span>{d.why}</span>
        </>
      )}
    </PinnedBand>
  );
  it("is a group named by its label, with one list item per DC", () => {
    const host = render(band(3));
    const g = q(host, '[role="group"]');
    expect(g.getAttribute("aria-labelledby")).toBe(q(host, ".diq-pinned__label").id);
    expect(q(host, ".diq-pinned__label").textContent).toBe("Did not answer (3)");
    expect(host.querySelectorAll("li")).toHaveLength(3);
    expect(host.querySelector("button")).toBeNull();
    expect(host.querySelector('[role="rowgroup"]')).toBeNull();
  });
  it("renders nothing when there is nothing to pin", () => {
    expect(render(band(0)).textContent).toBe("");
  });
  it("shows 4, then all on request; the list is a keyboard-reachable scroll box only when expanded", () => {
    const host = render(band(7));
    expect(host.querySelectorAll("li")).toHaveLength(4);
    const more = q(host, "button");
    expect(more.textContent).toBe("Show 3 more");
    expect(more.getAttribute("aria-expanded")).toBe("false");
    expect(q(host, "ul").getAttribute("tabindex")).toBeNull();
    act(() => more.click());
    expect(host.querySelectorAll("li")).toHaveLength(7);
    expect(more.getAttribute("aria-expanded")).toBe("true");
    expect(more.textContent).toBe("Show fewer");
    expect(q(host, "ul").getAttribute("tabindex")).toBe("0");
    expect(q(host, "ul").getAttribute("aria-label")).toBe("Did not answer (7)");
    act(() => more.click());
    expect(host.querySelectorAll("li")).toHaveLength(4);
  });
  it("is not part of the grid it sits above, so sorting the grid cannot move it", () => {
    const host = render(
      <>
        {band(2)}
        <DataGrid
          caption="Rows"
          columns={[
            { key: "n", header: "N", rowHeader: true, sortable: true, cell: (r: string) => r },
          ]}
          rows={["b", "a"]}
          rowKey={(r) => r}
        />
      </>,
    );
    expect(q(host, "table").contains(q(host, ".diq-pinned"))).toBe(false);
  });
  it.each(["crit", "warn", "info"] as const)(
    "has no axe violations (%s, collapsed and expanded)",
    async (tone) => {
      const host = render(
        <PinnedBand label="Not read (7)" tone={tone} items={DCS} itemKey={(d) => d.id}>
          {(d) => <b>{d.dc}</b>}
        </PinnedBand>,
      );
      expect(await run(host)).toEqual([]);
      act(() => q(host, "button").click());
      expect(await run(host)).toEqual([]);
    },
  );
});
