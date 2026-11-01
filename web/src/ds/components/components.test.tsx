// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";

import {
  Banner,
  Button,
  Chip,
  Kbd,
  Progress,
  Skeleton,
  StatePanel,
  Table,
  TextInput,
} from "./index";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function render(node: React.ReactNode): HTMLElement {
  const host = document.createElement("div");
  document.body.append(host);
  act(() => createRoot(host).render(node));
  return host;
}

/** The first element matching `selector`; throws so a missing element fails the test clearly. */
function q<T extends HTMLElement = HTMLElement>(host: ParentNode, selector: string): T {
  const el = host.querySelector<T>(selector);
  if (el === null) throw new Error(`no element matches ${selector}`);
  return el;
}

describe("Button", () => {
  it("defaults to type=button and fires onClick", () => {
    const onClick = vi.fn();
    const el = q<HTMLButtonElement>(render(<Button onClick={onClick}>Go</Button>), "button");
    expect(el.type).toBe("button");
    act(() => el.click());
    expect(onClick).toHaveBeenCalledOnce();
  });
  it("ignores clicks while loading, stays focusable and announces busy", () => {
    const onClick = vi.fn();
    const el = q<HTMLButtonElement>(
      render(
        <Button loading onClick={onClick}>
          Go
        </Button>,
      ),
      "button",
    );
    act(() => el.click());
    expect(onClick).not.toHaveBeenCalled();
    expect(el.disabled).toBe(false);
    expect(el.getAttribute("aria-busy")).toBe("true");
  });
});

describe("TextInput", () => {
  it("labels the input and links the error", () => {
    const host = render(<TextInput label="Search" error="Too short" />);
    const input = q<HTMLInputElement>(host, "input");
    expect(q<HTMLLabelElement>(host, "label").htmlFor).toBe(input.id);
    expect(input.getAttribute("aria-invalid")).toBe("true");
    const describedBy = input.getAttribute("aria-describedby") ?? "";
    expect(q(host, `[id="${describedBy}"]`).textContent).toBe("Too short");
  });
  it("has no description when valid", () => {
    const input = q(render(<TextInput label="Search" />), "input");
    expect(input.getAttribute("aria-invalid")).toBe("false");
    expect(input.hasAttribute("aria-describedby")).toBe(false);
  });
});

describe("Table", () => {
  it("renders headers, row headers and the full text in titles for long values", () => {
    const long = "x".repeat(64);
    const host = render(
      <Table
        caption="People"
        rows={[{ id: "1", name: long }]}
        rowKey={(r) => r.id}
        columns={[
          { key: "n", header: "Name", rowHeader: true, cell: (r) => r.name, title: (r) => r.name },
        ]}
      />,
    );
    expect(q(host, "caption").textContent).toBe("People");
    expect(q(host, "thead th").getAttribute("scope")).toBe("col");
    const rowHeader = q(host, "tbody th");
    expect(rowHeader.getAttribute("scope")).toBe("row");
    expect(rowHeader.getAttribute("title")).toBe(long);
  });
});

describe("Chip, Skeleton, StatePanel", () => {
  it("chip carries its text and tone class", () => {
    const el = q(render(<Chip tone="muted">Disabled</Chip>), ".diq-chip");
    expect(el.className).toContain("diq-chip--muted");
    expect(el.textContent).toBe("Disabled");
  });
  it("skeleton is a named status with the given rows", () => {
    const el = q(render(<Skeleton rows={3} label="Loading" />), "[role=status]");
    expect(el.getAttribute("aria-label")).toBe("Loading");
    expect(el.children).toHaveLength(3);
  });
  it("error panel is an alert; neutral is not", () => {
    expect(
      render(<StatePanel tone="error" title="Bad" />).querySelector("[role=alert]"),
    ).not.toBeNull();
    expect(render(<StatePanel title="Empty" />).querySelector("[role=alert]")).toBeNull();
  });
});

describe("Chip warn and crit", () => {
  it("add a glyph of a different shape, hidden from assistive tech, so tones differ without colour", () => {
    const warn = q(render(<Chip tone="warn">Stale</Chip>), ".diq-chip");
    const crit = q(render(<Chip tone="crit">Failed</Chip>), ".diq-chip");
    const wg = q(warn, ".diq-chip__glyph");
    const cg = q(crit, ".diq-chip__glyph");
    expect(wg.getAttribute("aria-hidden")).toBe("true");
    expect(wg.textContent).not.toBe(cg.textContent);
    expect(warn.className).toContain("diq-chip--warn");
    expect(crit.className).toContain("diq-chip--crit");
    expect(warn.textContent).toContain("Stale");
  });
  it("ok and muted stay text-only", () => {
    expect(render(<Chip tone="ok">Synced</Chip>).querySelector(".diq-chip__glyph")).toBeNull();
  });
});

describe("Banner", () => {
  it.each(["info", "warn", "crit"] as const)("%s carries a glyph and its text", (tone) => {
    const el = q(
      render(
        <Banner tone={tone} title="Stale data">
          Last sync was 3 hours ago.
        </Banner>,
      ),
      ".diq-banner",
    );
    expect(q(el, ".diq-banner__glyph").textContent?.length).toBeGreaterThan(0);
    expect(q(el, ".diq-banner__glyph").getAttribute("aria-hidden")).toBe("true");
    expect(el.textContent).toContain("Stale data");
    expect(el.textContent).toContain("Last sync was 3 hours ago.");
  });
  it("uses a different glyph per tone", () => {
    const glyphs = (["info", "warn", "crit"] as const).map(
      (t) => q(render(<Banner tone={t}>x</Banner>), ".diq-banner__glyph").textContent,
    );
    expect(new Set(glyphs).size).toBe(3);
  });
  it("announces crit as an alert and the others politely", () => {
    expect(q(render(<Banner tone="crit">x</Banner>), ".diq-banner").getAttribute("role")).toBe(
      "alert",
    );
    expect(q(render(<Banner tone="warn">x</Banner>), ".diq-banner").getAttribute("role")).toBe(
      "status",
    );
    expect(q(render(<Banner tone="info">x</Banner>), ".diq-banner").getAttribute("role")).toBe(
      "status",
    );
  });
  it("fires an action's callback", () => {
    const onClick = vi.fn();
    const host = render(
      <Banner tone="warn" actions={<Button onClick={onClick}>Resync</Button>}>
        x
      </Banner>,
    );
    act(() => q<HTMLButtonElement>(host, "button").click());
    expect(onClick).toHaveBeenCalledOnce();
  });
});

describe("Progress", () => {
  it("is a named progressbar with aria values when determinate", () => {
    const el = q(render(<Progress label="Run progress" value={33} />), "[role=progressbar]");
    expect(el.getAttribute("aria-label")).toBe("Run progress");
    expect(el.getAttribute("aria-valuemin")).toBe("0");
    expect(el.getAttribute("aria-valuemax")).toBe("100");
    expect(el.getAttribute("aria-valuenow")).toBe("33");
    expect(q(el, ".diq-progress__bar").style.inlineSize).toBe("33%");
  });
  it("omits aria-valuenow when indeterminate", () => {
    const el = q(render(<Progress label="Running" />), "[role=progressbar]");
    expect(el.hasAttribute("aria-valuenow")).toBe(false);
    expect(el.getAttribute("aria-valuemax")).toBe("100");
    expect(el.className).toContain("diq-progress--indeterminate");
  });
  it("clamps to the range and honours max", () => {
    const over = q(render(<Progress label="x" value={150} />), "[role=progressbar]");
    expect(over.getAttribute("aria-valuenow")).toBe("100");
    const custom = q(render(<Progress label="x" value={6} max={12} />), "[role=progressbar]");
    expect(custom.getAttribute("aria-valuemax")).toBe("12");
    expect(q(custom, ".diq-progress__bar").style.inlineSize).toBe("50%");
  });
});

describe("Kbd", () => {
  it("renders a kbd element", () => {
    const el = q(render(<Kbd>E</Kbd>), "kbd");
    expect(el.className).toBe("diq-kbd");
    expect(el.textContent).toBe("E");
  });
});

describe("StatePanel actions", () => {
  it("fires the callback of an activated action", () => {
    const onClick = vi.fn();
    const host = render(
      <StatePanel title="This run failed" actions={<Button onClick={onClick}>Retry</Button>}>
        <p>Nothing was changed.</p>
      </StatePanel>,
    );
    act(() => q<HTMLButtonElement>(q(host, ".diq-state__actions"), "button").click());
    expect(onClick).toHaveBeenCalledOnce();
  });
  it("renders no actions wrapper without actions", () => {
    expect(render(<StatePanel title="Empty" />).querySelector(".diq-state__actions")).toBeNull();
  });
});
