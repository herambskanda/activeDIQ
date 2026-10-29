// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";

import { Button, Chip, Skeleton, StatePanel, Table, TextInput } from "./index";

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
