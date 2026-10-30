// @vitest-environment jsdom
import axe from "axe-core";
import { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";

import {
  Checkbox,
  RadioCardGroup,
  SegmentedControl,
  Select,
  type Token,
  TokenInput,
  type TokenInputProps,
} from "./index";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function render(node: React.ReactNode): HTMLElement {
  const host = document.createElement("div");
  document.body.append(host);
  act(() => createRoot(host).render(node));
  return host;
}
function q<T extends HTMLElement = HTMLElement>(host: ParentNode, sel: string): T {
  const el = host.querySelector<T>(sel);
  if (el === null) throw new Error(`no element matches ${sel}`);
  return el;
}
const all = (host: ParentNode, sel: string) => Array.from(host.querySelectorAll<HTMLElement>(sel));
/** The element that describes `el` through aria-describedby (every id it lists must exist). */
function descriptions(host: ParentNode, el: HTMLElement): string[] {
  return (el.getAttribute("aria-describedby") ?? "")
    .split(" ")
    .filter(Boolean)
    .map((id) => q(host, `[id="${id}"]`).textContent ?? "");
}
/** Types into a React-controlled input the way a user does: set the value, then fire `input`. */
function type(input: HTMLInputElement, text: string) {
  act(() => {
    const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    set?.call(input, text);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
function press(el: HTMLElement, key: string) {
  const ev = new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true });
  act(() => {
    el.dispatchEvent(ev);
  });
  return ev;
}

const OPTIONS = [
  { value: "csv", label: "CSV (table only)" },
  { value: "xlsx", label: "XLSX (with About sheet)" },
  { value: "pdf", label: "PDF", disabled: true },
];

describe("Select", () => {
  it("is labelled, focusable and reports the chosen value", () => {
    const onChange = vi.fn();
    const host = render(
      <Select label="Format" options={OPTIONS} value="csv" onChange={onChange} />,
    );
    const el = q<HTMLSelectElement>(host, "select");
    expect(q<HTMLLabelElement>(host, "label").htmlFor).toBe(el.id);
    act(() => el.focus());
    expect(document.activeElement).toBe(el);
    act(() => {
      el.value = "xlsx";
      el.dispatchEvent(new Event("change", { bubbles: true }));
    });
    expect(onChange).toHaveBeenCalledWith("xlsx");
    expect(all(host, "option")[2]?.hasAttribute("disabled")).toBe(true);
  });
  it("clears through the placeholder option", () => {
    const onChange = vi.fn();
    const host = render(
      <Select label="Format" options={OPTIONS} value="csv" placeholder="Any" onChange={onChange} />,
    );
    const el = q<HTMLSelectElement>(host, "select");
    expect(el.options[0]?.value).toBe("");
    act(() => {
      el.value = "";
      el.dispatchEvent(new Event("change", { bubbles: true }));
    });
    expect(onChange).toHaveBeenCalledWith("");
  });
  it("links hint and error as the description and marks it invalid", () => {
    const host = render(
      <Select
        label="Format"
        options={OPTIONS}
        value=""
        onChange={() => undefined}
        hint="Pick one"
        error="Choose a format"
      />,
    );
    const el = q(host, "select");
    expect(el.getAttribute("aria-invalid")).toBe("true");
    expect(descriptions(host, el)).toEqual(["Pick one", "Choose a format"]);
  });
  it("read-only shows the chosen label in a focusable field that cannot change", () => {
    const host = render(
      <Select label="Format" options={OPTIONS} value="xlsx" readOnly onChange={() => undefined} />,
    );
    expect(host.querySelector("select")).toBeNull();
    const el = q<HTMLInputElement>(host, "input");
    expect(el.value).toBe("XLSX (with About sheet)");
    expect(el.readOnly).toBe(true);
  });
});

describe("Checkbox", () => {
  it("toggles with a click on the label (Space on the focused box fires the same click)", () => {
    const onChange = vi.fn();
    const host = render(
      <Checkbox label="Only send if there is data" checked={false} onChange={onChange} />,
    );
    const box = q<HTMLInputElement>(host, "input");
    act(() => box.focus());
    expect(document.activeElement).toBe(box);
    act(() => q(host, "label").click());
    expect(onChange).toHaveBeenCalledWith(true);
  });
  it("unchecking clears it", () => {
    const onChange = vi.fn();
    const box = q<HTMLInputElement>(
      render(<Checkbox label="x" checked onChange={onChange} />),
      "input",
    );
    act(() => box.click());
    expect(onChange).toHaveBeenCalledWith(false);
  });
  it("shows indeterminate and drops it from the checked state", () => {
    const box = q<HTMLInputElement>(
      render(<Checkbox label="All" checked={false} indeterminate onChange={() => undefined} />),
      "input",
    );
    expect(box.indeterminate).toBe(true);
  });
  it("read-only is announced and ignores clicks; disabled is not focusable", () => {
    const onChange = vi.fn();
    const ro = q<HTMLInputElement>(
      render(<Checkbox label="x" checked readOnly onChange={onChange} />),
      "input",
    );
    expect(ro.getAttribute("aria-readonly")).toBe("true");
    act(() => ro.click());
    expect(onChange).not.toHaveBeenCalled();
    expect(ro.checked).toBe(true);
    const off = q<HTMLInputElement>(
      render(<Checkbox label="x" checked={false} disabled onChange={onChange} />),
      "input",
    );
    expect(off.disabled).toBe(true);
  });
  it("links description and error", () => {
    const host = render(
      <Checkbox
        label="Confirm"
        checked={false}
        onChange={() => undefined}
        description="Data leaves the organisation"
        error="Tick the box to confirm"
      />,
    );
    const box = q(host, "input");
    expect(box.getAttribute("aria-invalid")).toBe("true");
    expect(descriptions(host, box)).toEqual([
      "Data leaves the organisation",
      "Tick the box to confirm",
    ]);
  });
});

const CHOICES = [
  { value: "daily", label: "Daily", description: "Every day at 06:00" },
  { value: "weekly", label: "Weekly", description: "Mondays at 06:00" },
  { value: "monthly", label: "Monthly", description: "First of the month", disabled: true },
];

for (const [name, Group] of [
  ["RadioCardGroup", RadioCardGroup],
  ["SegmentedControl", SegmentedControl],
] as const) {
  describe(name, () => {
    it("is a named radiogroup; Tab enters on the chosen option only", () => {
      const host = render(
        <Group label="When" options={CHOICES} value="weekly" onChange={() => undefined} />,
      );
      const group = q(host, "[role=radiogroup]");
      expect(group.querySelector("legend")?.textContent).toBe("When");
      const radios = all(host, "input[type=radio]") as HTMLInputElement[];
      expect(radios.map((r) => r.checked)).toEqual([false, true, false]);
      expect(new Set(radios.map((r) => r.name)).size).toBe(1);
      expect(radios[2]?.disabled).toBe(true);
      act(() => radios[1]?.focus());
      expect(document.activeElement).toBe(radios[1]);
    });
    it("changes by selecting an option", () => {
      const onChange = vi.fn();
      const host = render(
        <Group label="When" options={CHOICES} value="weekly" onChange={onChange} />,
      );
      act(() => all(host, "input")[0]?.click());
      expect(onChange).toHaveBeenCalledWith("daily");
    });
    it("clears with the Clear button and keeps focus in the group", () => {
      const onChange = vi.fn();
      const host = render(
        <Group label="When" options={CHOICES} value="weekly" clearable onChange={onChange} />,
      );
      const clear = q(host, "button");
      act(() => clear.focus());
      act(() => clear.click());
      expect(onChange).toHaveBeenCalledWith(null);
      expect((document.activeElement as HTMLInputElement).type).toBe("radio");
    });
    it("offers no Clear before a choice, nor when not clearable", () => {
      expect(
        render(
          <Group
            label="When"
            options={CHOICES}
            value={null}
            clearable
            onChange={() => undefined}
          />,
        ).querySelector("button"),
      ).toBeNull();
      expect(
        render(
          <Group label="When" options={CHOICES} value="daily" onChange={() => undefined} />,
        ).querySelector("button"),
      ).toBeNull();
    });
    it("links the error to the group through aria-describedby", () => {
      const host = render(
        <Group
          label="When"
          options={CHOICES}
          value={null}
          error="Choose when it runs"
          hint="Server time"
          onChange={() => undefined}
        />,
      );
      const group = q(host, "[role=radiogroup]");
      expect(group.getAttribute("aria-invalid")).toBe("true");
      expect(descriptions(host, group)).toEqual(["Server time", "Choose when it runs"]);
    });
    it("disabled disables every option; read-only refuses changes", () => {
      const off = render(
        <Group label="When" options={CHOICES} value="daily" disabled onChange={() => undefined} />,
      );
      expect(q<HTMLFieldSetElement>(off, "fieldset").disabled).toBe(true);
      const onChange = vi.fn();
      const ro = render(
        <Group
          label="When"
          options={CHOICES}
          value="daily"
          readOnly
          clearable
          onChange={onChange}
        />,
      );
      act(() => all(ro, "input")[1]?.click());
      expect(onChange).not.toHaveBeenCalled();
      expect(ro.querySelector("button")).toBeNull();
    });
  });
}

const PEOPLE: Token[] = [
  { id: "a", label: "Amara Okafor", detail: "amara.okafor@corp.example" },
  { id: "b", label: "Bjorn Lindqvist", detail: "bjorn.lindqvist@corp.example" },
  { id: "c", label: "Chen Wei", detail: "chen.wei@corp.example" },
];

/** A controlled TokenInput the way a screen uses it: the caller keeps tokens and filters suggestions. */
function Harness(
  props: Partial<TokenInputProps> & {
    initial?: readonly Token[];
    spy?: (t: readonly Token[]) => void;
  },
) {
  const { initial = [], spy, ...rest } = props;
  const [tokens, setTokens] = useState<readonly Token[]>(initial);
  const [query, setQuery] = useState("");
  const matches =
    query.trim() === ""
      ? []
      : PEOPLE.filter((p) =>
          `${p.label} ${p.detail}`.toLowerCase().includes(query.trim().toLowerCase()),
        );
  return (
    <TokenInput
      label="To"
      value={tokens}
      onChange={(t) => {
        setTokens(t);
        spy?.(t);
      }}
      suggestions={matches}
      onQueryChange={setQuery}
      emptyText="No matches"
      {...rest}
    />
  );
}
const chips = (host: ParentNode) =>
  all(host, ".diq-token__item").map((e) => e.querySelector(".diq-token__text")?.textContent);

describe("TokenInput", () => {
  it("types, shows suggestions, and Enter on the highlighted one adds a token", () => {
    const host = render(<Harness />);
    const input = q<HTMLInputElement>(host, "input");
    expect(q<HTMLLabelElement>(host, "label").htmlFor).toBe(input.id);
    expect(input.getAttribute("role")).toBe("combobox");
    act(() => input.focus());
    type(input, "chen");
    expect(input.getAttribute("aria-expanded")).toBe("true");
    const list = q(host, "[role=listbox]");
    expect(input.getAttribute("aria-controls")).toBe(list.id);
    expect(all(list, "[role=option]")).toHaveLength(1);
    press(input, "ArrowDown");
    const option = q(list, "[role=option]");
    expect(input.getAttribute("aria-activedescendant")).toBe(option.id);
    expect(option.getAttribute("aria-selected")).toBe("true");
    const ev = press(input, "Enter");
    expect(ev.defaultPrevented).toBe(true);
    expect(chips(host)).toEqual(["Chen Wei"]);
    expect(input.value).toBe("");
    expect(input.getAttribute("aria-expanded")).toBe("false");
    expect(q(host, "[role=status]").textContent).toBe("Added Chen Wei");
  });
  it("Backspace in an empty field removes the last token; with text it only edits the text", () => {
    const spy = vi.fn();
    const host = render(<Harness initial={PEOPLE.slice(0, 2)} spy={spy} />);
    const input = q<HTMLInputElement>(host, "input");
    act(() => input.focus());
    type(input, "x");
    expect(press(input, "Backspace").defaultPrevented).toBe(false);
    expect(chips(host)).toHaveLength(2);
    type(input, "");
    expect(press(input, "Backspace").defaultPrevented).toBe(true);
    expect(chips(host)).toEqual(["Amara Okafor"]);
    expect(spy).toHaveBeenLastCalledWith([PEOPLE[0]]);
    expect(q(host, "[role=status]").textContent).toBe("Removed Bjorn Lindqvist");
    press(input, "Backspace");
    expect(chips(host)).toEqual([]);
    expect(press(input, "Backspace").defaultPrevented).toBe(false);
  });
  it("arrows wrap around; Escape closes the list, then clears the text", () => {
    const host = render(<Harness />);
    const input = q<HTMLInputElement>(host, "input");
    type(input, "o"); // Amara Okafor, Bjorn Lindqvist ("corp"), Chen Wei ("corp") all contain "o"
    const options = () => all(host, "[role=option]");
    expect(options()).toHaveLength(3);
    press(input, "ArrowUp");
    expect(options()[2]?.getAttribute("aria-selected")).toBe("true");
    press(input, "ArrowDown");
    expect(options()[0]?.getAttribute("aria-selected")).toBe("true");
    expect(press(input, "Escape").defaultPrevented).toBe(true);
    expect(host.querySelector("[role=listbox]")).toBeNull();
    expect(input.value).toBe("o");
    press(input, "Escape");
    expect(input.value).toBe("");
    expect(press(input, "Escape").defaultPrevented).toBe(false); // nothing left to close: a surrounding sheet may take it
  });
  it("clicking a suggestion adds it and leaves focus in the input", () => {
    const host = render(<Harness />);
    const input = q<HTMLInputElement>(host, "input");
    act(() => input.focus());
    type(input, "amara");
    act(() => q(host, "[role=option]").click());
    expect(chips(host)).toEqual(["Amara Okafor"]);
    expect(document.activeElement).toBe(input);
  });
  it("never offers a suggestion that is already a token", () => {
    const host = render(<Harness initial={[PEOPLE[2] as Token]} />);
    type(q(host, "input"), "chen");
    expect(host.querySelector("[role=listbox]")).toBeNull();
    expect(q(host, ".diq-token__note").textContent).toBe("No matches");
  });
  it("with parse, Enter, comma and leaving the field commit typed text; refused text stays", () => {
    const parse = (text: string): Token | null =>
      /^\S+@\S+$/.test(text) ? { id: text, label: text } : null;
    const host = render(<Harness parse={parse} />);
    const input = q<HTMLInputElement>(host, "input");
    act(() => input.focus());
    type(input, "kim@elsewhere.example");
    expect(press(input, "Enter").defaultPrevented).toBe(true);
    type(input, "lee@elsewhere.example");
    expect(press(input, ",").defaultPrevented).toBe(true);
    type(input, "not an address");
    expect(press(input, "Enter").defaultPrevented).toBe(false); // refused: the form may still submit/validate
    expect(input.value).toBe("not an address");
    type(input, "sam@elsewhere.example");
    act(() => input.blur());
    expect(chips(host)).toEqual([
      "kim@elsewhere.example",
      "lee@elsewhere.example",
      "sam@elsewhere.example",
    ]);
  });
  it("without parse, typed text is never turned into a token", () => {
    const host = render(<Harness />);
    const input = q<HTMLInputElement>(host, "input");
    type(input, "zzz");
    press(input, "Enter");
    press(input, ",");
    act(() => input.blur());
    expect(chips(host)).toEqual([]);
  });
  it("each token has a labelled Remove button that returns focus to the input", () => {
    const host = render(<Harness initial={PEOPLE.slice(0, 2)} />);
    const remove = q(host, 'button[aria-label="Remove Amara Okafor"]');
    act(() => remove.click());
    expect(chips(host)).toEqual(["Bjorn Lindqvist"]);
    expect(document.activeElement).toBe(q(host, "input"));
  });
  it("links error and hint through aria-describedby and marks the field invalid", () => {
    const host = render(
      <Harness error="Add at least one recipient" hint="Enter or comma adds an address" />,
    );
    const input = q(host, "input");
    expect(input.getAttribute("aria-invalid")).toBe("true");
    expect(descriptions(host, input)).toEqual([
      "Enter or comma adds an address",
      "Add at least one recipient",
    ]);
  });
  it("announces loading and shows no stale list", () => {
    const host = render(<Harness loading />);
    type(q(host, "input"), "zz");
    expect(q(host, "[role=status]").textContent).toBe("Searching…");
    expect(q(host, ".diq-token__note").textContent).toBe("Searching…");
  });
  it("disabled and read-only offer no way to change the tokens", () => {
    const off = render(<Harness initial={PEOPLE.slice(0, 1)} disabled />);
    expect(q<HTMLInputElement>(off, "input").disabled).toBe(true);
    expect(off.querySelector("button")).toBeNull();
    const ro = render(<Harness initial={PEOPLE.slice(0, 1)} readOnly />);
    const input = q<HTMLInputElement>(ro, "input");
    expect(input.readOnly).toBe(true);
    expect(ro.querySelector("button")).toBeNull();
    press(input, "Backspace");
    expect(chips(ro)).toEqual(["Amara Okafor"]);
  });
  it("shows badges and gives long values their full text as a title", () => {
    const long = "x".repeat(64);
    const host = render(
      <Harness
        initial={[{ id: "l", label: long, badge: "Outside", detail: `${long}@example.invalid` }]}
      />,
    );
    expect(q(host, ".diq-token__badge").textContent).toContain("Outside");
    expect(q(host, ".diq-token__text").getAttribute("title")).toBe(`${long}@example.invalid`);
  });
});

describe("form controls accessibility (axe)", () => {
  // Colour contrast needs real layout and styles; it is covered by tokens.test.ts and the Storybook a11y addon.
  const noop = () => undefined;
  const states: ReadonlyArray<readonly [string, React.ReactNode]> = [
    [
      "Select default",
      <Select key="1" label="Format" options={OPTIONS} value="csv" onChange={noop} />,
    ],
    [
      "Select placeholder, hint",
      <Select
        key="2"
        label="Format"
        options={OPTIONS}
        value=""
        placeholder="Any"
        hint="Pick"
        onChange={noop}
      />,
    ],
    [
      "Select invalid",
      <Select
        key="3"
        label="Format"
        options={OPTIONS}
        value=""
        error="Choose a format"
        onChange={noop}
      />,
    ],
    [
      "Select disabled",
      <Select key="4" label="Format" options={OPTIONS} value="csv" disabled onChange={noop} />,
    ],
    [
      "Select loading",
      <Select key="5" label="Format" options={[]} value="" loading onChange={noop} />,
    ],
    [
      "Select read-only",
      <Select key="6" label="Format" options={OPTIONS} value="csv" readOnly onChange={noop} />,
    ],
    [
      "Checkbox states",
      <div key="7">
        <Checkbox label="A" checked onChange={noop} />
        <Checkbox label="B" checked={false} indeterminate onChange={noop} />
        <Checkbox label="C" checked={false} disabled onChange={noop} />
        <Checkbox label="D" checked readOnly onChange={noop} />
        <Checkbox label="E" checked={false} error="Required" description="Why" onChange={noop} />
      </div>,
    ],
    [
      "RadioCardGroup",
      <RadioCardGroup
        key="8"
        label="When"
        options={CHOICES}
        value="daily"
        clearable
        onChange={noop}
      />,
    ],
    [
      "RadioCardGroup invalid",
      <RadioCardGroup
        key="9"
        label="When"
        options={CHOICES}
        value={null}
        error="Choose"
        onChange={noop}
      />,
    ],
    [
      "RadioCardGroup disabled",
      <RadioCardGroup
        key="10"
        label="When"
        options={CHOICES}
        value="daily"
        disabled
        onChange={noop}
      />,
    ],
    [
      "SegmentedControl",
      <SegmentedControl
        key="11"
        label="Preset"
        options={CHOICES}
        value="weekly"
        clearable
        onChange={noop}
      />,
    ],
    [
      "SegmentedControl invalid",
      <SegmentedControl
        key="12"
        label="Preset"
        options={CHOICES}
        value={null}
        error="Choose"
        onChange={noop}
      />,
    ],
    [
      "SegmentedControl read-only",
      <SegmentedControl
        key="13"
        label="Preset"
        options={CHOICES}
        value="weekly"
        readOnly
        onChange={noop}
      />,
    ],
    ["TokenInput empty", <Harness key="14" placeholder="Name or e-mail" />],
    [
      "TokenInput tokens, invalid",
      <Harness
        key="15"
        initial={[...PEOPLE, { id: "z", label: "bad", invalid: true, badge: "Outside" }]}
        error="Fix the address"
        hint="Enter adds"
      />,
    ],
    ["TokenInput disabled", <Harness key="16" initial={PEOPLE} disabled />],
    ["TokenInput read-only", <Harness key="17" initial={PEOPLE} readOnly />],
  ];
  it.each(states)("%s has no violations", async (_name, node) => {
    const host = render(node);
    const r = await axe.run(host, { rules: { "color-contrast": { enabled: false } } });
    expect(r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`)).toEqual(
      [],
    );
  });
  it("TokenInput with the list open has no violations", async () => {
    const host = render(<Harness />);
    const input = q<HTMLInputElement>(host, "input");
    act(() => input.focus());
    type(input, "o");
    press(input, "ArrowDown");
    expect(host.querySelector("[role=listbox]")).not.toBeNull();
    const r = await axe.run(host, { rules: { "color-contrast": { enabled: false } } });
    expect(r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`)).toEqual(
      [],
    );
  });
});
