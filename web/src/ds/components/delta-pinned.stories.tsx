import type { Meta, StoryObj } from "@storybook/react-vite";

import "./components.css";
import { DeltaCell, type DeltaDirection, PinnedBand, type PinnedBandTone } from "./index";

const meta: Meta = {
  title: "Design system/DeltaCell and PinnedBand",
  parameters: { layout: "padded" },
};
export default meta;
type Story = StoryObj;

const CASES: ReadonlyArray<readonly [string, DeltaDirection, string | undefined]> = [
  ["14 characters", "stricter", "+6"],
  ["6 characters", "weaker", "−2"],
  ["8 characters", "same", undefined],
  ["Never expires", "differs", undefined],
  ["Never locks", "weaker", undefined],
];

/** Every direction. Only "weaker" is coloured; each has its own glyph. */
export const Deltas: Story = {
  render: () => (
    <ul style={{ listStyle: "none", padding: 0, display: "grid", gap: "var(--diq-space-2)" }}>
      {CASES.map(([v, d, a]) => (
        <li key={v + d}>
          <DeltaCell value={v} direction={d} amount={a} comparedTo="the domain policy" />
        </li>
      ))}
    </ul>
  ),
};

/** With the word shown, as in a detail pane. */
export const DeltaWithWord: Story = {
  render: () => (
    <DeltaCell
      value="6 characters"
      direction="weaker"
      amount="−2"
      comparedTo="the domain policy"
      showWord
    />
  ),
};

/** A 64-character value in a narrow box truncates; the glyph and number never do. */
export const DeltaLongValue: Story = {
  render: () => (
    <div style={{ width: "24ch" }}>
      <DeltaCell
        value={"Reversible encryption " + "enabled-for-legacy-".repeat(3)}
        direction="weaker"
        amount="−1"
        comparedTo="the domain policy"
      />
    </div>
  ),
};

export const DeltaRtl: Story = {
  render: () => (
    <div dir="rtl">
      <DeltaCell
        value="طول كلمة المرور ١٤"
        direction="stricter"
        amount="+6"
        comparedTo="سياسة النطاق"
      />
    </div>
  ),
};

const DCS = Array.from({ length: 7 }, (_, i) => ({
  id: `dc${i}`,
  dc: `DC-EMEA${i + 1}.corp.example`,
  why: i % 2 ? "The RPC server is unavailable (1722)" : "Access is denied (5)",
}));
const band = (tone: PinnedBandTone, n: number) => (
  <PinnedBand
    label={`Did not answer (${n})`}
    tone={tone}
    note="pinned: a blind spot matters more than any row below"
    items={DCS.slice(0, n)}
    itemKey={(d) => d.id}
  >
    {(d) => (
      <>
        <b style={{ minWidth: "28ch" }}>{d.dc}</b>
        <span>{d.why}</span>
      </>
    )}
  </PinnedBand>
);

export const PinnedCrit: Story = { render: () => band("crit", 2) };
export const PinnedWarn: Story = { render: () => band("warn", 3) };
export const PinnedInfo: Story = { render: () => band("info", 1) };
/** More than 4: "Show 3 more" expands; expanded the list scrolls and is a tab stop. */
export const PinnedManyItems: Story = { render: () => band("crit", 7) };
export const PinnedLongAndRtl: Story = {
  render: () => (
    <div dir="rtl" style={{ width: "420px" }}>
      <PinnedBand
        label="لم يستجب (2)"
        items={[
          { id: "a", t: "dc-" + "amsterdam-".repeat(8) + ".corp.example" },
          { id: "b", t: "שרת בקרת תחום" },
        ]}
        itemKey={(d) => d.id}
      >
        {(d) => <span>{d.t}</span>}
      </PinnedBand>
    </div>
  ),
};
