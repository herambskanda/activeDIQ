import type { Meta, StoryObj } from "@storybook/react-vite";
import { useMemo, useState } from "react";

import "./components.css";
import {
  Checkbox,
  RadioCardGroup,
  SegmentedControl,
  Select,
  type Token,
  TokenInput,
  type TokenInputProps,
} from "./index";

/**
 * Form controls (T-0954). Fixture data is invented. Every story is checked by the a11y addon (axe, with
 * real colour contrast); the interaction rules are in form-controls.test.tsx. Use the toolbar to
 * switch between light and dark through <html data-theme>, and Tab/arrow keys to drive each control.
 */
const meta: Meta = { title: "Design system/Form controls", parameters: { layout: "padded" } };
export default meta;
type Story = StoryObj;

const Stack = ({ children }: { children: React.ReactNode }) => (
  <div
    style={{
      display: "grid",
      gridTemplateColumns: "minmax(0, 1fr)",
      gap: "var(--diq-space-4)",
      maxWidth: "var(--diq-sheet-w)",
    }}
  >
    {children}
  </div>
);
const noop = () => undefined;

const FORMATS = [
  { value: "xlsx", label: "XLSX (with About sheet)" },
  { value: "csv", label: "CSV (table only)" },
  { value: "pdf", label: "PDF (not available for this report)", disabled: true },
];
const LONG = `${"Quarterly privileged-access review for the entire Engineering and Operations estate, ".repeat(2)}`;

function SelectDemo() {
  const [v, setV] = useState("xlsx");
  return (
    <Select label="Format" options={FORMATS} value={v} onChange={setV} placeholder="Any format" />
  );
}
export const SelectStates: Story = {
  render: () => (
    <Stack>
      <SelectDemo />
      <Select
        label="Format, hint"
        options={FORMATS}
        value="csv"
        hint="Used for every recipient."
        onChange={noop}
      />
      <Select
        label="Format, invalid"
        options={FORMATS}
        value=""
        placeholder="Choose a format"
        error="Choose a format before saving."
        onChange={noop}
      />
      <Select label="Format, disabled" options={FORMATS} value="csv" disabled onChange={noop} />
      <Select label="Format, read-only" options={FORMATS} value="xlsx" readOnly onChange={noop} />
      <Select
        label="Domains, loading"
        options={[]}
        value=""
        placeholder="Loading domains…"
        loading
        onChange={noop}
      />
      <Select
        label="Long option text"
        options={[{ value: "l", label: LONG }]}
        value="l"
        onChange={noop}
      />
    </Stack>
  ),
};

function CheckboxDemo() {
  const [a, setA] = useState(true);
  const [parts, setParts] = useState([true, false, false]);
  const some = parts.some(Boolean);
  const every = parts.every(Boolean);
  return (
    <>
      <Checkbox
        label="Only send if there is data (a run with 0 rows sends nothing)"
        checked={a}
        onChange={setA}
      />
      <Checkbox
        label="All domains"
        checked={every}
        indeterminate={some && !every}
        onChange={(c) => setParts(parts.map(() => c))}
      />
      {["corp.example", "emea.corp.example", "apac.corp.example"].map((d, i) => (
        <div key={d} style={{ marginInlineStart: "var(--diq-space-5)" }}>
          <Checkbox
            label={d}
            checked={parts[i] ?? false}
            onChange={(c) => setParts(parts.map((p, j) => (j === i ? c : p)))}
          />
        </div>
      ))}
    </>
  );
}
export const CheckboxStates: Story = {
  render: () => (
    <Stack>
      <CheckboxDemo />
      <Checkbox label="Unchecked" checked={false} onChange={noop} />
      <Checkbox label="Disabled, unchecked" checked={false} disabled onChange={noop} />
      <Checkbox label="Disabled, checked" checked disabled onChange={noop} />
      <Checkbox label="Read-only, checked" checked readOnly onChange={noop} />
      <Checkbox
        label={
          <>
            <strong>Data leaves your organisation:</strong> kim@elsewhere.example. I confirm these
            addresses may receive this report.
          </>
        }
        checked={false}
        description="Required before an outside address can be saved."
        error="Tick the box to confirm data leaves your organisation."
        onChange={noop}
      />
      <Checkbox label={LONG} checked onChange={noop} />
    </Stack>
  ),
};

const PRESETS = [
  { value: "daily", label: "Daily", description: "Every day at 06:00" },
  { value: "weekly", label: "Weekly", description: "Mondays at 06:00" },
  { value: "monthly", label: "Monthly", description: "First of the month, 06:00" },
  { value: "custom", label: "Custom", description: "Every n hours, days…", disabled: true },
];
function RadioCardDemo() {
  const [v, setV] = useState<string | null>("weekly");
  return (
    <RadioCardGroup label="When it runs" options={PRESETS} value={v} onChange={setV} clearable />
  );
}
export const RadioCardStates: Story = {
  render: () => (
    <Stack>
      <RadioCardDemo />
      <RadioCardGroup
        label="Nothing chosen, hint"
        options={PRESETS}
        value={null}
        hint="Time zone: Europe/London."
        onChange={noop}
      />
      <RadioCardGroup
        label="Invalid"
        options={PRESETS}
        value={null}
        error="Choose when it runs."
        onChange={noop}
      />
      <RadioCardGroup label="Disabled" options={PRESETS} value="daily" disabled onChange={noop} />
      <RadioCardGroup label="Read-only" options={PRESETS} value="daily" readOnly onChange={noop} />
      <RadioCardGroup
        label="Long text truncates, full text in the tooltip"
        options={[
          { value: "l", label: LONG, description: LONG },
          { value: "m", label: "Short", description: "Short" },
        ]}
        value="l"
        onChange={noop}
      />
    </Stack>
  ),
};

const REPORT_PRESETS = [
  { value: "all", label: "All accounts" },
  { value: "enabled", label: "Enabled only" },
  { value: "stale", label: "Stale 90 days" },
  { value: "admin", label: "Privileged" },
  { value: "disabled", label: "Disabled", disabled: true },
];
function SegmentedDemo() {
  const [v, setV] = useState<string | null>("enabled");
  return (
    <SegmentedControl label="Preset" options={REPORT_PRESETS} value={v} onChange={setV} clearable />
  );
}
export const SegmentedControlStates: Story = {
  render: () => (
    <Stack>
      <SegmentedDemo />
      <SegmentedControl
        label="Nothing chosen"
        options={REPORT_PRESETS}
        value={null}
        onChange={noop}
      />
      <SegmentedControl
        label="Invalid"
        options={REPORT_PRESETS}
        value={null}
        error="Choose a preset."
        onChange={noop}
      />
      <SegmentedControl
        label="Disabled"
        options={REPORT_PRESETS}
        value="all"
        disabled
        onChange={noop}
      />
      <SegmentedControl
        label="Read-only"
        options={REPORT_PRESETS}
        value="all"
        readOnly
        onChange={noop}
      />
      <SegmentedControl
        label="Long label"
        options={[
          { value: "l", label: LONG },
          { value: "s", label: "Short" },
        ]}
        value="l"
        onChange={noop}
      />
    </Stack>
  ),
};

/** Fixture directory: names with Unicode, RTL and 64-character values on purpose. */
const DIRECTORY: Token[] = [
  { id: "amara", label: "Amara Okafor", detail: "amara.okafor@corp.example" },
  { id: "bjorn", label: "Bjorn Lindqvist", detail: "bjorn.lindqvist@corp.example" },
  { id: "chen", label: "Chen Wei", detail: "chen.wei@corp.example" },
  { id: "dalia", label: "داليا حداد", detail: "dalia.haddad@corp.example" },
  {
    id: "emeka",
    label: "Emeka Nwosu-Rahimi-Duarte-Petrov-Sato-Kim-Haddad-Okafor-Lindqvist",
    detail: "emeka.nwosu@corp.example",
  },
  { id: "farah", label: "Farah Rahimi", detail: "farah.rahimi@corp.example" },
];
const MAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const parseMail = (text: string): Token | null =>
  MAIL.test(text)
    ? {
        id: text.toLowerCase(),
        label: text,
        ...(text.endsWith("@corp.example") ? {} : { badge: "Outside" }),
      }
    : null;

function TokenDemo(
  props: Partial<TokenInputProps> & { initial?: readonly Token[]; slow?: boolean },
) {
  const { initial = [], slow = false, ...rest } = props;
  const [tokens, setTokens] = useState<readonly Token[]>(initial);
  const [query, setQuery] = useState("");
  const suggestions = useMemo(() => {
    const t = query.trim().toLowerCase();
    return t.length < 2
      ? []
      : DIRECTORY.filter((p) => `${p.label} ${p.detail ?? ""}`.toLowerCase().includes(t));
  }, [query]);
  return (
    <TokenInput
      label="To"
      value={tokens}
      onChange={setTokens}
      suggestions={slow ? [] : suggestions}
      onQueryChange={setQuery}
      placeholder="Name or e-mail address"
      emptyText="No matching accounts"
      {...rest}
    />
  );
}
export const TokenInputStates: Story = {
  render: () => (
    <Stack>
      <TokenDemo
        parse={parseMail}
        hint="Type two letters of a name, or a full address and press Enter or comma."
      />
      <TokenDemo
        label="Selected tokens"
        initial={[
          DIRECTORY[0] as Token,
          { id: "kim@elsewhere.example", label: "kim@elsewhere.example", badge: "Outside" },
        ]}
        parse={parseMail}
      />
      <TokenDemo
        label="Invalid"
        initial={[{ id: "x", label: "not-an-address", invalid: true }]}
        parse={parseMail}
        error="“not-an-address” is not an e-mail address. Remove it or fix the spelling."
      />
      <TokenDemo label="Loading" slow loading initial={[DIRECTORY[2] as Token]} />
      <TokenDemo label="Disabled" disabled initial={DIRECTORY.slice(0, 2)} />
      <TokenDemo label="Read-only" readOnly initial={DIRECTORY.slice(0, 2)} />
      <TokenDemo label="Long, Unicode and right-to-left values" initial={DIRECTORY.slice(3, 5)} />
    </Stack>
  ),
};
