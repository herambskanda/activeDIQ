import type { Meta, StoryObj } from "@storybook/react-vite";
import { useState } from "react";

import "./components.css";
import { Link, ObjectPicker, type PickerAnswer, type PickerObject } from "./index";

/** Fixture data: invented objects on a reserved test domain. Real screens pass what the search API returns. */
const meta: Meta = { title: "Design system/Object picker" };
export default meta;
type Story = StoryObj;

const DEPARTMENTS: Record<number, string> = {
  1: "CN=J. Smith,OU=Finance,OU=Staff,DC=corp,DC=example,DC=test",
  2: "CN=J. Smith,OU=Sales,OU=Staff,DC=corp,DC=example,DC=test",
  3: "CN=J. Smith,OU=Legal,OU=Staff,DC=emea,DC=example,DC=test",
};
const smith = (n: number, over: Partial<PickerObject> = {}): PickerObject => ({
  id: `00000000-0000-4000-8000-00000000000${n}`,
  name: "J. Smith",
  identifier: `jsmith${n} · j.smith${n}@corp.example.test`,
  path: DEPARTMENTS[n] ?? "",
  ...over,
});
const FIXTURE: readonly PickerObject[] = [
  smith(1),
  smith(2, { enabled: false }),
  smith(3, { domain: "emea.example.test" }),
  {
    id: "00000000-0000-4000-8000-000000000004",
    name: "Dr. Alexandria Montgomery-Featherstonehaugh-Cholmondeley-Wolverton-Smythe-Beauchamp",
    identifier: "amontgomery · alexandria.montgomery@corp.example.test",
    path: "CN=Dr. Alexandria Montgomery,OU=Research and Development,OU=Laboratories,OU=Northern Europe,OU=Staff,DC=corp,DC=example,DC=test",
  },
  {
    id: "00000000-0000-4000-8000-000000000005",
    name: "محمد الأحمد",
    identifier: "malahmad",
    path: "CN=محمد الأحمد,OU=Riyadh,DC=corp,DC=example,DC=test",
  },
];

const answer =
  (mode: "ok" | "more" | "refine" | "empty" | "error") =>
  async (text: string, signal: AbortSignal): Promise<PickerAnswer> => {
    await new Promise((r) => setTimeout(r, 250));
    if (signal.aborted) throw new Error("aborted");
    if (mode === "error") throw new Error("down");
    if (mode === "refine") return { items: [], refine: true };
    if (mode === "empty") return { items: [] };
    return {
      items: FIXTURE.filter(
        (o) =>
          `${o.name} ${o.identifier ?? ""}`.toLowerCase().includes(text.toLowerCase()) ||
          text.length < 3,
      ),
      more: mode === "more",
    };
  };

function Demo({
  mode = "ok",
  initial = [],
  ...rest
}: {
  mode?: "ok" | "more" | "refine" | "empty" | "error";
  initial?: readonly PickerObject[];
  disabled?: boolean;
  readOnly?: boolean;
  error?: string;
  max?: number;
  label?: string;
}) {
  const [v, setV] = useState<readonly PickerObject[]>(initial);
  return (
    <ObjectPicker
      label="Users"
      kind="user"
      value={v}
      onChange={setV}
      search={answer(mode)}
      {...rest}
    />
  );
}
const Stack = ({ children }: { children: React.ReactNode }) => (
  <div style={{ display: "grid", gap: "var(--diq-space-5)", maxWidth: "40rem" }}>{children}</div>
);

export const States: Story = {
  render: () => (
    <Stack>
      <Demo label="Default: type “smith” or “mo”" />
      <Demo label="Best matches only (more)" mode="more" />
      <Demo label="Too broad (refine)" mode="refine" />
      <Demo label="No match" mode="empty" />
      <Demo label="Search failed" mode="error" />
      <Demo label="Chosen, long and right-to-left" initial={FIXTURE.slice(2, 5)} />
      <Demo label="At the limit" max={2} initial={FIXTURE.slice(0, 2)} />
      <Demo label="Error" error="Choose at least one user." />
      <Demo label="Disabled" disabled initial={FIXTURE.slice(0, 1)} />
      <Demo label="Read-only" readOnly initial={FIXTURE.slice(0, 1)} />
    </Stack>
  ),
};

export const RouterLink: Story = {
  render: () => (
    <p>
      <Link to="/reports">Reports</Link> ·{" "}
      <Link to="https://not-a-console-path.test">refused: plain text</Link>
    </p>
  ),
};
