import type { Meta, StoryObj } from "@storybook/react-vite";
import { type ReactNode, useEffect, useMemo, useState } from "react";

import "./components.css";
import {
  Chip,
  DataGrid,
  type DataGridColumn,
  DeltaCell,
  type DeltaDirection,
  DetailDock,
  DockLayout,
  PinnedBand,
} from "./index";

/** Fixture data: invented policy names and numbers (labelled as sample on every screen that uses them). */
interface Policy {
  readonly id: string;
  readonly name: string;
  readonly precedence: number;
  readonly length: number;
  readonly history: number;
  readonly maxAge: number;
  readonly lockout: number;
  readonly appliesTo: string;
}
const DOMAIN_LEN = 8;
const policies = (n: number): Policy[] =>
  Array.from({ length: n }, (_, i) => ({
    id: `p${i}`,
    name: i === 0 ? "Domain policy (corp.example)" : `PSO-Sample-${String(i).padStart(2, "0")}`,
    precedence: i * 10,
    length: i === 0 ? DOMAIN_LEN : 6 + ((i * 5) % 16),
    history: i === 0 ? 24 : (i * 3) % 30,
    maxAge: i === 0 ? 90 : ([0, 30, 60, 90, 180][i % 5] ?? 90),
    lockout: i === 0 ? 5 : ([0, 3, 5, 10][i % 4] ?? 5),
    appliesTo: i === 0 ? "All users" : `${i * 7}: svc-sql0${i}, svc-backup`,
  }));

const dir = (p: Policy): { d: DeltaDirection; amount: string } => {
  if (p.length === DOMAIN_LEN) return { d: "same", amount: "" };
  return p.length > DOMAIN_LEN
    ? { d: "stricter", amount: `+${p.length - DOMAIN_LEN}` }
    : { d: "weaker", amount: `−${DOMAIN_LEN - p.length}` };
};
const delta = (p: Policy, field: "length" | "history"): ReactNode => {
  const base = policies(1)[0] as Policy;
  const x = p[field];
  const b = base[field];
  const d: DeltaDirection = x === b ? "same" : x > b ? "stricter" : "weaker";
  return (
    <DeltaCell
      value={x}
      direction={d}
      amount={x === b ? undefined : `${x > b ? "+" : "−"}${Math.abs(x - b)}`}
      comparedTo="the domain policy"
    />
  );
};

const COLUMNS: DataGridColumn<Policy>[] = [
  { key: "name", header: "Policy", rowHeader: true, width: 26, cell: (p) => p.name },
  { key: "prec", header: "Precedence", width: 14, align: "end", cell: (p) => p.precedence },
  {
    key: "len",
    header: "Min length",
    width: 16,
    title: (p) => String(p.length),
    cell: (p) => delta(p, "length"),
  },
  {
    key: "hist",
    header: "History",
    width: 16,
    title: (p) => String(p.history),
    cell: (p) => delta(p, "history"),
  },
  {
    key: "age",
    header: "Max age",
    width: 14,
    align: "end",
    cell: (p) => (p.maxAge === 0 ? "Never" : `${p.maxAge} d`),
  },
  {
    key: "lock",
    header: "Lock after",
    width: 16,
    align: "end",
    cell: (p) => (p.lockout === 0 ? "Never locks" : `${p.lockout} fails`),
  },
  { key: "to", header: "Applies to", width: 34, cell: (p) => p.appliesTo },
  { key: "state", header: "State", width: 14, cell: () => <Chip tone="ok">● Applied</Chip> },
];

function PolicyPane({ p }: { readonly p: Policy }) {
  const { d, amount } = dir(p);
  return (
    <>
      <table className="diq-table" style={{ width: "100%" }}>
        <caption className="diq-sr-only">Setting compared with the domain policy</caption>
        <thead>
          <tr>
            <th scope="col">Setting</th>
            <th scope="col">Domain</th>
            <th scope="col">This policy</th>
            <th scope="col">Difference</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <th scope="row">Min length</th>
            <td>{DOMAIN_LEN}</td>
            <td>{p.length}</td>
            <td>
              <DeltaCell
                value=""
                direction={d}
                amount={amount || undefined}
                comparedTo="the domain policy"
                showWord
              />
            </td>
          </tr>
        </tbody>
      </table>
      <p style={{ margin: 0, color: "var(--diq-text-2)", fontSize: "var(--diq-text-cap)" }}>
        Direct targets, not the resultant set. Which policy wins for a user is shown per user.
      </p>
    </>
  );
}

function Demo(props: {
  readonly count?: number;
  readonly start?: number | null;
  readonly width?: string;
  readonly rtl?: boolean;
  readonly longTitle?: boolean;
  readonly theme?: "dark" | "light";
}) {
  const { count = 214, start = 3, width, rtl, longTitle, theme } = props;
  const rows = useMemo(() => policies(count), [count]);
  const [at, setAt] = useState<number | null>(start);
  useEffect(() => {
    if (!theme) return;
    document.documentElement.dataset.theme = theme;
    return () => {
      delete document.documentElement.dataset.theme;
    };
  }, [theme]);
  const row = at === null ? null : rows[at];
  return (
    <div
      dir={rtl ? "rtl" : undefined}
      style={{ width, padding: "var(--diq-space-4)", background: "var(--diq-bg)" }}
    >
      <DockLayout
        dock={
          row ? (
            <DetailDock
              title={longTitle ? `${row.name} ${"Finance-Contractors-".repeat(4)}` : row.name}
              titleText={row.name}
              description="Fine-grained policy · corp.example"
              position={{ index: (at ?? 0) + 1, total: rows.length }}
              onPrev={() => setAt((a) => Math.max(0, (a ?? 0) - 1))}
              onNext={() => setAt((a) => Math.min(rows.length - 1, (a ?? 0) + 1))}
              onClose={() => setAt(null)}
              footer={<a href="#users">Users governed by this policy (USR-05)</a>}
            >
              <PolicyPane p={row} />
            </DetailDock>
          ) : undefined
        }
      >
        <DataGrid
          caption={`Account policies, ${rows.length.toLocaleString("en")} rows`}
          columns={COLUMNS}
          rows={rows}
          rowKey={(p) => p.id}
          currentRowKey={row?.id ?? null}
          onRowActivate={(p) => setAt(rows.indexOf(p))}
          onActiveRowChange={(p) => setAt((a) => (a === null ? a : rows.indexOf(p)))}
          onEscape={() => setAt(null)}
          resizable
        />
      </DockLayout>
    </div>
  );
}

const meta: Meta = {
  title: "Design system/DetailDock",
  parameters: {
    docs: {
      description: {
        component:
          "A docked, non-modal detail pane beside a DataGrid (T-1516). Enter on a row opens it without moving focus; ↑/↓ in the grid step the rows and the pane follows; Previous / Next do the same by pointer; Esc closes (from the grid or the dock). Fixture policies are invented.",
      },
    },
  },
};
export default meta;
type Story = StoryObj;

/** Dock open at 1280 px: the grid scrolls sideways beside it and the Policy column stays in view. */
export const BesideGrid: Story = { render: () => <Demo width="1280px" /> };
/** Scroll the grid right: the Policy column stays, with a rule on its edge. Arrow into a far column and it scrolls into view. */
export const StickyNameColumn: Story = { render: () => <Demo width="900px" start={null} /> };
export const FirstRow: Story = { render: () => <Demo width="1280px" start={0} /> };
export const LastRow: Story = { render: () => <Demo width="1280px" count={12} start={11} /> };
/** Under the width of grid + dock the dock drops below the grid at full width. */
export const Narrow: Story = { render: () => <Demo width="560px" /> };
export const LongTitle: Story = { render: () => <Demo width="1280px" longTitle /> };
export const Rtl: Story = { render: () => <Demo width="1280px" rtl /> };
export const Dark: Story = { render: () => <Demo width="1280px" theme="dark" /> };

/** The three pieces together: a pinned band above the grid, deltas in cells, the dock beside. */
export const WithPinnedBand: Story = {
  render: () => (
    <div style={{ width: "1280px", padding: "var(--diq-space-4)" }}>
      <PinnedBand
        label="Did not answer (6)"
        note="pinned: a blind spot matters more than any row below"
        items={Array.from({ length: 6 }, (_, i) => ({
          id: `d${i}`,
          dc: `DC-EMEA${i + 1}`,
          why: "RPC server unavailable (1722)",
        }))}
        itemKey={(d) => d.id}
      >
        {(d) => (
          <>
            <b style={{ minWidth: "12ch" }}>{d.dc}</b>
            <span>{d.why}</span>
          </>
        )}
      </PinnedBand>
      <Demo start={2} />
    </div>
  ),
};
