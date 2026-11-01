import type { Meta, StoryObj } from "@storybook/react-vite";
import { useEffect, useMemo, useState } from "react";

import "./components.css";
import { DataGrid, type DataGridColumn, type DataGridSort } from "./index";

/** Fixture data: invented names only. Real screens pass server rows. */
interface Account {
  readonly id: string;
  readonly name: string;
  readonly sam: string;
  readonly ou: string;
  readonly enabled: "Enabled" | "Disabled";
  readonly logons: number;
}
const FIRST = [
  "Amara",
  "Bjorn",
  "Chen",
  "Dalia",
  "Emeka",
  "Farah",
  "Gustavo",
  "Hana",
  "Ivo",
  "Jun",
];
const LAST = [
  "Okafor",
  "Lindqvist",
  "Wei",
  "Haddad",
  "Nwosu",
  "Rahimi",
  "Duarte",
  "Sato",
  "Petrov",
  "Kim",
];
const OUS = ["Staff", "Contractors", "Service", "Finance", "Engineering", "Operations"];
const accounts = (n: number): Account[] =>
  Array.from({ length: n }, (_, i) => {
    const first = FIRST[i % FIRST.length] ?? "";
    const last = LAST[Math.floor(i / FIRST.length) % LAST.length] ?? "";
    return {
      id: `a${i}`,
      name: `${first} ${last} ${String(i).padStart(5, "0")}`,
      sam: `${first[0]?.toLowerCase() ?? ""}${last.toLowerCase()}${i}`,
      ou: `corp.example/Offices/${OUS[i % OUS.length] ?? ""}/Region ${i % 9}`,
      enabled: i % 11 === 0 ? "Disabled" : "Enabled",
      logons: (i * 37) % 1000,
    };
  });

const COLUMNS: DataGridColumn<Account>[] = [
  { key: "name", header: "Display name", width: 26, sortable: true, cell: (a) => a.name },
  {
    key: "sam",
    header: "sAMAccountName",
    width: 20,
    sortable: true,
    mono: true,
    cell: (a) => a.sam,
  },
  { key: "ou", header: "OU path", width: 34, sortable: true, cell: (a) => a.ou },
  {
    key: "enabled",
    header: "State",
    width: 14,
    sortable: true,
    title: (a) => a.enabled,
    cell: (a) => (
      <span className={`diq-chip diq-chip--${a.enabled === "Enabled" ? "ok" : "muted"}`}>
        {a.enabled === "Enabled" ? "● Enabled" : "⊘ Disabled"}
      </span>
    ),
  },
  {
    key: "logons",
    header: "Logons",
    width: 12,
    align: "end",
    sortable: true,
    cell: (a) => a.logons,
  },
];

function sorted(rows: Account[], sort: DataGridSort | null): Account[] {
  if (!sort) return rows;
  const k = sort.key as keyof Account;
  const m = sort.dir === "asc" ? 1 : -1;
  return [...rows].sort(
    (x, y) => String(x[k]).localeCompare(String(y[k]), "en", { numeric: true }) * m,
  );
}
function nextSort(cur: DataGridSort | null, key: string): DataGridSort | null {
  if (cur?.key !== key) return { key, dir: "asc" };
  return cur.dir === "asc" ? { key, dir: "desc" } : null;
}

function Demo(props: {
  readonly count: number;
  readonly columns?: DataGridColumn<Account>[];
  readonly selectable?: boolean;
  readonly resizable?: boolean;
  readonly busy?: boolean;
  readonly visibleRows?: number;
  readonly data?: Account[];
}) {
  const { count, columns = COLUMNS, selectable, resizable, busy, visibleRows, data } = props;
  const [sort, setSort] = useState<DataGridSort | null>(null);
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const base = useMemo(() => data ?? accounts(count), [data, count]);
  const rows = useMemo(() => sorted(base, sort), [base, sort]);
  return (
    <div style={{ padding: "var(--diq-space-4)" }}>
      <DataGrid
        caption={`Accounts, ${rows.length.toLocaleString("en")} rows`}
        columns={columns}
        rows={rows}
        rowKey={(a) => a.id}
        sort={sort}
        onSort={(k) => setSort((s) => nextSort(s, k))}
        selected={selectable ? selected : undefined}
        onSelectedChange={selectable ? setSelected : undefined}
        resizable={resizable}
        busy={busy}
        visibleRows={visibleRows}
        empty={<p>No accounts match. Clear the filter to see all.</p>}
      />
    </div>
  );
}

const meta: Meta = {
  title: "Design system/DataGrid",
  parameters: {
    docs: {
      description: {
        component:
          "Virtualised, sortable, keyboard-navigable grid (T-0952). Fixture names are invented. Arrow keys move between cells, Home/End/PageUp/PageDown/Ctrl+Home/Ctrl+End jump, Enter or Space on a header sorts, Space on a row selects (Shift extends), Shift+Left/Right on a header resizes.",
      },
    },
  },
};
export default meta;
type Story = StoryObj;

/** 12,000 rows: about 22 `tr[data-row]` exist at any time. */
export const Rows12000: Story = { render: () => <Demo count={12000} resizable /> };
export const Selectable: Story = { render: () => <Demo count={12000} selectable resizable /> };
export const Comfortable: Story = { render: () => <ComfortableDemo /> };
function ComfortableDemo() {
  useEffect(() => {
    document.documentElement.dataset.density = "comfortable";
    return () => {
      delete document.documentElement.dataset.density;
    };
  }, []);
  return <Demo count={400} selectable />;
}

/** 40-character names in a narrow column: truncated, full text in `title`. */
export const LongValues: Story = {
  render: () => {
    const long = accounts(200).map((a) => ({
      ...a,
      name: `${a.name} ${"abcdefghij".repeat(4)}`.slice(0, 40),
    }));
    return (
      <Demo
        count={0}
        data={long}
        columns={[
          { ...(COLUMNS[0] as DataGridColumn<Account>), width: 16 },
          ...COLUMNS.slice(1, 3),
        ]}
        resizable
      />
    );
  },
};

/** Unicode, right-to-left and empty values. */
export const UnicodeAndEmpty: Story = {
  render: () => {
    const names = ["Åsa Öberg", "李小龍", "محمد الفاسي", "Zoë 🙂 O’Brien", "", "שרה כהן"];
    const rows = names.map((name, i) => ({
      ...(accounts(1)[0] as Account),
      id: `u${i}`,
      name,
      sam: name ? `user${i}` : "",
    }));
    return <Demo count={0} data={rows} columns={COLUMNS.slice(0, 2)} />;
  },
};

export const FewRows: Story = { render: () => <Demo count={4} selectable /> };
export const Empty: Story = { render: () => <Demo count={0} /> };
export const Busy: Story = { render: () => <Demo count={200} busy /> };
export const Rtl: Story = {
  render: () => (
    <div dir="rtl">
      <Demo count={200} selectable resizable />
    </div>
  ),
};
