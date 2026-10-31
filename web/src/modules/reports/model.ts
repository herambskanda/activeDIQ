// The reports screens' logic with no React in it: search hits, the address-bar state of a report,
// the run request built from it, filter typing and cell text. Tested in model.test.ts.
import type {
  Cell,
  ColumnInfo,
  Definition,
  DefinitionSummary,
  Filter,
  FilterView,
  Preset,
  Run,
  RunParameters,
  Value,
} from "./api";

// ---- categories --------------------------------------------------------------------------

/** The library categories of the contract (ReportCategory), in the order the library lists them. */
export const CATEGORIES: readonly { readonly id: string; readonly label: string }[] = [
  { id: "users", label: "Users" },
  { id: "passwords", label: "Passwords" },
  { id: "groups", label: "Groups" },
  { id: "computers", label: "Computers" },
  { id: "contacts", label: "Contacts" },
  { id: "organizational_units", label: "Organizational units" },
];

/** A category's label; a value this console does not know is shown readably rather than hidden. */
export function categoryLabel(id: string): string {
  const known = CATEGORIES.find((c) => c.id === id);
  if (known) return known.label;
  const text = id.replace(/_/g, " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

// ---- search hits -------------------------------------------------------------------------

export interface Hit {
  readonly key: string;
  readonly definitionId: string;
  /** The preset the hit opens; absent means the report's default. */
  readonly presetId?: string;
  readonly label: string;
  readonly sub: string;
  /** The ManageEngine name that matched, shown as "Also known as" on the report. */
  readonly alias: string | null;
}

export const HIT_LIMIT = 8;

const terms = (q: string) => q.toLowerCase().split(/\s+/).filter(Boolean);
const hasAll = (hay: string, ts: readonly string[]) =>
  ts.every((t) => hay.toLowerCase().includes(t));

/**
 * The hits for a query over the library entries the server returned for it: a hit per matching
 * ManageEngine name (it opens that name's preset), then the report itself. Every term must appear.
 */
export function searchHits(
  entries: readonly DefinitionSummary[],
  query: string,
): { hits: Hit[]; total: number } {
  const ts = terms(query);
  if (ts.length === 0) return { hits: [], total: 0 };
  const all: Hit[] = [];
  for (const d of entries) {
    const sub = `${categoryLabel(d.category)} · ${d.name}`;
    let aliased = false;
    for (const me of d.alsoKnownAs) {
      if (!hasAll(me.meName, ts)) continue;
      aliased = true;
      all.push({
        key: `${d.id}:${me.presetId}`,
        definitionId: d.id,
        presetId: me.presetId,
        label: me.meName,
        sub,
        alias: me.meName,
      });
    }
    if (
      hasAll(`${d.name} ${categoryLabel(d.category)}`, ts) ||
      (!aliased && hasAll(d.description, ts))
    ) {
      all.push({
        key: d.id,
        definitionId: d.id,
        label: d.name,
        sub: categoryLabel(d.category),
        alias: null,
      });
    }
  }
  const startsFirst = (h: Hit) => (h.label.toLowerCase().startsWith(ts[0] ?? "") ? 0 : 1);
  const sorted = all
    .map((h, i) => ({ h, i }))
    .sort((a, b) => startsFirst(a.h) - startsFirst(b.h) || a.i - b.i)
    .map((x) => x.h);
  return { hits: sorted.slice(0, HIT_LIMIT), total: sorted.length };
}

/** Where a hit opens: the report, with its preset when the hit names one. */
export function hitHref(hit: Pick<Hit, "definitionId" | "presetId">): string {
  const q = hit.presetId ? `?preset=${encodeURIComponent(hit.presetId)}` : "";
  return `/reports/${encodeURIComponent(hit.definitionId)}${q}`;
}

type CompareOp = Extract<Filter, { kind: "ReportFilterCompare" }>["operator"];

// ---- filters -----------------------------------------------------------------------------

/** A filter the admin added to the report, in the address bar as `f=<column>:<operator>:<value>`. */
export interface UserFilter {
  readonly column: string;
  readonly operator: string;
  readonly value: string;
}

export const OPERATOR_LABEL: Readonly<Record<string, string>> = {
  equals: "is",
  not_equals: "is not",
  contains: "contains",
  starts_with: "starts with",
  less_than: "is less than",
  less_or_equal: "is at most",
  greater_than: "is more than",
  greater_or_equal: "is at least",
  has_value: "has a value",
  empty: "is empty",
  within_last: "is within the last (days)",
  within_next: "is within the next (days)",
  older_than: "is older than (days)",
};

const OPERATORS_BY_TYPE: Readonly<Record<string, readonly string[]>> = {
  text: ["equals", "not_equals", "contains", "starts_with", "has_value", "empty"],
  integer: [
    "equals",
    "not_equals",
    "less_than",
    "less_or_equal",
    "greater_than",
    "greater_or_equal",
    "has_value",
    "empty",
  ],
  boolean: ["equals"],
  enum: ["equals", "not_equals", "has_value", "empty"],
  time: ["has_value", "empty", "within_last", "within_next", "older_than"],
};

const NO_VALUE = new Set(["has_value", "empty"]);
const DAYS = new Set(["within_last", "within_next", "older_than"]);

/** The operators the console offers for a column: the API's list for it, narrowed to those this console can type a value for. */
export function operatorsFor(column: ColumnInfo): string[] {
  const ok = OPERATORS_BY_TYPE[column.type] ?? [];
  return column.filterable ? column.filterOperators.filter((o) => ok.includes(o)) : [];
}

export const needsValue = (operator: string) => !NO_VALUE.has(operator);

/** Why a filter's value is not acceptable, or undefined. The API checks again. */
export function filterProblem(
  column: ColumnInfo,
  operator: string,
  value: string,
): string | undefined {
  if (!needsValue(operator)) return undefined;
  const v = value.trim();
  if (v === "") return "Enter a value.";
  if (DAYS.has(operator) || column.type === "integer") {
    if (!/^-?\d{1,15}$/.test(v)) return "Enter a whole number.";
    if (DAYS.has(operator) && Number(v) < 0) return "Enter a number of days, zero or more.";
  }
  if (column.type === "text" && v.length > 256) return "Use at most 256 characters.";
  return undefined;
}

function typedValue(column: ColumnInfo, value: string): Value {
  switch (column.type) {
    case "integer":
      return { kind: "ReportValueInteger", value: Number(value) };
    case "boolean":
      return { kind: "ReportValueBoolean", value: value === "true" };
    case "enum":
      return { kind: "ReportValueEnum", value };
    default:
      return { kind: "ReportValueText", value };
  }
}

/** A user filter as the run request carries it. */
export function toFilter(f: UserFilter, columns: readonly ColumnInfo[]): Filter | undefined {
  const column = columns.find((c) => c.id === f.column);
  if (!column) return undefined;
  const id = f.column as Extract<Filter, { kind: "ReportFilterPresence" }>["column"];
  const v = f.value.trim();
  if (f.operator === "has_value" || f.operator === "empty") {
    return { kind: "ReportFilterPresence", column: id, presence: f.operator };
  }
  if (DAYS.has(f.operator)) {
    return {
      kind: "ReportFilterRelative",
      column: id,
      relation: f.operator as "within_last" | "within_next" | "older_than",
      days: Number(v),
    };
  }
  return {
    kind: "ReportFilterCompare",
    column: id,
    operator: f.operator as Extract<Filter, { kind: "ReportFilterCompare" }>["operator"],
    value: typedValue(column, v),
  };
}

/** A stored filter (a preset's, or a run's) as a request filter, so a preset's filters can be kept when others are added. */
export function viewToFilter(v: FilterView): Filter | undefined {
  if (v.kind === "ReportFilterGroupView") {
    const filters = v.filters.map(viewToFilter).filter((f): f is Filter => f !== undefined);
    const m = v.match as string;
    const match: "all" | "any" | "none" = m === "any" || m === "none" ? m : "all";
    return { kind: "ReportFilterGroup", match, filters };
  }
  const column = v.column as Extract<Filter, { kind: "ReportFilterPresence" }>["column"];
  const first = v.values[0];
  const op = v.operator as string; // an open enum: the cases below are the ones this console can send
  switch (op) {
    case "has_value":
    case "empty":
      return { kind: "ReportFilterPresence", column, presence: op };
    case "within_last":
    case "within_next":
    case "older_than":
      return first?.kind === "ReportValueInteger"
        ? { kind: "ReportFilterRelative", column, relation: op, days: first.value }
        : undefined;
    case "in":
      return { kind: "ReportFilterIn", column, values: v.values };
    case "equals":
    case "not_equals":
    case "less_than":
    case "less_or_equal":
    case "greater_than":
    case "greater_or_equal":
    case "contains":
    case "starts_with":
      return first
        ? { kind: "ReportFilterCompare", column, operator: op as CompareOp, value: first }
        : undefined;
    default:
      return undefined;
  }
}

export const SERVICE_ACCOUNT_COLUMN = "probable_service_account";

/** True when a stored filter tree tests `column` anywhere. */
export function filtersTest(filters: readonly FilterView[], column: string): boolean {
  return filters.some((f) =>
    f.kind === "ReportFilterGroupView" ? filtersTest(f.filters, column) : f.column === column,
  );
}

/** The stored filters without any test of `column` (empty groups disappear). */
export function withoutColumn(filters: readonly FilterView[], column: string): FilterView[] {
  const out: FilterView[] = [];
  for (const f of filters) {
    if (f.kind === "ReportFilterGroupView") {
      const inner = withoutColumn(f.filters, column);
      if (inner.length > 0) out.push({ ...f, filters: inner });
    } else if (f.column !== column) out.push(f);
  }
  return out;
}

// ---- the address-bar state of one report -------------------------------------------------

export type SortOrder = "asc" | "desc";

/** Everything about a report view that is in the address bar. A change of any of it except the sort is a new run. */
export interface View {
  readonly preset: string | null;
  readonly days: number | null;
  readonly columns: readonly string[] | null;
  readonly filters: readonly UserFilter[];
  /** Probable service accounts are shown although the preset hides them. */
  readonly showServiceAccounts: boolean;
  readonly sort: string | null;
  readonly order: SortOrder;
}

export const EMPTY_VIEW: View = {
  preset: null,
  days: null,
  columns: null,
  filters: [],
  showServiceAccounts: false,
  sort: null,
  order: "asc",
};

export const PERIOD_DAYS: readonly number[] = [7, 30, 90, 180, 365];

export function parseView(search: URLSearchParams): View {
  const days = Number(search.get("days"));
  const cols = search.get("cols");
  const filters: UserFilter[] = [];
  for (const raw of search.getAll("f")) {
    const a = raw.indexOf(":");
    const b = raw.indexOf(":", a + 1);
    if (a <= 0 || b <= a) continue;
    filters.push({
      column: raw.slice(0, a),
      operator: raw.slice(a + 1, b),
      value: raw.slice(b + 1),
    });
  }
  const sort = search.get("sort");
  return {
    preset: search.get("preset") || null,
    days: PERIOD_DAYS.includes(days) ? days : null,
    columns: cols ? cols.split(",").filter(Boolean) : null,
    filters,
    showServiceAccounts: search.get("svc") === "1",
    sort: sort || null,
    order: search.get("order") === "desc" ? "desc" : "asc",
  };
}

export function viewToSearch(v: View): string {
  const p = new URLSearchParams();
  if (v.preset) p.set("preset", v.preset);
  if (v.days !== null) p.set("days", String(v.days));
  if (v.columns) p.set("cols", v.columns.join(","));
  for (const f of v.filters) p.append("f", `${f.column}:${f.operator}:${f.value}`);
  if (v.showServiceAccounts) p.set("svc", "1");
  if (v.sort) {
    p.set("sort", v.sort);
    if (v.order === "desc") p.set("order", "desc");
  }
  const s = p.toString();
  return s === "" ? "" : `?${s}`;
}

/** The part of the view that defines a run: the sort is not part of it (sorting re-orders the same run). */
export function runKey(v: View): string {
  return viewToSearch({ ...v, sort: null, order: "asc" });
}

/**
 * The request for a run of this view. Fields the view does not change are left out, so the preset's
 * (and then the definition's) values apply. Filters in a request replace the preset's, so when the admin
 * adds a filter or shows service accounts, the preset's own filters are sent along with theirs.
 */
export function buildRunBody(
  definition: Pick<Definition, "id" | "columns">,
  preset: Preset | undefined,
  view: View,
) {
  const parameters: RunParameters = {};
  if (view.days !== null) parameters.period = { kind: "ReportPeriodLastDays", days: view.days };
  if (view.columns) parameters.columns = view.columns as NonNullable<RunParameters["columns"]>;
  if (view.filters.length > 0 || view.showServiceAccounts) {
    const base = preset?.filters ?? [];
    const kept = view.showServiceAccounts ? withoutColumn(base, SERVICE_ACCOUNT_COLUMN) : base;
    const filters = kept.map(viewToFilter).filter((f): f is Filter => f !== undefined);
    for (const f of view.filters) {
      const typed = toFilter(f, definition.columns);
      if (typed) filters.push(typed);
    }
    parameters.filters = filters;
  }
  return {
    definitionId: definition.id,
    ...(view.preset ? { presetId: view.preset } : {}),
    ...(Object.keys(parameters).length > 0 ? { parameters } : {}),
  };
}

// ---- header facts ------------------------------------------------------------------------

export type FreshnessTone = "ok" | "warn" | "muted";

export function freshnessTone(run: Pick<Run, "freshness" | "coverage">): FreshnessTone {
  if (run.freshness.state === "stale") return "warn";
  if (run.freshness.state === "not_synced_yet") return "muted";
  if (run.freshness.state === "per_dc_read" && run.coverage && !run.coverage.complete)
    return "warn";
  return "ok";
}

const MINUTE = 60_000;

/** "3 h 5 min ago": the age of the data, for the stale banner. */
export function ageText(from: Date, now: Date): string {
  const minutes = Math.max(0, Math.round((now.getTime() - from.getTime()) / MINUTE));
  if (minutes < 1) return "less than a minute ago";
  if (minutes < 60) return `${minutes} min ago`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (h < 48) return m === 0 ? `${h} h ago` : `${h} h ${m} min ago`;
  return `${Math.floor(h / 24)} days ago`;
}

export const formatCount = (n: number) => n.toLocaleString("en");

export function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** The words for a typed failure reason of a run (ReportFailureReason). The API's own message is the fallback. */
export function failureText(reason: string, message: string): string {
  switch (reason) {
    case "query_timeout":
      return "the query timed out";
    case "row_cap_exceeded":
      return "the result is over the row limit";
    case "per_dc_read_cap_exceeded":
      return "it would read too many domain controllers";
    case "scope_too_large":
      return "the scope is too large to evaluate";
    case "connection_unavailable":
      return "a connection could not be read";
    case "runner_inactive":
      return "the account that started it is disabled or gone";
    case "token_refused":
      return "the token behind it was revoked or expired";
    case "definition_retired":
      return "the report was retired before it started";
    case "interrupted":
      return "the run was interrupted";
    default:
      return message !== ""
        ? message.charAt(0).toLowerCase() + message.slice(1)
        : "an internal error";
  }
}

// ---- cells -------------------------------------------------------------------------------

/**
 * A cell as text. Directory strings are returned as they are and rendered as React text, never as
 * HTML. absent is a dash, never is "Never", unknown says its input is missing (FR-09).
 */
export function cellText(cell: Cell, column: ColumnInfo | undefined): string {
  switch (cell.kind) {
    case "ReportCellText":
    case "ReportCellInteger":
    case "ReportCellGuid":
      return cell.value;
    case "ReportCellTextList":
      return cell.value.join("; ");
    case "ReportValueBoolean":
      return cell.value ? "Yes" : "No";
    case "ReportValueTime":
      return formatTime(cell.value);
    case "ReportValueEnum":
      return column?.choices.find((c) => c.id === cell.value)?.label ?? cell.value;
    case "ReportCellAbsent":
      return "—";
    case "ReportCellNever":
      return "Never";
    case "ReportCellUnknown":
      return "Unknown (input missing)";
  }
}
