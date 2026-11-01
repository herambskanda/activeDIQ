/* eslint-disable @typescript-eslint/no-non-null-assertion -- tests assert on fixtures they just built */
import { describe, expect, it } from "vitest";

import type { ColumnInfo, DefinitionSummary, FilterView, Preset } from "./api";
import {
  ageText,
  buildRunBody,
  cellText,
  EMPTY_VIEW,
  filterProblem,
  filtersTest,
  hitHref,
  operatorsFor,
  parseView,
  runKey,
  searchHits,
  toFilter,
  viewToSearch,
  withoutColumn,
} from "./model";

// Fixtures live in tests only (CLAUDE.md rule 6).
const entry = (id: string, name: string, me: [string, string][] = []): DefinitionSummary => ({
  id,
  version: 1,
  name,
  description: `About ${name}`,
  category: "users",
  dataset: "inventory.users",
  freshnessKind: "synced",
  alsoKnownAs: me.map(([meName, presetId]) => ({ meName, presetId })),
});
const col = (id: string, type: string, extra: Partial<ColumnInfo> = {}): ColumnInfo => ({
  id,
  label: id,
  type,
  sortable: true,
  filterable: true,
  defaultVisible: true,
  choices: [],
  filterOperators: ["equals", "contains", "has_value", "empty", "within_last", "less_than"],
  ...extra,
});
const svc: FilterView = {
  kind: "ReportFilterConditionView",
  column: "probable_service_account",
  operator: "equals",
  values: [{ kind: "ReportValueBoolean", value: false }],
};

describe("searchHits", () => {
  const entries = [
    entry("usr-03", "Logon activity", [["Recently Logged on Users", "recent"]]),
    entry("pwd-01", "Password status"),
  ];
  it("opens an ME name at its preset, with the name as the alias", () => {
    const { hits } = searchHits(entries, "recently logged");
    expect(hits[0]).toMatchObject({
      definitionId: "usr-03",
      presetId: "recent",
      alias: "Recently Logged on Users",
    });
    expect(hitHref(hits[0]!)).toBe("/reports/usr-03?preset=recent");
  });
  it("finds a report by its name and opens its default preset", () => {
    const { hits } = searchHits(entries, "password");
    expect(hits.map((h) => h.label)).toEqual(["Password status"]);
    expect(hitHref(hits[0]!)).toBe("/reports/pwd-01");
  });
  it("needs every term, and finds nothing for an empty query", () => {
    expect(searchHits(entries, "password zzqx").total).toBe(0);
    expect(searchHits(entries, "  ").hits).toEqual([]);
  });
});

describe("view in the address bar", () => {
  it("round-trips preset, period, columns, filters, service accounts and sort", () => {
    const view = {
      ...EMPTY_VIEW,
      preset: "recent",
      days: 90,
      columns: ["name", "domain"],
      filters: [{ column: "name", operator: "contains", value: "a:b" }],
      showServiceAccounts: true,
      sort: "name",
      order: "desc" as const,
    };
    expect(parseView(new URLSearchParams(viewToSearch(view)))).toEqual(view);
  });
  it("ignores a period that is not offered and a malformed filter", () => {
    const v = parseView(new URLSearchParams("days=12&f=nocolons"));
    expect(v.days).toBeNull();
    expect(v.filters).toEqual([]);
  });
  it("does not start a new run for a sort", () => {
    expect(runKey({ ...EMPTY_VIEW, sort: "name", order: "desc" })).toBe(runKey(EMPTY_VIEW));
    expect(runKey({ ...EMPTY_VIEW, days: 30 })).not.toBe(runKey(EMPTY_VIEW));
  });
});

describe("buildRunBody", () => {
  const columns = [col("name", "text"), col("days_since", "integer")];
  const preset = {
    id: "inactive",
    filters: [svc],
    columns: [],
    name: "x",
    meName: null,
    periodDays: 90,
  } as Preset;
  it("sends only the preset for an unchanged view", () => {
    expect(
      buildRunBody({ id: "usr-03", columns }, preset, { ...EMPTY_VIEW, preset: "inactive" }),
    ).toEqual({
      definitionId: "usr-03",
      presetId: "inactive",
    });
  });
  it("keeps the preset's filters when one is added", () => {
    const body = buildRunBody({ id: "usr-03", columns }, preset, {
      ...EMPTY_VIEW,
      filters: [{ column: "days_since", operator: "greater_than", value: "10" }],
    });
    expect(body.parameters?.filters).toHaveLength(2);
    expect(body.parameters?.filters?.[1]).toMatchObject({
      kind: "ReportFilterCompare",
      value: { kind: "ReportValueInteger", value: 10 },
    });
  });
  it("drops only the service-account test when they are shown", () => {
    const body = buildRunBody({ id: "usr-03", columns }, preset, {
      ...EMPTY_VIEW,
      showServiceAccounts: true,
    });
    expect(body.parameters?.filters).toEqual([]);
  });
  it("sends the period and columns as chosen", () => {
    const body = buildRunBody({ id: "usr-03", columns }, preset, {
      ...EMPTY_VIEW,
      days: 30,
      columns: ["name"],
    });
    expect(body.parameters).toEqual({
      period: { kind: "ReportPeriodLastDays", days: 30 },
      columns: ["name"],
    });
  });
});

describe("filters", () => {
  it("finds and removes a test of one column, even inside a group", () => {
    const group: FilterView = { kind: "ReportFilterGroupView", match: "all", filters: [svc] };
    expect(filtersTest([group], "probable_service_account")).toBe(true);
    expect(withoutColumn([group], "probable_service_account")).toEqual([]);
    expect(filtersTest([], "probable_service_account")).toBe(false);
  });
  it("offers a column the operators it takes that the console can type", () => {
    expect(operatorsFor(col("last_logon", "time"))).toEqual(["has_value", "empty", "within_last"]);
    expect(operatorsFor(col("name", "text", { filterable: false }))).toEqual([]);
  });
  it("checks a value like the API will", () => {
    expect(filterProblem(col("n", "integer"), "less_than", "x")).toBe("Enter a whole number.");
    expect(filterProblem(col("n", "text"), "contains", " ")).toBe("Enter a value.");
    expect(filterProblem(col("n", "text"), "empty", "")).toBeUndefined();
    expect(
      toFilter({ column: "n", operator: "within_last", value: "7" }, [col("n", "time")]),
    ).toMatchObject({
      kind: "ReportFilterRelative",
      days: 7,
    });
  });
});

describe("cells", () => {
  const c = col("status", "enum", { choices: [{ id: "on", label: "Enabled" }] });
  it("renders every kind as plain text", () => {
    expect(cellText({ kind: "ReportCellText", value: "<b>x</b>" }, undefined)).toBe("<b>x</b>");
    expect(cellText({ kind: "ReportValueEnum", value: "on" }, c)).toBe("Enabled");
    expect(cellText({ kind: "ReportCellTextList", value: ["a", "b"] }, undefined)).toBe("a; b");
    expect(cellText({ kind: "ReportCellNever" }, undefined)).toBe("Never");
    expect(cellText({ kind: "ReportCellAbsent" }, undefined)).toBe("—");
    expect(cellText({ kind: "ReportCellUnknown" }, undefined)).toBe("Unknown (input missing)");
    expect(cellText({ kind: "ReportValueBoolean", value: true }, undefined)).toBe("Yes");
  });
});

describe("ageText", () => {
  it("says the age in the unit that reads best", () => {
    const now = new Date("2026-10-31T12:00:00Z");
    expect(ageText(new Date("2026-10-31T11:59:40Z"), now)).toBe("less than a minute ago");
    expect(ageText(new Date("2026-10-31T11:15:00Z"), now)).toBe("45 min ago");
    expect(ageText(new Date("2026-10-31T09:00:00Z"), now)).toBe("3 h ago");
    expect(ageText(new Date("2026-10-28T12:00:00Z"), now)).toBe("3 days ago");
  });
});
