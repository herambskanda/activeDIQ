// @vitest-environment jsdom
/* eslint-disable @typescript-eslint/no-non-null-assertion -- tests assert on fixtures they just built */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { API_BASE_URL, createApiClient } from "../../api/client";
import { FILTER_DEBOUNCE_MS, LibraryPage } from "./library-page";
import { ReportPage } from "./report-page";
import { SEARCH_DEBOUNCE_MS } from "./search";
import { POLL_MS } from "./use-report-run";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// Fixtures live in tests only (CLAUDE.md rule 6).
const column = (id: string, label: string, type = "text") => ({
  id,
  label,
  type,
  sortable: true,
  filterable: true,
  defaultVisible: true,
  choices: [],
  filterOperators: ["equals", "contains"],
});
const svcFilter = {
  kind: "ReportFilterConditionView",
  column: "probable_service_account",
  operator: "equals",
  values: [{ kind: "ReportValueBoolean", value: false }],
};
const definition = {
  id: "usr-03",
  version: 1,
  name: "Logon activity",
  description: "Who logged on",
  category: "users",
  dataset: "inventory.users",
  freshnessKind: "synced",
  alsoKnownAs: [{ meName: "Recently Logged on Users", presetId: "recent" }],
  columns: [column("name", "Name"), column("days_since", "Days since", "integer")],
  exportFormats: ["csv"],
  minScheduleIntervalHours: 1,
  perDc: false,
  subjectKind: "none",
  presets: [
    {
      id: "inactive",
      name: "Inactive 90 days",
      meName: null,
      periodDays: 90,
      columns: ["name"],
      filters: [svcFilter],
    },
    {
      id: "recent",
      name: "Recently logged on",
      meName: "Recently Logged on Users",
      periodDays: 30,
      columns: ["name"],
      filters: [],
    },
  ],
};
const run = (over: Record<string, unknown> = {}) => ({
  id: "11111111-1111-4111-8111-111111111111",
  definitionId: "usr-03",
  definitionVersion: 1,
  presetId: "recent",
  state: "succeeded",
  asOf: "2026-10-31T09:41:00Z",
  createdAt: "2026-10-31T09:41:00Z",
  createdBy: { kind: "user", id: "u" },
  startedAt: "2026-10-31T09:41:00Z",
  finishedAt: "2026-10-31T09:41:02Z",
  expiresAt: null,
  digest: "abc",
  freshness: { state: "synced", label: "Synced 09:41" },
  objectsChecked: 2500,
  rowCount: 1200,
  scopeApplied: "Domain lab.test",
  parameters: {
    columns: ["name", "days_since"],
    connectionIds: [],
    filters: [svcFilter],
    includeReadOnlyDcs: false,
    ouExclude: [],
    ouInclude: [],
    subjects: [],
  },
  progress: { percent: 100, stage: "done" },
  skippedConnections: [],
  ...over,
});
const page = (rows: number, next: string | null = null) => ({
  runId: run().id,
  rowCount: 1200,
  page: { nextCursor: next },
  columns: [column("name", "Name"), column("days_since", "Days since", "integer")],
  rows: Array.from({ length: rows }, (_, i) => ({
    rowKey: `r${i}`,
    cells: [
      { kind: "ReportCellText", value: i === 0 ? "<img src=x onerror=alert(1)>" : `User ${i}` },
      { kind: "ReportCellInteger", value: String(i) },
    ],
  })),
});

let calls: { method: string; url: URL; body: string }[];
let respond: (c: { method: string; url: URL; body: unknown }) => Response | undefined;
let container: HTMLElement;
let root: Root;

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": status >= 400 ? "application/problem+json" : "application/json" },
  });
const problem = (status: number, title: string, code?: string) =>
  json(status, { type: "about:blank", title, status, ...(code ? { code } : {}) });

const client = () =>
  createApiClient({
    baseUrl: "http://localhost/api/v1",
    fetch: async (req) => {
      const url = new URL(req.url);
      const body = req.method === "POST" ? await req.text() : "";
      calls.push({ method: req.method, url, body });
      const custom = respond({
        method: req.method,
        url,
        body: body ? JSON.parse(body) : undefined,
      });
      if (custom) return custom;
      const path = url.pathname.replace(API_BASE_URL, "");
      if (path === "/reports/definitions")
        return json(200, { items: [definition], page: { nextCursor: null } });
      if (path === "/reports/definitions/usr-03") return json(200, definition);
      if (path === "/reports/runs" && req.method === "POST") return json(202, run());
      if (path.endsWith("/rows")) return json(200, page(60, "next"));
      return problem(404, "not found");
    },
  });

async function mount(path: string, ui: "report" | "library") {
  window.history.replaceState(null, "", path);
  await act(async () => {
    root.render(
      ui === "report" ? <ReportPage client={client()} /> : <LibraryPage client={client()} />,
    );
  });
  await settle(0);
}
async function settle(ms = 0) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}
const text = () => container.textContent ?? "";
const button = (name: string | RegExp) => {
  const b = [...container.querySelectorAll("button")].find((x) =>
    typeof name === "string" ? x.textContent === name : name.test(x.textContent ?? ""),
  );
  if (!b) throw new Error(`no button ${String(name)}; page: ${text().slice(0, 400)}`);
  return b;
};
const click = async (el: Element) => {
  await act(async () => {
    el.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
  await settle(0);
};
const setValue = async (input: HTMLInputElement, value: string) => {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  await act(async () => {
    setter?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
};

beforeEach(() => {
  vi.useFakeTimers();
  calls = [];
  respond = () => undefined;
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});
afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.useRealTimers();
});

describe("a report opens and runs without a Generate step", () => {
  it("starts one run for the preset and shows the rows, the freshness and the counts", async () => {
    await mount("/reports/usr-03?preset=recent", "report");
    const posts = calls.filter((c) => c.method === "POST");
    expect(posts).toHaveLength(1);
    expect(JSON.parse(posts[0]!.body)).toEqual({ definitionId: "usr-03", presetId: "recent" });
    expect(text()).toContain("Also known as: Recently Logged on Users");
    expect(text()).toContain("Synced 09:41");
    expect(text()).toContain("1,200 of 2,500 checked");
    expect(container.querySelectorAll("tbody tr[data-row]").length).toBeGreaterThan(5);
    expect(text()).toContain("Showing 60 of 1,200 rows");
    expect(text()).not.toContain("Generate");
  });

  it("shows a directory string as text, never as HTML", async () => {
    await mount("/reports/usr-03?preset=recent", "report");
    expect(container.querySelector("img")).toBeNull();
    expect(text()).toContain("<img src=x onerror=alert(1)>");
  });

  it("sorting asks the server for the same run in that order and starts no new run", async () => {
    await mount("/reports/usr-03?preset=recent", "report");
    const header = [...container.querySelectorAll("th")].find((t) =>
      t.textContent?.startsWith("Days since"),
    );
    await click(header!);
    expect(window.location.search).toContain("sort=days_since");
    const rowCalls = calls.filter((c) => c.url.pathname.endsWith("/rows"));
    expect(rowCalls.at(-1)!.url.searchParams.get("sortBy")).toBe("days_since");
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
  });

  it("loads the next page with the cursor", async () => {
    await mount("/reports/usr-03?preset=recent", "report");
    await click(button("Load more rows"));
    expect(
      calls
        .filter((c) => c.url.pathname.endsWith("/rows"))
        .at(-1)!
        .url.searchParams.get("cursor"),
    ).toBe("next");
  });

  it("a period change is a new run with that period", async () => {
    await mount("/reports/usr-03?preset=recent", "report");
    const select = container.querySelector<HTMLSelectElement>("select")!;
    await act(async () => {
      select.value = "90";
      select.dispatchEvent(new Event("change", { bubbles: true }));
    });
    await settle(0);
    const last = calls.filter((c) => c.method === "POST").at(-1)!;
    expect(JSON.parse(last.body).parameters.period).toEqual({
      kind: "ReportPeriodLastDays",
      days: 90,
    });
  });

  it("follows a running run until it ends", async () => {
    let polls = 0;
    respond = ({ method, url }) => {
      if (method === "POST" && url.pathname.endsWith("/runs"))
        return json(
          202,
          run({ state: "running", progress: { percent: 40, stage: "reading_directory" } }),
        );
      if (method === "GET" && /\/runs\/[^/]+$/.test(url.pathname))
        return json(200, run(++polls < 2 ? { state: "running" } : {}));
      return undefined;
    };
    await mount("/reports/usr-03?preset=recent", "report");
    expect(text()).toContain("Running…");
    expect(button("Cancel run")).toBeTruthy();
    await settle(POLL_MS * 3);
    expect(text()).toContain("Synced 09:41");
    expect(text()).not.toContain("Running…");
  });
});

describe("states", () => {
  it("names the cause when the scope grants nothing", async () => {
    respond = ({ method, url }) =>
      method === "POST" && url.pathname.endsWith("/runs")
        ? json(202, run({ rowCount: 0, emptyReason: "scope_grants_nothing" }))
        : undefined;
    await mount("/reports/usr-03?preset=recent", "report");
    expect(text()).toContain("Your role covers no directory objects");
    expect(text()).toContain("this is not an error");
    expect(calls.some((c) => c.url.pathname.endsWith("/rows"))).toBe(false);
  });

  it("names the cause when the scope kind is unsupported", async () => {
    respond = ({ method, url }) =>
      method === "POST" && url.pathname.endsWith("/runs")
        ? json(202, run({ rowCount: 0, emptyReason: "unsupported_scope_kind" }))
        : undefined;
    await mount("/reports/usr-03?preset=recent", "report");
    expect(text()).toContain("Reports can’t use your role’s scope yet");
  });

  it("says Stale, with the age", async () => {
    respond = ({ method, url }) =>
      method === "POST" && url.pathname.endsWith("/runs")
        ? json(
            202,
            run({
              asOf: new Date(Date.now() - 3 * 3600_000).toISOString(),
              freshness: { state: "stale", label: "Stale: oldest sync pass 3h0m0s ago" },
            }),
          )
        : undefined;
    await mount("/reports/usr-03?preset=recent", "report");
    expect(text()).toContain("Stale data");
    expect(text()).toContain("Stale: oldest sync pass 3h0m0s ago");
    expect(text()).toContain("3 h ago");
  });

  it("says why a run failed and retries as a new run", async () => {
    respond = ({ method, url }) => {
      if (method === "POST" && url.pathname.endsWith("/runs"))
        return json(
          202,
          run({ state: "failed", failure: { reason: "query_timeout", message: "timed out" } }),
        );
      if (method === "POST" && url.pathname.endsWith("/retry")) return json(202, run());
      return undefined;
    };
    await mount("/reports/usr-03?preset=recent", "report");
    expect(text()).toContain("This run failed: the query timed out");
    await click(button("Retry (new run)"));
    expect(calls.some((c) => c.url.pathname.endsWith("/retry"))).toBe(true);
    expect(text()).toContain("Synced 09:41");
  });

  it("offers a new run for an expired result", async () => {
    respond = ({ method, url }) =>
      method === "POST" && url.pathname.endsWith("/runs")
        ? json(202, run({ state: "expired" }))
        : undefined;
    await mount("/reports/usr-03?preset=recent", "report");
    expect(text()).toContain("This result has expired");
    await click(button("Run again with the same settings"));
    expect(
      calls.filter((c) => c.method === "POST" && c.url.pathname.endsWith("/runs")),
    ).toHaveLength(2);
  });

  it("explains a scope that changed since the run", async () => {
    respond = ({ url }) =>
      url.pathname.endsWith("/rows")
        ? problem(409, "scope changed", "scope_changed_rerun")
        : undefined;
    await mount("/reports/usr-03?preset=recent", "report");
    expect(text()).toContain("Your access changed since this run");
  });

  it("offers Show for hidden probable service accounts, and the run then includes them", async () => {
    await mount("/reports/usr-03?preset=inactive", "report");
    expect(text()).toContain("Probable service accounts are hidden");
    await click(button("Show them"));
    expect(window.location.search).toContain("svc=1");
    const last = calls.filter((c) => c.method === "POST").at(-1)!;
    expect(JSON.parse(last.body).parameters.filters).toEqual([]);
  });

  it("has no access panel and no retry for a role without reports.run", async () => {
    respond = () => problem(403, "Forbidden");
    await mount("/reports/usr-03", "report");
    expect(text()).toContain("You don't have access to reports");
    expect(text()).toContain("reports.run");
    expect(container.querySelector("tbody")).toBeNull();
    expect([...container.querySelectorAll("button")].some((b) => b.textContent === "Retry")).toBe(
      false,
    );
  });

  it("shows a retry for a failed definition", async () => {
    respond = ({ url }) => (url.pathname.endsWith("/usr-03") ? problem(500, "boom") : undefined);
    await mount("/reports/usr-03", "report");
    expect(text()).toContain("The request failed");
    expect(button("Retry")).toBeTruthy();
  });

  it("does not run a report that needs a group, and says so", async () => {
    respond = ({ url }) =>
      url.pathname.endsWith("/usr-03")
        ? json(200, { ...definition, subjectKind: "group" })
        : undefined;
    await mount("/reports/usr-03", "report");
    expect(text()).toContain("about a specific group or user");
    expect(calls.some((c) => c.method === "POST")).toBe(false);
  });
});

describe("the library", () => {
  it("lists reports by category with their ManageEngine names, and filters on the server", async () => {
    await mount("/reports", "library");
    expect(text()).toContain("Logon activity");
    expect(text()).toContain("Also known as: Recently Logged on Users");
    await setValue(container.querySelector<HTMLInputElement>('input[type="search"]')!, "recent");
    await settle(FILTER_DEBOUNCE_MS);
    expect(window.location.search).toBe("?q=recent");
    expect(calls.at(-1)!.url.searchParams.get("q")).toBe("recent");
  });

  it("says nothing matches and offers to clear the filter", async () => {
    respond = ({ url }) =>
      url.pathname.endsWith("/definitions") && url.searchParams.get("q")
        ? json(200, { items: [], page: { nextCursor: null } })
        : undefined;
    await mount("/reports?q=zzqx", "library");
    expect(text()).toContain("No report matches “zzqx”");
    await click(button("Clear filter"));
    expect(window.location.search).toBe("");
  });

  it("opens the first hit for an ME name on Enter, with its preset", async () => {
    await mount("/reports", "library");
    await act(async () => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "/", bubbles: true }));
    });
    const input = container.querySelector<HTMLInputElement>('input[role="combobox"]')!;
    await setValue(input, "recently logged");
    await act(async () => {
      input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    });
    await settle(SEARCH_DEBOUNCE_MS);
    expect(window.location.pathname + window.location.search).toBe("/reports/usr-03?preset=recent");
  });

  it("finds none for a role without reports.run", async () => {
    respond = () => problem(403, "Forbidden");
    await mount("/reports", "library");
    expect(text()).toContain("You don't have access to reports");
    await act(async () => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "/", bubbles: true }));
    });
    const input = container.querySelector<HTMLInputElement>('input[role="combobox"]')!;
    await setValue(input, "logon");
    await settle(SEARCH_DEBOUNCE_MS);
    expect(text()).toContain("No reports are available to your role.");
    expect(container.querySelector('[role="option"]')).toBeNull();
  });
});
