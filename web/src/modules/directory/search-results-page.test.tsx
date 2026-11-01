// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createApiClient } from "../../api/client";
import { collectContributions } from "../../app/modules";
import { directoryModule } from ".";
import { RECOVERY_PASSWORD_MESSAGE, type SearchHit } from "./search-results-model";
import { DEBOUNCE_MS, SearchResultsPage } from "./search-results-page";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// Fixtures live in tests only (CLAUDE.md rule 6).
const guid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const user = (n: number, over: Partial<SearchHit> = {}): SearchHit => ({
  type: "users",
  objectId: guid(n),
  displayName: `Priya Raman ${n}`,
  distinguishedName: `CN=Priya Raman ${n},OU=Sales,DC=corp,DC=example,DC=test`,
  domain: "corp.example.test",
  matchClass: "prefix",
  highlights: [{ field: "displayName", start: 0, length: 5 }],
  status: [],
  samAccountName: `praman${n}`,
  userPrincipalName: `praman${n}@corp.example.test`,
  ...over,
});
const group = (n: number): SearchHit => ({
  type: "groups",
  objectId: guid(900 + n),
  displayName: `Payroll ${n}`,
  distinguishedName: `CN=Payroll ${n},OU=Groups,DC=corp,DC=example,DC=test`,
  domain: "corp.example.test",
  matchClass: "fuzzy",
  highlights: [],
  status: [],
  samAccountName: `payroll${n}`,
});
const result = (groups: Record<string, unknown>[], extra: Record<string, unknown> = {}) => ({
  asOf: "2026-11-01T09:00:00Z",
  refine: false,
  groups,
  ...extra,
});
const grp = (type: string, items: SearchHit[], extra: Record<string, unknown> = {}) => ({
  type,
  items,
  count: items.length,
  ...extra,
});

interface Call {
  url: URL;
  method: string;
  body: Record<string, unknown>;
}
let calls: Call[];
let respond: (call: Call) => Response | Promise<Response>;
let container: HTMLElement;
let root: Root;

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const problem = (status: number, extra: Record<string, unknown> = {}) =>
  json(status, { type: "about:blank", title: "t", status, traceId: "trace-1", ...extra });

const client = () =>
  createApiClient({
    baseUrl: "http://localhost/api/v1",
    fetch: async (req) => {
      const text = await req.text();
      const call = {
        url: new URL(req.url),
        method: req.method,
        body: text === "" ? {} : (JSON.parse(text) as Record<string, unknown>),
      };
      calls.push(call);
      return respond(call);
    },
  });

async function mount(path: string) {
  window.history.replaceState(null, "", path);
  await act(async () => {
    root.render(<SearchResultsPage client={client()} />);
  });
}
async function settle(ms = DEBOUNCE_MS) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}
function setValue(input: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (!setter) throw new Error("no value setter");
  setter.call(input, value);
}
async function type(value: string) {
  const input = container.querySelector("input[type=search]") as HTMLInputElement;
  await act(async () => {
    setValue(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
const text = () => container.textContent ?? "";
const rows = () => [...container.querySelectorAll("tbody tr")];
function button(name: string): HTMLButtonElement {
  const found = [...container.querySelectorAll("button")].find((b) => b.textContent === name);
  if (!found) throw new Error(`no button "${name}"`);
  return found;
}
const hasButton = (name: string) =>
  [...container.querySelectorAll("button")].some((b) => b.textContent === name);
async function click(el: Element) {
  await act(async () => {
    el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, button: 0 }));
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  calls = [];
  respond = () => json(200, result([]));
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  vi.useRealTimers();
});

describe("SearchResultsPage", () => {
  it("starts idle with no request and no dead control", async () => {
    await mount("/search");
    expect(text()).toContain("Type a name");
    expect(calls).toHaveLength(0);
    expect(hasButton("Clear")).toBe(false);
  });

  it("posts the text from the address, in the body, and shows every field of each hit", async () => {
    const hits = [
      user(1, {
        status: [
          { kind: "locked", at: "2026-11-01T09:12:00Z" },
          { kind: "disabled" },
          { kind: "tier0" },
        ],
        disambiguator: { title: "Analyst", office: "London" },
        mail: "priya.raman@corp.example.test",
      }),
      user(2),
    ];
    respond = () =>
      json(200, result([grp("users", hits), grp("groups", []), grp("computers", [])]));
    await mount("/search?q=priya");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.url.pathname.endsWith("/directory/search")).toBe(true);
    expect(calls[0]?.url.search).toBe("");
    expect(calls[0]?.body).toEqual({ q: "priya", groupLimit: 50 });

    const first = rows()[0] as HTMLElement;
    const t = first.textContent ?? "";
    expect(t).toContain("User");
    expect(t).toContain("Priya Raman 1");
    expect(t).toContain("praman1");
    expect(t).toContain("praman1@corp.example.test");
    expect(t).toContain("priya.raman@corp.example.test");
    expect(t).toContain("Disabled");
    expect(t).toContain("TIER 0");
    expect(t).toMatch(/Locked \d\d:\d\d/);
    expect(t).toContain("Analyst · London");
    expect(t).toContain("CN=Priya Raman 1,OU=Sales,DC=corp,DC=example,DC=test");
    expect(t).toContain("corp.example.test");
    expect(first.querySelector("mark")?.textContent).toBe("Priya");
    expect(rows()).toHaveLength(2);
    expect(text()).toContain("as of");
  });

  it("shows the API's trimmed counts in the filter and no other number", async () => {
    respond = () =>
      json(
        200,
        result([
          grp("users", [user(1)], { count: 13 }),
          grp("groups", [group(1)], { count: 2 }),
          grp("computers", [], { count: 0 }),
          grp("contacts", [], { count: 0 }),
        ]),
      );
    await mount("/search?q=pay");
    const labels = [...container.querySelectorAll("fieldset label")].map((l) => l.textContent);
    expect(labels).toEqual(["All", "Users (13)", "Groups (2)", "Computers (0)", "Contacts (0)"]);
  });

  it("shows no count when the API sent none", async () => {
    respond = () =>
      json(
        200,
        result([
          { type: "users", items: [user(1)] },
          { type: "groups", items: [] },
        ]),
      );
    await mount("/search?q=pr");
    const labels = [...container.querySelectorAll("fieldset label")].map((l) => l.textContent);
    expect(labels).toEqual(["All", "Users", "Groups", "Computers", "Contacts"]);
  });

  it("filters by type through the address, and asks the API for that type only", async () => {
    respond = (c) =>
      json(
        200,
        c.body["type"] === "groups"
          ? result([grp("groups", [group(1)])])
          : result([
              grp("users", [user(1)], { count: 4 }),
              grp("groups", [group(1)], { count: 1 }),
            ]),
      );
    await mount("/search?q=pay");
    const groups = [...container.querySelectorAll("input[type=radio]")].find(
      (r) => (r as HTMLInputElement).value === "groups",
    ) as HTMLInputElement;
    await click(groups);
    expect(window.location.search).toBe("?q=pay&type=groups");
    expect(calls[1]?.body).toEqual({ q: "pay", type: "groups", groupLimit: 50 });
    expect(rows()).toHaveLength(1);
    expect(rows()[0]?.textContent).toContain("Payroll 1");
    // The counts of the earlier all-types answer for the same text are kept.
    const labels = [...container.querySelectorAll("fieldset label")].map((l) => l.textContent);
    expect(labels).toContain("Users (4)");
  });

  it("opens a deep link with the type selected", async () => {
    respond = () => json(200, result([grp("groups", [group(1)])]));
    await mount("/search?q=pay&type=groups");
    expect(calls[0]?.body["type"]).toBe("groups");
    const checked = container.querySelector("input[type=radio]:checked") as HTMLInputElement;
    expect(checked.value).toBe("groups");
  });

  it("ignores a type it does not know", async () => {
    await mount("/search?q=pay&type=bogus");
    expect(calls[0]?.body).toEqual({ q: "pay", groupLimit: 50 });
  });

  it("links a user to the user search and links no other kind", async () => {
    respond = () =>
      json(
        200,
        result([
          grp("users", [user(1)]),
          grp("groups", [group(1)]),
          grp("computers", [
            { ...group(2), type: "computers", displayName: "WS-01", samAccountName: "WS-01$" },
          ]),
          grp("contacts", [{ ...group(3), type: "contacts", displayName: "Vendor Contact" }]),
        ]),
      );
    await mount("/search?q=x");
    const anchors = [...container.querySelectorAll("tbody a")] as HTMLAnchorElement[];
    expect(anchors.map((a) => a.getAttribute("href"))).toEqual(["/directory/users?q=praman1"]);
    expect(rows()).toHaveLength(4);
    // No anchor anywhere on the page leads to a path no module registered.
    const registered = collectContributions([directoryModule]).routes.map((r) => r.path);
    for (const a of container.querySelectorAll("a")) {
      expect(registered).toContain(new URL(a.getAttribute("href") ?? "", "http://x").pathname);
    }
  });

  it("opens a user's link without a page load", async () => {
    respond = () => json(200, result([grp("users", [user(1)])]));
    await mount("/search?q=pr");
    await click(container.querySelector("tbody a") as Element);
    expect(window.location.pathname + window.location.search).toBe("/directory/users?q=praman1");
  });

  it("renders hostile directory text as text, never markup", async () => {
    const evil = user(1, {
      displayName: "<img src=x onerror=alert(1)>",
      distinguishedName: "CN=<script>alert(1)</script>,DC=x",
      highlights: [{ field: "displayName", start: 1, length: 3 }],
      disambiguator: { title: "<b>boss</b>" },
    });
    respond = () => json(200, result([grp("users", [evil])]));
    await mount("/search?q=img");
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("tbody b")).toBeNull();
    expect(rows()[0]?.textContent).toContain("<img src=x onerror=alert(1)>");
  });

  it("shows the domain column only when a hit has a domain", async () => {
    respond = () => json(200, result([grp("users", [user(1, { domain: "" })])]));
    await mount("/search?q=pr");
    const heads = [...container.querySelectorAll("thead th")].map((h) => h.textContent);
    expect(heads).not.toContain("Domain");
  });

  it("debounces typing into one request and puts the text in the address", async () => {
    await mount("/search");
    await type("p");
    await type("pr");
    await type("pri");
    await settle(DEBOUNCE_MS - 1);
    expect(calls).toHaveLength(0);
    await settle(1);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.body["q"]).toBe("pri");
    expect(window.location.search).toBe("?q=pri");
  });

  it("follows back and forward", async () => {
    await mount("/search?q=first");
    await type("second");
    await settle();
    expect(window.location.search).toBe("?q=second");
    await act(async () => {
      window.history.replaceState(null, "", "/search?q=first");
      window.dispatchEvent(new PopStateEvent("popstate"));
    });
    expect((container.querySelector("input[type=search]") as HTMLInputElement).value).toBe("first");
    expect(calls.at(-1)?.body["q"]).toBe("first");
  });

  it("shows a loading skeleton while the request is out", async () => {
    let release: (r: Response) => void = () => undefined;
    respond = () => new Promise<Response>((res) => (release = res));
    await mount("/search?q=pri");
    expect(container.querySelector(".diq-skeleton")).not.toBeNull();
    await act(async () => release(json(200, result([grp("users", [user(1)])]))));
    expect(container.querySelector(".diq-skeleton")).toBeNull();
    expect(rows()).toHaveLength(1);
  });

  it("does not show a slow early answer over a newer one", async () => {
    const pending: Array<(r: Response) => void> = [];
    respond = () => new Promise<Response>((res) => pending.push(res));
    await mount("/search?q=a1");
    await type("b2");
    await settle();
    expect(pending).toHaveLength(2);
    await act(async () => pending[1]?.(json(200, result([grp("users", [user(2)])]))));
    await act(async () => pending[0]?.(json(200, result([grp("users", [user(1)])]))));
    expect(rows()).toHaveLength(1);
    expect(rows()[0]?.textContent).toContain("Priya Raman 2");
  });
});

describe("paging and show all", () => {
  it("offers Show all for a kind with more, and the link goes to that type", async () => {
    respond = () =>
      json(
        200,
        result([
          grp("users", [user(1)], { count: 120, more: true, nextCursor: "c1" }),
          grp("groups", [group(1)], { count: 1 }),
        ]),
      );
    await mount("/search?q=pr");
    const link = [...container.querySelectorAll("a")].find((a) =>
      a.textContent?.startsWith("Show all"),
    ) as HTMLAnchorElement;
    expect(link.textContent).toBe("Show all 120 users");
    expect(link.getAttribute("href")).toBe("/search?q=pr&type=users");
    // No Next page without a type: a cursor needs one.
    expect(hasButton("Next page")).toBe(false);
  });

  it("pages one type by the API's cursor, forward and back", async () => {
    respond = (c) => {
      const cursor = c.body["cursor"];
      if (cursor === "c1") {
        return json(200, result([grp("users", [user(51)], { count: 51, nextCursor: "c2" })]));
      }
      if (cursor === "c2") return json(200, result([grp("users", [user(52)], { count: 51 })]));
      return json(
        200,
        result([grp("users", [user(1)], { count: 51, more: true, nextCursor: "c1" })]),
      );
    };
    await mount("/search?q=pr&type=users");
    expect(text()).toContain("Showing 1–1 of 51 users.");
    expect(hasButton("Previous page")).toBe(false);
    await click(button("Next page"));
    expect(calls.at(-1)?.body).toEqual({ q: "pr", type: "users", groupLimit: 50, cursor: "c1" });
    expect(rows()[0]?.textContent).toContain("Priya Raman 51");
    expect(text()).toContain("Page 2");
    expect(text()).toContain("Showing 51–51 of 51 users.");
    await click(button("Next page"));
    expect(rows()[0]?.textContent).toContain("Priya Raman 52");
    expect(hasButton("Next page")).toBe(false);
    await click(button("Previous page"));
    await click(button("Previous page"));
    expect(rows()[0]?.textContent).toContain("Priya Raman 1");
    expect(window.location.search).toBe("?q=pr&type=users");
    expect(window.location.search).not.toContain("c1");
  });

  it("starts from page one when the text changes", async () => {
    respond = (c) =>
      json(200, result([grp("users", [user(c.body["cursor"] ? 2 : 1)], { nextCursor: "c1" })]));
    await mount("/search?q=pr&type=users");
    await click(button("Next page"));
    expect(text()).toContain("Page 2");
    await type("pri");
    await settle();
    expect(text()).not.toContain("Page 2");
    expect(calls.at(-1)?.body["cursor"]).toBeUndefined();
  });

  it("says when paging stopped at 1,000 hits", async () => {
    respond = () => json(200, result([grp("users", [user(1)], { limitReached: true })]));
    await mount("/search?q=pr&type=users");
    expect(text()).toContain("Showing the first 1,000 matches. Refine your search");
  });
});

describe("states", () => {
  it("renders the refine state with the hits and without counts", async () => {
    respond = () =>
      json(
        200,
        result(
          [
            { type: "users", items: [user(1)] },
            { type: "groups", items: [] },
          ],
          { refine: true },
        ),
      );
    await mount("/search?q=ab");
    expect(text()).toContain("Keep typing to narrow the search");
    expect(rows()).toHaveLength(1);
    const labels = [...container.querySelectorAll("fieldset label")].map((l) => l.textContent);
    expect(labels).toEqual(["All", "Users", "Groups", "Computers", "Contacts"]);
  });

  it("renders the refine state with no hits at all", async () => {
    respond = () => json(200, result([{ type: "users", items: [] }], { refine: true }));
    await mount("/search?q=a");
    expect(text()).toContain("Keep typing to narrow the search");
    expect(container.querySelector("table")).toBeNull();
  });

  it("shows the empty state in the scope's words, and Clear search returns to the start", async () => {
    await mount("/search?q=kowalski");
    expect(text()).toContain("No objects match “kowalski” in your scope");
    expect(text()).toContain("your scope may not cover it");
    await click(button("Clear search"));
    expect(window.location.pathname + window.location.search).toBe("/search");
    expect(text()).toContain("Type a name");
    expect(document.activeElement).toBe(container.querySelector("input[type=search]"));
  });

  it("shows the empty state when the API answers with no groups at all", async () => {
    respond = () => json(200, { asOf: null, refine: false, groups: [] });
    await mount("/search?q=zzz");
    expect(text()).toContain("No objects match");
  });

  it("says when the inventory has never synced", async () => {
    respond = () => json(200, { asOf: null, refine: false, groups: [grp("users", [user(1)])] });
    await mount("/search?q=pr");
    expect(text()).toContain("has not synced yet");
  });

  it.each([
    [403, "You don't have permission", false],
    [429, "Too many searches", true],
    [500, "The search failed", true],
    [503, "Search is unavailable", true],
  ])("shows a %i with the trace ID and the right recovery", async (status, title, retry) => {
    respond = () => problem(status);
    await mount("/search?q=pr");
    const alert = container.querySelector("[role=alert]");
    expect(alert?.textContent).toContain(title);
    expect(alert?.textContent).toContain("trace-1");
    expect(hasButton("Retry")).toBe(retry);
  });

  it("shows a 400 without a Retry that cannot help, and offers Clear search", async () => {
    respond = () =>
      problem(400, {
        detail: "The search text is empty.",
        errors: [{ code: "query_too_short", detail: "", in: "body", pointer: "/q" }],
      });
    await mount("/search?q=pr");
    expect(text()).toContain("The search text is empty.");
    expect(text()).toContain("trace-1");
    expect(hasButton("Retry")).toBe(false);
    expect(hasButton("Clear search")).toBe(true);
  });

  it("offers a way to the first page when a cursor is refused", async () => {
    respond = (c) =>
      c.body["cursor"] === undefined
        ? json(200, result([grp("users", [user(1)], { nextCursor: "c1" })]))
        : problem(400, {
            errors: [{ code: "cursor_invalid", detail: "", in: "body", pointer: "/cursor" }],
          });
    await mount("/search?q=pr&type=users");
    await click(button("Next page"));
    expect(text()).toContain("no longer available");
    await click(button("Back to the first page"));
    expect(rows()).toHaveLength(1);
  });

  it("Retry repeats the search and recovers", async () => {
    let failing = true;
    respond = () => (failing ? problem(500) : json(200, result([grp("users", [user(1)])])));
    await mount("/search?q=pr");
    failing = false;
    await click(button("Retry"));
    expect(calls).toHaveLength(2);
    expect(rows()).toHaveLength(1);
  });

  it("shows an unreachable server with Retry", async () => {
    respond = () => {
      throw new TypeError("fetch failed");
    };
    await mount("/search?q=pr");
    expect(text()).toContain("Can't reach the server");
    expect(hasButton("Retry")).toBe(true);
  });

  it("offers Sign in on a 401", async () => {
    respond = () => problem(401);
    await mount("/search?q=pr");
    expect(text()).toContain("Your session has ended");
    expect(hasButton("Sign in")).toBe(true);
    expect(hasButton("Retry")).toBe(false);
  });
});

describe("a recovery-password-looking query", () => {
  const rp = "123456-123456-123456-123456-123456-123456-123456-123456";

  it("typed in the box is refused before any request and never reaches the address", async () => {
    await mount("/search");
    await type(rp);
    await settle(2 * DEBOUNCE_MS);
    expect(calls).toHaveLength(0);
    expect(text()).toContain(RECOVERY_PASSWORD_MESSAGE);
    expect(window.location.href).not.toContain("123456");
    // Submitting does not send it either.
    await act(async () => {
      container
        .querySelector("form")
        ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(calls).toHaveLength(0);
    expect(window.location.href).not.toContain("123456");
  });

  it("arriving in the address is refused, sent nowhere, and removed from the address", async () => {
    await mount(`/search?q=${rp}&type=users`);
    expect(calls).toHaveLength(0);
    expect(text()).toContain(RECOVERY_PASSWORD_MESSAGE);
    expect(window.location.href).not.toContain("123456");
    expect(window.location.search).toBe("?type=users");
    expect((container.querySelector("input[type=search]") as HTMLInputElement).value).toBe("");
  });

  it("is refused when the server refuses it too, with the same words and the trace ID", async () => {
    respond = () =>
      problem(400, {
        errors: [{ code: "query_refused", detail: "", in: "body", pointer: "/q" }],
      });
    await mount("/search?q=abc");
    expect(text()).toContain(RECOVERY_PASSWORD_MESSAGE);
    expect(text()).toContain("trace-1");
  });
});

describe("controls", () => {
  it("Clear empties the box and the address and returns focus to it", async () => {
    await mount("/search?q=pr&type=users");
    await click(button("Clear"));
    expect((container.querySelector("input[type=search]") as HTMLInputElement).value).toBe("");
    expect(window.location.pathname + window.location.search).toBe("/search?type=users");
    expect(document.activeElement).toBe(container.querySelector("input[type=search]"));
  });

  it("searches at once on Enter", async () => {
    await mount("/search");
    await type("ann");
    await act(async () => {
      container
        .querySelector("form")
        ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(calls).toHaveLength(1);
  });
});
