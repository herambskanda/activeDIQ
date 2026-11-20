// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createApiClient } from "../../api/client";
import { DEBOUNCE_MS, UserSearchPage } from "./user-search-page";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// Fixtures live in tests only (CLAUDE.md rule 6).
const user = (n: number, over: Record<string, unknown> = {}) => ({
  type: "users",
  objectId: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
  displayName: `Test Person ${n}`,
  matchClass: "prefix",
  highlights: [],
  samAccountName: `tperson${n}`,
  userPrincipalName: `tperson${n}@lab.test`,
  distinguishedName: `CN=Test Person ${n},OU=Lab,DC=lab,DC=test`,
  domain: "",
  status: [],
  ...over,
});
const answer = (
  items: unknown[],
  group: Record<string, unknown> = {},
  top: Record<string, unknown> = {},
) => ({
  groups: [{ type: "users", items, ...group }],
  refine: false,
  asOf: "2026-11-01T10:00:00Z",
  ...top,
});

interface Call {
  readonly method: string;
  readonly path: string;
  readonly body: { q?: string; type?: string; cursor?: string };
}
let calls: Call[];
let respond: (body: Call["body"]) => Response | Promise<Response>;
let container: HTMLElement;
let root: Root;

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const client = () =>
  createApiClient({
    baseUrl: "http://localhost/api/v1",
    fetch: async (req) => {
      const text = await req.clone().text();
      const body = text === "" ? {} : (JSON.parse(text) as Call["body"]);
      calls.push({ method: req.method, path: new URL(req.url).pathname, body });
      return respond(body);
    },
  });

async function mount() {
  await act(async () => {
    root.render(<UserSearchPage client={client()} />);
  });
}
const setNativeValue = (input: HTMLInputElement, value: string) => {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (!setter) throw new Error("no value setter");
  setter.call(input, value);
};
async function type(value: string) {
  const input = el("input") as HTMLInputElement;
  await act(async () => {
    setNativeValue(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
async function settle(ms = DEBOUNCE_MS) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}
function el(selector: string): Element {
  const found = container.querySelector(selector);
  if (!found) throw new Error(`no element matches ${selector}`);
  return found;
}
const inputValue = () => (el("input") as HTMLInputElement).value;
const text = () => container.textContent ?? "";
const findButton = (name: string) =>
  [...container.querySelectorAll("button")].find((b) => b.textContent === name);
function button(name: string): HTMLButtonElement {
  const found = findButton(name);
  if (!found) throw new Error(`no button "${name}"`);
  return found;
}

beforeEach(() => {
  vi.useFakeTimers();
  calls = [];
  respond = () => json(200, answer([]));
  window.history.replaceState(null, "", "/directory/users");
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  vi.useRealTimers();
});

describe("UserSearchPage", () => {
  it("starts idle and calls nothing", async () => {
    await mount();
    expect(text()).toContain("Type a name");
    expect(calls).toHaveLength(0);
  });

  it("debounces typing into one request and shows the users the API returned", async () => {
    respond = () => json(200, answer([user(1), user(2, { status: [{ kind: "disabled" }] })]));
    await mount();
    await type("t");
    await type("te");
    await type("tes");
    await settle(DEBOUNCE_MS - 1);
    expect(calls).toHaveLength(0);
    await settle(1);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.method).toBe("POST");
    expect(calls[0]?.path.endsWith("/directory/search")).toBe(true);
    expect(calls[0]?.body.q).toBe("tes");
    expect(calls[0]?.body.type).toBe("users");
    expect(calls.some((c) => c.path.endsWith("/directory/users"))).toBe(false);
    const rows = container.querySelectorAll("tbody tr");
    expect(rows).toHaveLength(2);
    expect(rows[0]?.textContent).toContain("Test Person 1");
    expect(rows[0]?.textContent).toContain("tperson1@lab.test");
    expect(rows[1]?.textContent).toContain("Disabled");
    expect(text()).toContain("2 users found.");
    expect(window.location.search).toBe("?q=tes");
  });

  it("searches at once on Enter", async () => {
    await mount();
    await type("ann");
    await act(async () => {
      el("form").dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(calls).toHaveLength(1);
  });

  it("shows a loading skeleton while the request is out", async () => {
    let release: (r: Response) => void = () => undefined;
    respond = () => new Promise<Response>((res) => (release = res));
    await mount();
    await type("ann");
    await settle();
    expect(container.querySelector(".diq-skeleton")).not.toBeNull();
    await act(async () => release(json(200, answer([user(1)]))));
    expect(container.querySelector(".diq-skeleton")).toBeNull();
    expect(container.querySelectorAll("tbody tr")).toHaveLength(1);
  });

  it("shows the empty state with a way out", async () => {
    await mount();
    await type("nobody");
    await settle();
    expect(text()).toContain("No users match “nobody” in your scope");
    await act(async () => button("Clear search").click());
    expect(text()).toContain("Type a name");
    expect(inputValue()).toBe("");
  });

  it("pages by the API's cursor and shows its count", async () => {
    respond = (body) =>
      body.cursor === undefined
        ? json(
            200,
            answer(
              Array.from({ length: 50 }, (_, i) => user(i)),
              { count: 70, nextCursor: "c1" },
            ),
          )
        : json(200, answer([user(99)], { count: 70 }));
    await mount();
    await type("tes");
    await settle();
    expect(text()).toContain("Showing 1–50 of 70 users.");
    await act(async () => button("Next page").click());
    expect(calls[1]?.body.cursor).toBe("c1");
    expect(text()).toContain("Showing 51–51 of 70 users.");
    expect(findButton("Next page")).toBeUndefined();
    await act(async () => button("Previous page").click());
    expect(text()).toContain("Showing 1–50 of 70 users.");
  });

  it("shows only what the API returned: status chips, e-mail and inventory time", async () => {
    respond = () =>
      json(
        200,
        answer([
          user(1, {
            mail: "p1@lab.test",
            status: [{ kind: "locked" }],
            disambiguator: { title: "Engineer" },
          }),
        ]),
      );
    await mount();
    await type("tes");
    await settle();
    const row = el("tbody tr").textContent ?? "";
    expect(row).toContain("p1@lab.test");
    expect(row).toContain("Locked");
    expect(row).toContain("Engineer");
    expect(text()).toContain("Directory inventory as of");
  });

  it("asks to keep typing when the API says refine", async () => {
    respond = () => json(200, { groups: [{ type: "users", items: [] }], refine: true, asOf: null });
    await mount();
    await type("te");
    await settle();
    expect(text()).toContain("Keep typing to narrow the search");
  });

  it("shows permission denied on 403 without a retry", async () => {
    respond = () => json(403, { type: "about:blank", title: "Forbidden", status: 403 });
    await mount();
    await type("ann");
    await settle();
    expect(el('[role="alert"]').textContent).toContain("don't have permission");
    expect(container.querySelectorAll("tbody tr")).toHaveLength(0);
    expect(findButton("Retry")).toBeUndefined();
  });

  it("shows an error with a Retry that repeats the search and recovers", async () => {
    respond = () =>
      json(500, { type: "about:blank", title: "boom", status: 500, traceId: "trace-9" });
    await mount();
    await type("ann");
    await settle();
    const alert = el('[role="alert"]').textContent ?? "";
    expect(alert).toContain("The search failed");
    expect(alert).toContain("trace-9");
    expect(alert).not.toContain("boom");
    respond = () => json(200, answer([user(1)]));
    await act(async () => button("Retry").click());
    expect(calls).toHaveLength(2);
    expect(container.querySelectorAll("tbody tr")).toHaveLength(1);
  });

  it("offers Sign in, not Retry, when the session has ended", async () => {
    respond = () => json(401, { type: "about:blank", title: "Unauthenticated", status: 401 });
    await mount();
    await type("ann");
    await settle();
    expect(el('[role="alert"]').textContent).toContain("Your session has ended");
    expect(findButton("Retry")).toBeUndefined();
    expect(findButton("Sign in")).toBeDefined();
  });

  it("shows unreachable when the network fails", async () => {
    respond = () => {
      throw new TypeError("Failed to fetch");
    };
    await mount();
    await type("ann");
    await settle();
    expect(text()).toContain("Can't reach the server");
    expect(findButton("Retry")).toBeDefined();
  });

  it("accepts syntax characters as plain text, and refuses a recovery password beside the box", async () => {
    await mount();
    await type("o'brien (it)");
    await settle();
    expect(calls).toHaveLength(1);
    expect(calls[0]?.body.q).toBe("o'brien (it)");
    await type("123456-123456-123456-123456-123456-123456-123456-123456");
    await settle();
    expect(el("input").getAttribute("aria-invalid")).toBe("true");
    expect(calls).toHaveLength(1);
  });

  it("renders directory strings as text, never as markup", async () => {
    respond = () => json(200, answer([user(1, { displayName: "<img src=x onerror=alert(1)>" })]));
    await mount();
    await type("img");
    await settle();
    expect(container.querySelector("tbody img")).toBeNull();
    expect(el("tbody th").textContent).toBe("<img src=x onerror=alert(1)>");
  });

  it("opens a deep link with the search already run", async () => {
    window.history.replaceState(null, "", "/directory/users?q=ann");
    respond = () => json(200, answer([user(1)]));
    await mount();
    expect(inputValue()).toBe("ann");
    expect(calls[0]?.body.q).toBe("ann");
    expect(container.querySelectorAll("tbody tr")).toHaveLength(1);
  });

  it("follows back and forward", async () => {
    respond = (body) => json(200, answer([user(body.q === "aa" ? 1 : 2)]));
    await mount();
    await type("aa");
    await settle();
    await type("bb");
    await settle();
    expect(el("tbody th").textContent).toBe("Test Person 2");
    await act(async () => {
      window.history.back();
      await vi.advanceTimersByTimeAsync(50);
    });
    expect(inputValue()).toBe("aa");
    expect(el("tbody th").textContent).toBe("Test Person 1");
  });

  it("ignores a slow earlier answer that arrives after a newer one", async () => {
    const pending = new Map<string, (r: Response) => void>();
    respond = (body) => new Promise<Response>((res) => pending.set(body.q ?? "", res));
    const resolveFor = (q: string) => {
      const r = pending.get(q);
      if (!r) throw new Error(`no request for ${q}`);
      return r;
    };
    await mount();
    await type("aa");
    await settle();
    await type("bb");
    await settle();
    await act(async () => resolveFor("bb")(json(200, answer([user(2)]))));
    await act(async () => resolveFor("aa")(json(200, answer([user(1)]))));
    expect(el("tbody th").textContent).toBe("Test Person 2");
  });
});
