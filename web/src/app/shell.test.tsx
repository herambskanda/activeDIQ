// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { API_BASE_URL, createApiClient, setCsrfToken } from "../api/client";
import type { WebModule } from "./modules";
import { safeNext } from "./session";
import { Shell } from "./shell";
import { RECOVERY_PASSWORD_MESSAGE } from "./palette-wiring";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const json = (status: number, body?: unknown) =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

let hasSession: boolean;
let calls: { path: string; method: string; csrf: string | null; body: string }[];
let container: HTMLElement;
let root: Root;
let totpOk: boolean;
let searchHandler: (q: string) => Response | Promise<Response>;

const client = () =>
  createApiClient({
    baseUrl: "http://localhost/api/v1",
    fetch: async (req) => {
      const path = new URL(req.url).pathname.replace(API_BASE_URL, "");
      calls.push({
        path,
        method: req.method,
        csrf: req.headers.get("X-CSRF-Token"),
        body: await req.clone().text(),
      });
      if (path === "/auth/csrf") {
        return hasSession
          ? json(200, { header: "X-CSRF-Token", value: "csrf-1" })
          : json(401, { type: "/problems/unauthenticated", title: "Unauthenticated", status: 401 });
      }
      if (path === "/auth/break-glass/password") {
        const ok = JSON.parse(await req.clone().text()).password === "right";
        return ok
          ? new Response(null, { status: 204 })
          : json(401, { type: "/problems/sign-in-failed", title: "Sign-in failed", status: 401 });
      }
      if (path === "/auth/second-factor/totp/verify") {
        if (!totpOk) {
          return json(401, {
            type: "/problems/sign-in-failed",
            title: "Sign-in failed",
            status: 401,
          });
        }
        hasSession = true;
        return new Response(null, { status: 204 });
      }
      if (path === "/directory/search") {
        const parsed = JSON.parse(await req.clone().text());
        return searchHandler(parsed.q);
      }
      return json(404, { type: "about:blank", title: "nf", status: 404 });
    },
  });

const modules: WebModule[] = [
  {
    id: "directory",
    register: (r) => {
      r.route({ path: "/directory/users", component: () => <p>Users screen</p> });
      r.palette({
        id: "directory.search-users",
        label: "Search users",
        keywords: ["find", "user", "people", "directory"],
        route: "/directory/users",
      });
    },
  },
  {
    id: "other",
    register: (r) => {
      r.route({ path: "/other", component: () => <p>Other screen</p> });
    },
  },
];

function requireInput(el: HTMLInputElement | null): HTMLInputElement {
  if (!el) throw new Error("expected input element");
  return el;
}

const text = () => container.textContent ?? "";
const setValue = (input: HTMLInputElement, value: string) => {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  setter?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
};
const field = (label: string) => {
  const l = [...container.querySelectorAll("label")].find((x) => x.textContent === label);
  return container.querySelector(`#${CSS.escape(l?.htmlFor ?? "none")}`) as HTMLInputElement;
};
async function fill(label: string, value: string) {
  await act(async () => setValue(field(label), value));
}
async function submit() {
  await act(async () => {
    container
      .querySelector("form")
      ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
}
const ctrlK = () =>
  document.dispatchEvent(new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }));
async function pressCtrlK() {
  await act(async () => ctrlK());
}
const paletteInput = () =>
  requireInput(document.querySelector<HTMLInputElement>('input[role="combobox"]'));
/** Types a query and lets the debounce (250 ms) elapse. Needs fake timers. */
async function typeQuery(q: string) {
  await act(async () => {
    setValue(paletteInput(), q);
    vi.advanceTimersByTime(300);
  });
}
const searchCalls = () => calls.filter((c) => c.path === "/directory/search");
async function mount() {
  await act(async () => root.render(<Shell modules={modules} client={client()} />));
}

beforeEach(() => {
  hasSession = false;
  totpOk = true;
  calls = [];
  searchHandler = (q: string) =>
    json(200, {
      asOf: "2026-11-01T15:00:00Z",
      refine: false,
      groups: [
        {
          type: "users",
          count: 1,
          items: [
            {
              objectId: "u-1",
              type: "users",
              displayName: `User for ${q}`,
              samAccountName: q,
              distinguishedName: `CN=${q},DC=corp,DC=test`,
              domain: "corp.test",
              matchClass: "exact",
              status: [],
              highlights: [],
            },
          ],
        },
      ],
    });
  setCsrfToken(undefined);
  window.history.replaceState(null, "", "/other?x=1");
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  vi.useRealTimers();
});

describe("Shell session gate", () => {
  it("shows the sign-in screen when there is no session, keeping the requested address", async () => {
    await mount();
    expect(text()).toContain("Sign in to activeDIQ");
    expect(text()).not.toContain("Other screen");
    expect(window.location.pathname).toBe("/sign-in");
    expect(new URLSearchParams(window.location.search).get("next")).toBe("/other?x=1");
  });

  it("opens the requested screen at once when a session exists", async () => {
    hasSession = true;
    await mount();
    expect(text()).toContain("Other screen");
    expect(window.location.pathname).toBe("/other");
  });

  it("signs in with password then code, lands on the requested page and sends the CSRF value", async () => {
    await mount();
    await fill("Account name", "breakglass");
    await fill("Password", "right");
    await submit();
    expect(text()).toContain("Authenticator code");
    expect(calls.find((c) => c.path === "/auth/break-glass/password")?.body).toBe(
      JSON.stringify({ username: "breakglass", password: "right" }),
    );
    await fill("Authenticator code", "123456");
    await submit();
    expect(text()).toContain("Other screen");
    expect(window.location.pathname + window.location.search).toBe("/other?x=1");
    // The session's CSRF value is now attached to mutations.
    const c = client();
    await c.POST("/auth/logout");
    expect(calls.at(-1)?.csrf).toBe("csrf-1");
  });

  it("shows one generic error on a wrong password and stays on the form with the account kept", async () => {
    await mount();
    await fill("Account name", "breakglass");
    await fill("Password", "wrong");
    await submit();
    expect(container.querySelector('[role="alert"]')?.textContent).toContain("Sign-in failed");
    expect(field("Account name").value).toBe("breakglass");
    expect(text()).not.toContain("Authenticator code");
  });

  it("validates empty fields beside the field without calling the API", async () => {
    await mount();
    const before = calls.length;
    await submit();
    expect(text()).toContain("Enter your account name.");
    expect(calls.length).toBe(before);
  });

  it("starts over when the code is refused", async () => {
    totpOk = false;
    await mount();
    await fill("Account name", "breakglass");
    await fill("Password", "right");
    await submit();
    await fill("Authenticator code", "000000");
    await submit();
    expect(container.querySelector('[role="alert"]')?.textContent).toContain("Sign-in failed");
    expect(text()).toContain("Password");
  });
});

describe("safeNext", () => {
  it("follows only paths on this console", () => {
    expect(safeNext("/directory/users?q=a", "/h")).toBe("/directory/users?q=a");
    expect(safeNext("//evil.test", "/h")).toBe("/h");
    expect(safeNext("https://evil.test", "/h")).toBe("/h");
    expect(safeNext("/\\evil.test", "/h")).toBe("/h");
    expect(safeNext("/sign-in?next=/x", "/h")).toBe("/h");
    expect(safeNext(null, "/h")).toBe("/h");
  });
});

describe("T-1101 AC 1: Command palette entry points, focus, and 5-minute query TTL", () => {
  beforeEach(() => {
    hasSession = true;
  });

  it("opens focused on clicking the top-bar search field, and closes on Escape", async () => {
    await mount();
    const searchBtn = container.querySelector<HTMLButtonElement>('[data-testid="top-bar-search"]');
    expect(searchBtn).not.toBeNull();

    await act(async () => {
      searchBtn?.click();
    });

    const dialog = document.querySelector<HTMLDivElement>('[role="dialog"]');
    expect(dialog).not.toBeNull();
    const input = dialog?.querySelector<HTMLInputElement>('input[role="combobox"]');
    expect(document.activeElement).toBe(input);

    // Escape closes it
    await act(async () => {
      dialog?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    });
    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });

  it("opens on Ctrl+K and toggles closed on a second press", async () => {
    await mount();
    // Press Ctrl+K to open
    await act(async () => {
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });
    expect(document.querySelector('[role="dialog"]')).not.toBeNull();

    // Press Ctrl+K again to close
    await act(async () => {
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });
    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });

  it("opens on '/' outside a text field, but ignores '/' inside a field", async () => {
    await mount();
    // Outside a field
    await act(async () => {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "/", bubbles: true }));
    });
    expect(document.querySelector('[role="dialog"]')).not.toBeNull();

    // Close palette
    await act(async () => {
      document
        .querySelector('[role="dialog"]')
        ?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    });
    expect(document.querySelector('[role="dialog"]')).toBeNull();

    // Inside an input element
    const testInput = document.createElement("input");
    document.body.appendChild(testInput);
    testInput.focus();

    await act(async () => {
      testInput.dispatchEvent(new KeyboardEvent("keydown", { key: "/", bubbles: true }));
    });
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    testInput.remove();
  });

  it("keeps the last query within 5 minutes, but clears it after 5 minutes", async () => {
    vi.useFakeTimers();
    await mount();

    // Open palette and type "alovelace"
    await act(async () => {
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });
    const input = requireInput(document.querySelector<HTMLInputElement>('input[role="combobox"]'));
    await act(async () => {
      setValue(input, "alovelace");
    });
    expect(input.value).toBe("alovelace");

    // Close palette
    await act(async () => {
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });

    // Reopen after 4 minutes -> query preserved
    await act(async () => {
      vi.advanceTimersByTime(4 * 60 * 1000);
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });
    const reopenedInput = requireInput(
      document.querySelector<HTMLInputElement>('input[role="combobox"]'),
    );
    expect(reopenedInput.value).toBe("alovelace");

    // Close again
    await act(async () => {
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });

    // Reopen after more than 5 minutes -> query reset
    await act(async () => {
      vi.advanceTimersByTime(6 * 60 * 1000);
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });
    const resetInput = requireInput(
      document.querySelector<HTMLInputElement>('input[role="combobox"]'),
    );
    expect(resetInput.value).toBe("");
  });
});

describe("T-1101 AC 2: Debounced search, grouping order, and stale answers", () => {
  beforeEach(() => {
    hasSession = true;
  });

  it("makes one debounced request to /directory/search and renders groups in order", async () => {
    vi.useFakeTimers();
    searchHandler = (q: string) =>
      json(200, {
        asOf: "2026-11-01T15:00:00Z",
        refine: false,
        groups: [
          {
            type: "users",
            count: 2,
            items: [
              {
                objectId: "u-exact",
                type: "users",
                displayName: "Ada Lovelace",
                samAccountName: q,
                matchClass: "exact",
                distinguishedName: "CN=Ada,DC=corp,DC=test",
                domain: "corp.test",
                status: [{ kind: "locked", at: "2026-11-01T09:12:00Z" }],
                highlights: [],
              },
              {
                objectId: "u-prefix",
                type: "users",
                displayName: "Adam Smith",
                samAccountName: "asmith",
                matchClass: "prefix",
                distinguishedName: "CN=Adam,DC=corp,DC=test",
                domain: "corp.test",
                status: [],
                highlights: [],
              },
            ],
          },
          {
            type: "groups",
            count: 1,
            items: [
              {
                objectId: "g-1",
                type: "groups",
                displayName: "Admins",
                samAccountName: "GG-Admins",
                matchClass: "prefix",
                distinguishedName: "CN=Admins,DC=corp,DC=test",
                domain: "corp.test",
                status: [{ kind: "tier0" }],
                highlights: [],
              },
            ],
          },
        ],
      });

    await mount();
    await act(async () => {
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });

    const input = requireInput(document.querySelector<HTMLInputElement>('input[role="combobox"]'));
    await act(async () => {
      setValue(input, "ad");
    });

    // Before debounce timer expires, no request made
    expect(calls.filter((c) => c.path === "/directory/search")).toHaveLength(0);

    // Advance past debounce (250ms)
    await act(async () => {
      vi.advanceTimersByTime(300);
    });

    // Exactly 1 request made with body { q: "ad" }
    const searchCalls = calls.filter((c) => c.path === "/directory/search");
    expect(searchCalls).toHaveLength(1);
    const firstCall = searchCalls[0];
    if (!firstCall) throw new Error("expected search call");
    expect(JSON.parse(firstCall.body)).toEqual({ q: "ad" });

    // Groups rendered in order: Exact first, then Users, Groups
    const groupHeadings = [...document.querySelectorAll<HTMLElement>(".diq-pal__gh")].map((el) =>
      el.textContent?.trim(),
    );
    expect(groupHeadings[0]).toContain("Exact");
    expect(groupHeadings[1]).toContain("Users");
    expect(groupHeadings[2]).toContain("Groups");

    // Status chip present
    expect(document.body.textContent).toContain("Locked 09:12");
    expect(document.body.textContent).toContain("TIER 0");
  });
});

describe("T-1101 AC 3: Registered Pages group and navigation", () => {
  beforeEach(() => {
    hasSession = true;
  });

  it("lists registered pages whose routes exist, navigates on select, and has no actions group", async () => {
    vi.useFakeTimers();
    searchHandler = () =>
      json(200, {
        asOf: null,
        refine: false,
        groups: [],
      });

    await mount();
    await act(async () => {
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });

    const input = requireInput(document.querySelector<HTMLInputElement>('input[role="combobox"]'));
    // Type query matching "Search users" keyword "people"
    await act(async () => {
      setValue(input, "people");
      vi.advanceTimersByTime(300);
    });

    // "Pages" group is visible with "Search users"
    const groupHeadings = [...document.querySelectorAll<HTMLElement>(".diq-pal__gh")].map((el) =>
      el.textContent?.trim(),
    );
    expect(groupHeadings).toContain("Pages");
    expect(groupHeadings).not.toContain("Actions");

    const pageOption = document.querySelector<HTMLElement>('[role="option"]');
    expect(pageOption?.textContent).toContain("Search users");

    // Clicking page option navigates to /directory/users
    await act(async () => {
      pageOption?.click();
    });
    expect(window.location.pathname).toBe("/directory/users");
  });
});

describe("T-1101 AC 4: Destination routing for Show all and Exact hits", () => {
  beforeEach(() => {
    hasSession = true;
  });

  it("opens /search?q= on Show all and /directory/users?q= on exact user hit", async () => {
    vi.useFakeTimers();
    searchHandler = () =>
      json(200, {
        asOf: null,
        refine: false,
        groups: [
          {
            type: "users",
            count: 10,
            items: [
              {
                objectId: "u-exact",
                type: "users",
                displayName: "Ada Lovelace",
                samAccountName: "alovelace",
                matchClass: "exact",
                distinguishedName: "CN=Ada,DC=corp,DC=test",
                domain: "corp.test",
                status: [],
                highlights: [],
              },
            ],
          },
        ],
      });

    await mount();
    await act(async () => {
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });

    const input = requireInput(document.querySelector<HTMLInputElement>('input[role="combobox"]'));
    await act(async () => {
      setValue(input, "alovelace");
      vi.advanceTimersByTime(300);
    });

    // Click exact hit -> lands on /directory/users?q=alovelace
    const exactRow = document.querySelector<HTMLElement>('[role="option"]');
    await act(async () => {
      exactRow?.click();
    });
    expect(window.location.pathname).toBe("/directory/users");
    expect(new URLSearchParams(window.location.search).get("q")).toBe("alovelace");
  });
});

describe("T-1101 AC 5: Unhappy states (403, 429, 500, empty, recovery password)", () => {
  beforeEach(() => {
    hasSession = true;
  });

  it("refuses 48-digit recovery password in the browser and sends 0 requests", async () => {
    vi.useFakeTimers();
    await mount();
    await act(async () => {
      document.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });

    const input = requireInput(document.querySelector<HTMLInputElement>('input[role="combobox"]'));
    const pwd48 = "123456-789012-345678-901234-567890-123456-789012-345678";
    await act(async () => {
      setValue(input, pwd48);
      vi.advanceTimersByTime(500);
    });

    // Zero API requests sent
    expect(calls.filter((c) => c.path === "/directory/search")).toHaveLength(0);

    // IA message shown
    expect(document.body.textContent).toContain(RECOVERY_PASSWORD_MESSAGE);
  });

  describe.each([
    ["dash", "-"],
    ["space", " "],
    ["no", ""],
  ])("typed block by block with %s separators", (_n, sep) => {
    it("sends nothing after the first block, and refuses from the first block plus separator", async () => {
      vi.useFakeTimers();
      await mount();
      await pressCtrlK();
      const blocks = [
        "111111",
        "222222",
        "333333",
        "444444",
        "555555",
        "666666",
        "777777",
        "888888",
      ];
      // The first block alone is a plain 6-digit number (6 of 48 digits): it may be searched.
      await typeQuery(blocks[0] ?? "");
      expect(searchCalls().map((c) => JSON.parse(c.body ?? "{}").q)).toEqual(["111111"]);
      let typed = blocks[0] ?? "";
      // From the first block plus its separator (or the ninth digit) onward, nothing more is sent.
      for (const b of blocks.slice(1)) {
        if (sep !== "") {
          await typeQuery(typed + sep);
          expect(document.body.textContent, typed + sep).toContain(RECOVERY_PASSWORD_MESSAGE);
        }
        typed += sep + b;
        await typeQuery(typed);
        expect(document.body.textContent, typed).toContain(RECOVERY_PASSWORD_MESSAGE);
        expect(searchCalls(), typed).toHaveLength(1);
      }
    });
  });

  it("full-width digits typed block by block are refused too", async () => {
    vi.useFakeTimers();
    await mount();
    await pressCtrlK();
    await typeQuery("１１１１１１-");
    await typeQuery("１１１１１１-２２２２２２");
    expect(searchCalls()).toHaveLength(0);
    expect(document.body.textContent).toContain(RECOVERY_PASSWORD_MESSAGE);
  });

  it("does not retain a refused prefix for the next open", async () => {
    vi.useFakeTimers();
    await mount();
    await pressCtrlK();
    await typeQuery("111111-222222");
    await pressCtrlK(); // close
    await pressCtrlK(); // reopen
    expect(paletteInput().value).toBe("");
  });

  it("an 8-digit key ID and a name are still searched", async () => {
    vi.useFakeTimers();
    await mount();
    await pressCtrlK();
    await typeQuery("12345678");
    await typeQuery("alovelace");
    expect(searchCalls().map((c) => JSON.parse(c.body ?? "{}").q)).toEqual([
      "12345678",
      "alovelace",
    ]);
  });

  const problem = (status: number, title: string) =>
    new Response(
      JSON.stringify({ type: "about:blank", title, status, traceId: `trace-${status}-xyz` }),
      { status, headers: { "content-type": "application/problem+json" } },
    );

  async function searchFor(q: string) {
    vi.useFakeTimers();
    await mount();
    await pressCtrlK();
    await typeQuery(q);
  }

  it("403: names the denial and shows the Trace ID", async () => {
    searchHandler = () => problem(403, "Forbidden");
    await searchFor("test");
    expect(document.body.textContent).toContain("Search forbidden");
    expect(document.body.textContent).toContain("trace-403-xyz");
  });

  it("429: says to wait and shows the Trace ID", async () => {
    searchHandler = () => problem(429, "Too Many Requests");
    await searchFor("test");
    expect(document.body.textContent).toContain("Too many searches");
    expect(document.body.textContent).toContain("trace-429-xyz");
  });

  it("500: says the search failed, shows the Trace ID and offers a retry that searches again", async () => {
    searchHandler = () => problem(500, "Internal Server Error");
    await searchFor("test");
    expect(document.body.textContent).toContain("The search failed");
    expect(document.body.textContent).toContain("trace-500-xyz");
    const retry = [...document.querySelectorAll("button")].find((b) =>
      /try again/i.test(b.textContent ?? ""),
    );
    expect(retry).toBeDefined();
    await act(async () => retry?.click());
    await act(async () => {
      vi.advanceTimersByTime(300);
    });
    expect(calls.filter((c) => c.path === "/directory/search")).toHaveLength(2);
  });

  it("empty list: says nothing matched in the user's scope", async () => {
    searchHandler = () => json(200, { asOf: null, refine: false, groups: [] });
    await searchFor("zzzz");
    expect(document.body.textContent).toContain("No objects match “zzzz” in your scope");
  });

  it("server unreachable: says so instead of rendering blank", async () => {
    searchHandler = () => Promise.reject(new TypeError("Failed to fetch"));
    await searchFor("test");
    expect(document.body.textContent).toContain("Can't reach the server");
  });
});

describe("T-1101 AC 1: focus returns to the opener", () => {
  beforeEach(() => {
    hasSession = true;
  });

  it("returns focus to the top-bar button after Escape", async () => {
    await mount();
    const btn = container.querySelector<HTMLButtonElement>('[data-testid="top-bar-search"]');
    btn?.focus();
    await act(async () => btn?.click());
    expect(document.activeElement).toBe(paletteInput());
    await act(async () => {
      document
        .querySelector('[role="dialog"]')
        ?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    });
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(document.activeElement).toBe(btn);
  });

  it("returns focus to the element that had it when Ctrl+K was pressed, on a second press", async () => {
    await mount();
    const btn = container.querySelector<HTMLButtonElement>('[data-testid="top-bar-search"]');
    btn?.focus();
    await pressCtrlK();
    expect(document.activeElement).toBe(paletteInput());
    await act(async () => {
      paletteInput().dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }),
      );
    });
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(document.activeElement).toBe(btn);
  });
});

describe("T-1101 AC 2: request count and stale answers", () => {
  beforeEach(() => {
    hasSession = true;
  });

  const answer = (name: string) =>
    json(200, {
      asOf: null,
      refine: false,
      groups: [
        {
          type: "users",
          count: 1,
          items: [
            {
              objectId: `u-${name}`,
              type: "users",
              displayName: name,
              samAccountName: name.toLowerCase(),
              matchClass: "prefix",
              distinguishedName: `CN=${name},DC=corp,DC=test`,
              domain: "corp.test",
              status: [],
              highlights: [],
            },
          ],
        },
      ],
    });

  it("a burst of keystrokes inside the debounce window makes exactly one request", async () => {
    vi.useFakeTimers();
    await mount();
    await pressCtrlK();
    for (const q of ["a", "al", "alo", "alov"]) {
      await act(async () => {
        setValue(paletteInput(), q);
        vi.advanceTimersByTime(100);
      });
    }
    expect(searchCalls()).toHaveLength(0);
    await act(async () => {
      vi.advanceTimersByTime(300);
    });
    expect(searchCalls()).toHaveLength(1);
    expect(JSON.parse(searchCalls()[0]?.body ?? "{}")).toEqual({ q: "alov" });
  });

  it("ignores an earlier answer that arrives after a later one", async () => {
    vi.useFakeTimers();
    const resolvers: Record<string, (r: Response) => void> = {};
    searchHandler = (q) => new Promise<Response>((resolve) => (resolvers[q] = resolve));
    await mount();
    await pressCtrlK();
    await typeQuery("first");
    await typeQuery("second");
    expect(searchCalls()).toHaveLength(2);

    await act(async () => resolvers["second"]?.(answer("Second Person")));
    expect(document.body.textContent).toContain("Second Person");
    await act(async () => resolvers["first"]?.(answer("First Person")));
    expect(document.body.textContent).toContain("Second Person");
    expect(document.body.textContent).not.toContain("First Person");
  });

  it("ignores a late failure of an earlier request", async () => {
    vi.useFakeTimers();
    const resolvers: Record<string, (r: Response) => void> = {};
    const rejecters: Record<string, (e: unknown) => void> = {};
    searchHandler = (q) =>
      new Promise<Response>((resolve, reject) => {
        resolvers[q] = resolve;
        rejecters[q] = reject;
      });
    await mount();
    await pressCtrlK();
    await typeQuery("first");
    await typeQuery("second");
    await act(async () => resolvers["second"]?.(answer("Second Person")));
    await act(async () => rejecters["first"]?.(new TypeError("Failed to fetch")));
    expect(document.body.textContent).toContain("Second Person");
    expect(document.body.textContent).not.toContain("Can't reach the server");
  });

  const pending = () => {
    const r: {
      resolve?: (x: Response) => void;
      reject?: (e: unknown) => void;
    } = {};
    searchHandler = () =>
      new Promise<Response>((resolve, reject) => {
        r.resolve = resolve;
        r.reject = reject;
      });
    return r;
  };

  it("ignores an answer that arrives after the input was cleared", async () => {
    vi.useFakeTimers();
    const r = pending();
    await mount();
    await pressCtrlK();
    await typeQuery("first");
    expect(searchCalls()).toHaveLength(1);
    await typeQuery("");
    await act(async () => r.resolve?.(answer("First Person")));
    expect(document.body.textContent).not.toContain("First Person");
    expect(document.body.querySelector('[role="option"]')).toBeNull();
  });

  it("ignores a late failure after the input was cleared", async () => {
    vi.useFakeTimers();
    const r = pending();
    await mount();
    await pressCtrlK();
    await typeQuery("first");
    await typeQuery("");
    await act(async () => r.reject?.(new TypeError("Failed to fetch")));
    expect(document.body.textContent).not.toContain("Can't reach the server");
  });

  it("keeps the recovery-password refusal when an earlier answer arrives late", async () => {
    vi.useFakeTimers();
    const r = pending();
    await mount();
    await pressCtrlK();
    await typeQuery("first");
    await typeQuery("123456-789012-345678-901234-567890-123456-789012-345678");
    await act(async () => r.resolve?.(answer("First Person")));
    expect(document.body.textContent).toContain(RECOVERY_PASSWORD_MESSAGE);
    expect(document.body.textContent).not.toContain("First Person");
    expect(searchCalls()).toHaveLength(1);
  });

  it("ignores an answer that arrives after the palette was closed", async () => {
    vi.useFakeTimers();
    const r = pending();
    await mount();
    await pressCtrlK();
    await typeQuery("first");
    await act(async () => {
      document
        .querySelector('[role="dialog"]')
        ?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    });
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    await act(async () => r.resolve?.(answer("First Person")));
    expect(document.body.textContent).not.toContain("First Person");
  });
});

describe("T-1101 AC 4: Show all N", () => {
  beforeEach(() => {
    hasSession = true;
  });

  const tenUsers = () =>
    json(200, {
      asOf: null,
      refine: false,
      groups: [
        {
          type: "users",
          count: 10,
          items: [
            {
              objectId: "u-exact",
              type: "users",
              displayName: "Ada Lovelace",
              samAccountName: "alovelace",
              matchClass: "exact",
              distinguishedName: "CN=Ada,DC=corp,DC=test",
              domain: "corp.test",
              status: [],
              highlights: [],
            },
            {
              objectId: "u-2",
              type: "users",
              displayName: "Adam Smith",
              samAccountName: "asmith",
              matchClass: "prefix",
              distinguishedName: "CN=Adam,DC=corp,DC=test",
              domain: "corp.test",
              status: [],
              highlights: [],
            },
          ],
        },
      ],
    });

  const showAllRow = () =>
    [...document.querySelectorAll<HTMLElement>('[role="option"]')].find((o) =>
      /show all/i.test(o.textContent ?? ""),
    );

  it("the Users group's 'Show all 10' row opens /search?q=…&type=users", async () => {
    vi.useFakeTimers();
    searchHandler = tenUsers;
    await mount();
    await pressCtrlK();
    await typeQuery("ad");
    const row = showAllRow();
    expect(row?.textContent).toContain("Show all 10");
    await act(async () => row?.click());
    expect(window.location.pathname).toBe("/search");
    const params = new URLSearchParams(window.location.search);
    expect(params.get("q")).toBe("ad");
    expect(params.get("type")).toBe("users");
    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });

  it("Enter on the 'Show all' row opens it too", async () => {
    vi.useFakeTimers();
    searchHandler = tenUsers;
    await mount();
    await pressCtrlK();
    await typeQuery("ad");
    // Rows: Exact(Ada), Users(Adam), Show all 10. Walk down to the last row.
    await act(async () => {
      paletteInput().dispatchEvent(
        new KeyboardEvent("keydown", { key: "End", bubbles: true, cancelable: true }),
      );
    });
    await act(async () => {
      paletteInput().dispatchEvent(
        new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }),
      );
    });
    expect(window.location.pathname).toBe("/search");
    expect(new URLSearchParams(window.location.search).get("type")).toBe("users");
  });

  it("opens a user without a sAMAccountName by its UPN, and a name containing ' · ' correctly", async () => {
    vi.useFakeTimers();
    searchHandler = () =>
      json(200, {
        asOf: null,
        refine: false,
        groups: [
          {
            type: "users",
            count: 1,
            items: [
              {
                objectId: "u-x",
                type: "users",
                displayName: "Odd · Name",
                userPrincipalName: "odd@corp.test",
                mail: "odd.name@corp.test",
                matchClass: "prefix",
                distinguishedName: "CN=Odd,DC=corp,DC=test",
                domain: "corp.test",
                status: [],
                highlights: [],
              },
            ],
          },
        ],
      });
    await mount();
    await pressCtrlK();
    await typeQuery("odd");
    const row = document.querySelector<HTMLElement>('[role="option"]');
    await act(async () => row?.click());
    expect(window.location.pathname).toBe("/directory/users");
    expect(new URLSearchParams(window.location.search).get("q")).toBe("odd@corp.test");
  });
});
