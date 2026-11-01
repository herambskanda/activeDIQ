import { describe, expect, it } from "vitest";

import { ApiError } from "../../api/client";
import { collectContributions } from "../../app/modules";
import { directoryModule } from ".";
import {
  chipView,
  disambiguatorOf,
  hitHref,
  identifiersOf,
  looksLikeRecoveryPassword,
  OBJECT_DESTINATIONS,
  RECOVERY_PASSWORD_MESSAGE,
  searchFailureOf,
  searchHref,
  segmentsOf,
  type SearchHit,
  typeOf,
  validateSearchText,
} from "./search-results-model";

// Fixtures live in tests only (CLAUDE.md rule 6).
const hit = (over: Partial<SearchHit> = {}, without: (keyof SearchHit)[] = []): SearchHit => {
  const base = full(over);
  return Object.fromEntries(
    Object.entries(base).filter(([k]) => !without.includes(k as keyof SearchHit)),
  ) as unknown as SearchHit;
};
const full = (over: Partial<SearchHit>): SearchHit => ({
  type: "users",
  objectId: "00000000-0000-4000-8000-000000000001",
  displayName: "Priya Raman",
  distinguishedName: "CN=Priya Raman,OU=Sales,DC=corp,DC=example,DC=test",
  domain: "corp.example.test",
  matchClass: "exact",
  highlights: [],
  status: [],
  samAccountName: "praman",
  userPrincipalName: "praman@corp.example.test",
  ...over,
});

describe("recovery passwords and search text", () => {
  const dashed = "123456-123456-123456-123456-123456-123456-123456-123456";
  it("refuses 48 digits however they are separated", () => {
    expect(looksLikeRecoveryPassword(dashed)).toBe(true);
    expect(looksLikeRecoveryPassword(dashed.replaceAll("-", ""))).toBe(true);
    expect(looksLikeRecoveryPassword(dashed.replaceAll("-", " "))).toBe(true);
    expect(validateSearchText(dashed)).toBe(RECOVERY_PASSWORD_MESSAGE);
  });
  it("refuses it in the forms ADR-0011 names: full-width and other scripts' digits", () => {
    const groups = dashed.split("-");
    const shift = (t: string, base: number) =>
      t.replace(/\d/g, (d) => String.fromCharCode(base + Number(d)));
    expect(looksLikeRecoveryPassword(shift(dashed, 0xff10))).toBe(true);
    expect(looksLikeRecoveryPassword(shift(dashed, 0x660))).toBe(true);
    expect(looksLikeRecoveryPassword(shift(groups.join(""), 0xff10))).toBe(true);
    expect(looksLikeRecoveryPassword(groups.join("\u2013"))).toBe(true); // en dash
    expect(looksLikeRecoveryPassword(groups.join("\u3000"))).toBe(true); // ideographic space
    expect(validateSearchText(shift(dashed, 0xff10))).toBe(RECOVERY_PASSWORD_MESSAGE);
  });
  it("refuses it with dots, underscores or other separators, or beside other text", () => {
    const groups = dashed.split("-");
    for (const sep of [".", "_", ",", ":", ";", "/"]) {
      expect(looksLikeRecoveryPassword(groups.join(sep))).toBe(true);
    }
    expect(looksLikeRecoveryPassword(`key ${dashed}`)).toBe(true);
    expect(looksLikeRecoveryPassword(`${dashed} extra`)).toBe(true);
    expect(looksLikeRecoveryPassword("1".repeat(49))).toBe(true);
  });
  it("does not refuse other digit strings or text", () => {
    expect(looksLikeRecoveryPassword("12345678")).toBe(false);
    expect(looksLikeRecoveryPassword("1".repeat(47))).toBe(false);
    expect(looksLikeRecoveryPassword("1".repeat(47) + "x" + "1".repeat(47))).toBe(false);
    expect(validateSearchText("Raman, Priya")).toBeUndefined();
  });
  it("accepts syntax characters, which are typed text to this search", () => {
    for (const q of ["CN=Priya,DC=x", "CORP\\praman", "a*b", "(x)", "<b>", "pri~"]) {
      expect(validateSearchText(q)).toBeUndefined();
    }
  });
  it("applies the API's length and NUL limits by code point", () => {
    expect(validateSearchText("😀".repeat(256))).toBeUndefined();
    expect(validateSearchText("😀".repeat(257))).toMatch(/at most 256/);
    expect(validateSearchText("a\u0000b")).toMatch(/NUL/);
  });
});

describe("addresses", () => {
  it("puts the text and the type in the address and omits empty ones", () => {
    expect(searchHref("")).toBe("/search");
    expect(searchHref("ada lovelace", "users")).toBe("/search?q=ada+lovelace&type=users");
    expect(searchHref("", "groups")).toBe("/search?type=groups");
  });
  it("reads only a known type", () => {
    expect(typeOf("computers")).toBe("computers");
    expect(typeOf("user")).toBeUndefined();
    expect(typeOf(null)).toBeUndefined();
  });
});

describe("chipView", () => {
  const utc = "UTC";
  it("words every chip as the IA does", () => {
    const at = "2026-10-01T16:42:00Z";
    expect(chipView({ kind: "locked", at: "2026-11-01T09:12:00Z" }, utc)).toEqual({
      tone: "crit",
      label: "Locked 09:12",
    });
    expect(chipView({ kind: "disabled" })).toEqual({ tone: "muted", label: "Disabled" });
    expect(chipView({ kind: "passwordExpired" })?.label).toBe("Password expired");
    expect(chipView({ kind: "passwordExpiresInDays", days: 3 })?.label).toBe(
      "Password expires in 3 d",
    );
    expect(chipView({ kind: "accountExpires", at: "2027-03-31T00:00:00Z" }, utc)?.label).toBe(
      "Expires 31 Mar",
    );
    expect(chipView({ kind: "deleted", at }, utc)?.label).toBe("Deleted 1 Oct 16:42");
    expect(chipView({ kind: "tier0" })?.label).toBe("TIER 0");
    expect(chipView({ kind: "cloudOnly" })?.label).toBe("Cloud only");
  });
  it("says no time it was not given", () => {
    expect(chipView({ kind: "locked" })?.label).toBe("Locked");
    expect(chipView({ kind: "deleted" })?.label).toBe("Deleted");
    expect(chipView({ kind: "accountExpires" })?.label).toBe("Expires");
    expect(chipView({ kind: "passwordExpiresInDays" })).toBeUndefined();
  });
  it("shows nothing for a kind it does not know", () => {
    expect(chipView({ kind: "somethingNew" })).toBeUndefined();
  });
});

describe("row text", () => {
  it("lists distinct identifiers and skips empty ones", () => {
    expect(identifiersOf(hit({ mail: "PRAMAN@corp.example.test" }))).toEqual([
      "praman",
      "praman@corp.example.test",
    ]);
    expect(identifiersOf(hit({}, ["samAccountName", "userPrincipalName"]))).toEqual([]);
  });
  it("joins what the inventory holds that tells people apart", () => {
    expect(disambiguatorOf(hit())).toBe("");
    expect(disambiguatorOf(hit({ disambiguator: { title: "Analyst", office: "London" } }))).toBe(
      "Analyst · London",
    );
    expect(disambiguatorOf(hit({ disambiguator: { department: "Finance" } }))).toBe("Finance");
  });
  it("splits by code point, so an emoji before the match does not shift it", () => {
    const segs = segmentsOf("😀 Priya", "displayName", [
      { field: "displayName", start: 2, length: 3 },
      { field: "mail", start: 0, length: 1 },
    ]);
    expect(segs).toEqual([
      { text: "😀 ", match: false },
      { text: "Pri", match: true },
      { text: "ya", match: false },
    ]);
  });
  it("clips overlapping and out-of-range highlights and treats no range as plain text", () => {
    expect(
      segmentsOf("abcdef", "mail", [
        { field: "mail", start: 1, length: 3 },
        { field: "mail", start: 2, length: 99 },
        { field: "mail", start: 3, length: 0 },
      ]),
    ).toEqual([
      { text: "a", match: false },
      { text: "bcdef", match: true },
    ]);
    expect(segmentsOf("abc", "mail", [])).toEqual([{ text: "abc", match: false }]);
    expect(segmentsOf("", "mail", [])).toEqual([]);
  });
  it("keeps markup characters as text", () => {
    expect(segmentsOf("<b>x</b>", "mail", [])).toEqual([{ text: "<b>x</b>", match: false }]);
  });
});

describe("where a row links", () => {
  it("sends a user to the user search filtered to the account name", () => {
    expect(hitHref(hit())).toBe("/directory/users?q=praman");
  });
  it("falls back to the next identifier when one is not searchable there", () => {
    expect(hitHref(hit({ samAccountName: "pra(man" }))).toBe(
      "/directory/users?q=praman%40corp.example.test",
    );
    expect(hitHref(hit({ mail: "p@x.test" }, ["samAccountName", "userPrincipalName"]))).toBe(
      "/directory/users?q=p%40x.test",
    );
  });
  it("has no link for a user without a usable identifier", () => {
    expect(hitHref(hit({}, ["samAccountName", "userPrincipalName"]))).toBeUndefined();
  });
  it("has no link for groups, computers, contacts or a type it does not know", () => {
    for (const type of ["groups", "computers", "contacts", "something"]) {
      expect(hitHref(hit({ type }))).toBeUndefined();
    }
  });
  it("links only to routes the directory module registers", () => {
    const routes = collectContributions([directoryModule]).routes.map((r) => r.path);
    for (const path of Object.values(OBJECT_DESTINATIONS)) expect(routes).toContain(path);
  });
});

describe("searchFailureOf", () => {
  const problem = (status: number, extra: Record<string, unknown> = {}) =>
    new ApiError({ type: "about:blank", title: "t", status, ...extra }, status);

  it("explains each status and carries the trace ID", () => {
    const cases: [number, string, string][] = [
      [401, "unauthenticated", "Your session has ended"],
      [403, "denied", "You don't have permission to search the directory"],
      [429, "rate-limited", "Too many searches"],
      [500, "error", "The search failed"],
      [503, "error", "Search is unavailable right now"],
    ];
    for (const [status, kind, title] of cases) {
      expect(searchFailureOf(problem(status, { traceId: "tr-1" }))).toMatchObject({
        kind,
        title,
        traceId: "tr-1",
      });
    }
  });
  it("words 400 by its error code and never repeats the server's text for a refusal", () => {
    const refused = searchFailureOf(
      problem(400, { errors: [{ code: "query_refused", detail: "x", in: "body", pointer: "/q" }] }),
    );
    expect(refused.detail).toBe(RECOVERY_PASSWORD_MESSAGE);
    expect(
      searchFailureOf(
        problem(400, {
          errors: [{ code: "cursor_invalid", detail: "", in: "body", pointer: "/cursor" }],
        }),
      ).title,
    ).toMatch(/no longer available/);
    expect(searchFailureOf(problem(400, { detail: "The search text is empty." })).detail).toBe(
      "The search text is empty.",
    );
  });
  it("calls anything that is not an ApiError unreachable", () => {
    expect(searchFailureOf(new TypeError("fetch failed")).kind).toBe("unreachable");
  });
});
