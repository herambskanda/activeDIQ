// The /search page's logic with no React in it: what a query may be, how the API's chips and
// highlights are worded and split, where a row may link, and how a failure is explained. Every
// value shown comes from the API's DirectorySearchResult; nothing here invents a status or a count.
import { ApiError } from "../../api/client";
import type { components } from "../../api/schema.gen";
import type { ChipTone } from "../../ds/components";
import { type Failure, validateQuery } from "./search-model";

type Schemas = components["schemas"];
export type SearchHit = Schemas["DirectorySearchHit"];
export type SearchGroup = Schemas["DirectorySearchGroup"];
export type SearchResult = Schemas["DirectorySearchResult"];
export type SearchChip = Schemas["DirectorySearchChip"];
export type SearchType = Schemas["DirectorySearchType"];

export const USERS_PATH = "/directory/users";
export const SEARCH_PATH = "/search";

/** The API's longest accepted q (DirectorySearchRequest). */
export const MAX_SEARCH_LENGTH = 256;

/** Hits per page when one type is chosen, and per type when all are shown (the API's maximum). */
export const PAGE_SIZE = 50;

/** The kinds of object, in the API's group order. */
export const TYPES: readonly { readonly value: SearchType; readonly label: string }[] = [
  { value: "users", label: "Users" },
  { value: "groups", label: "Groups" },
  { value: "computers", label: "Computers" },
  { value: "contacts", label: "Contacts" },
];

/** The `type` from the address bar, or undefined (all kinds) when it is absent or not one we know. */
export function typeOf(raw: string | null): SearchType | undefined {
  return TYPES.find((t) => t.value === raw)?.value;
}

export const RECOVERY_PASSWORD_MESSAGE =
  "That looks like a recovery password. Search by the 8-character key ID instead.";

/**
 * A BitLocker recovery password is 48 digits, usually typed as eight groups of six joined by
 * dashes (IA 5.2). It is a secret, so the console refuses it before any request and never keeps it
 * in the address bar. Digits with only dashes or spaces between them count.
 */
export function looksLikeRecoveryPassword(q: string): boolean {
  if (!/^[\d\s-]+$/.test(q)) return false;
  return q.replace(/\D/g, "").length === 48;
}

/**
 * Why `q` would not be sent, or undefined when it can be. The search takes typed text: syntax
 * characters have no meaning, so only the API's own limits (length, NUL) are checked, plus the
 * recovery-password refusal. An empty q is not an error; it is no search.
 */
export function validateSearchText(q: string): string | undefined {
  if (looksLikeRecoveryPassword(q)) return RECOVERY_PASSWORD_MESSAGE;
  if (Array.from(q).length > MAX_SEARCH_LENGTH) {
    return `Search text can be at most ${MAX_SEARCH_LENGTH} characters.`;
  }
  if (q.includes("\u0000")) return "Search text can't contain a NUL character.";
  return undefined;
}

/** The address of the page for a query and optional type; the query is never added when empty. */
export function searchHref(q: string, type?: SearchType): string {
  const params = new URLSearchParams();
  if (q !== "") params.set("q", q);
  if (type !== undefined) params.set("type", type);
  const s = params.toString();
  return s === "" ? SEARCH_PATH : `${SEARCH_PATH}?${s}`;
}

// ---- Status chips ------------------------------------------------------------------------------

export interface ChipView {
  readonly tone: ChipTone;
  readonly label: string;
}

function timeOf(at: string, timeZone?: string): string | undefined {
  const d = new Date(at);
  if (Number.isNaN(d.getTime())) return undefined;
  return new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
    ...(timeZone ? { timeZone } : {}),
  }).format(d);
}

function dayOf(at: string, withTime: boolean, timeZone?: string): string | undefined {
  const d = new Date(at);
  if (Number.isNaN(d.getTime())) return undefined;
  const day = new Intl.DateTimeFormat("en-GB", {
    day: "numeric",
    month: "short",
    ...(timeZone ? { timeZone } : {}),
  }).format(d);
  return withTime ? `${day} ${timeOf(at, timeZone) ?? ""}`.trim() : day;
}

/**
 * Words one chip as the IA does (5.3): "Locked 09:12", "Disabled", "Password expired",
 * "Password expires in 3 d", "Expires 31 Mar", "Deleted 1 Oct 16:42", "TIER 0", "Cloud only".
 * The time is shown in the viewer's time zone unless `timeZone` says otherwise. A kind this console
 * does not know (the enum is open) returns undefined and is not shown.
 */
export function chipView(chip: SearchChip, timeZone?: string): ChipView | undefined {
  const when = (text: string | undefined, prefix: string) =>
    text === undefined ? prefix : `${prefix} ${text}`;
  switch (chip.kind) {
    case "locked":
      return {
        tone: "crit",
        label: when(chip.at === undefined ? undefined : timeOf(chip.at, timeZone), "Locked"),
      };
    case "disabled":
      return { tone: "muted", label: "Disabled" };
    case "passwordExpired":
      return { tone: "crit", label: "Password expired" };
    case "passwordExpiresInDays":
      return chip.days === undefined
        ? undefined
        : { tone: "warn", label: `Password expires in ${chip.days} d` };
    case "accountExpires":
      return {
        tone: "warn",
        label: when(chip.at === undefined ? undefined : dayOf(chip.at, false, timeZone), "Expires"),
      };
    case "deleted":
      return {
        tone: "muted",
        label: when(chip.at === undefined ? undefined : dayOf(chip.at, true, timeZone), "Deleted"),
      };
    case "tier0":
      return { tone: "warn", label: "TIER 0" };
    case "cloudOnly":
      return { tone: "muted", label: "Cloud only" };
    default:
      return undefined;
  }
}

// ---- Row text ----------------------------------------------------------------------------------

/** The identifiers a row shows in mono: account name, then user principal name, then mail. */
export function identifiersOf(hit: SearchHit): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of [hit.samAccountName, hit.userPrincipalName, hit.mail]) {
    if (v === undefined || v === "" || seen.has(v.toLowerCase())) continue;
    seen.add(v.toLowerCase());
    out.push(v);
  }
  return out;
}

/** Title, then office, then department: whatever the inventory holds that tells two people apart. */
export function disambiguatorOf(hit: SearchHit): string {
  const d = hit.disambiguator;
  if (d === undefined) return "";
  return [d.title, d.office, d.department].filter((v) => v !== undefined && v !== "").join(" · ");
}

export interface Segment {
  readonly text: string;
  readonly match: boolean;
}

/**
 * Splits `text` by the API's highlight ranges for `field`. Ranges count Unicode code points from
 * the start of the value, so the text is split by code point, not by UTF-16 unit. Ranges that
 * overlap or run past the end are clipped; a range with no length is ignored.
 */
export function segmentsOf(
  text: string,
  field: SearchHit["highlights"][number]["field"],
  highlights: readonly SearchHit["highlights"][number][],
): Segment[] {
  const chars = Array.from(text);
  const marked = new Array<boolean>(chars.length).fill(false);
  for (const h of highlights) {
    if (h.field !== field) continue;
    const end = Math.min(chars.length, h.start + h.length);
    for (let i = Math.max(0, h.start); i < end; i++) marked[i] = true;
  }
  const out: Segment[] = [];
  chars.forEach((c, i) => {
    const last = out[out.length - 1];
    const match = marked[i] === true;
    if (last && last.match === match) out[out.length - 1] = { text: last.text + c, match };
    else out.push({ text: c, match });
  });
  return out;
}

// ---- Where a row may link ----------------------------------------------------------------------

/**
 * Where each kind of object opens. Only a kind with a page that exists is listed: at checkpoint 2a
 * that is users, which open the user search filtered to the identifier. Groups, computers and
 * contacts show no link until a page for them is registered. A test holds every path here to a
 * route the directory module registers.
 */
export const OBJECT_DESTINATIONS: Partial<Record<SearchType, string>> = { users: USERS_PATH };

/** The link of a row, or undefined when its kind has no page or no identifier the page can search. */
export function hitHref(hit: SearchHit): string | undefined {
  const path = (OBJECT_DESTINATIONS as Readonly<Record<string, string | undefined>>)[hit.type];
  if (path === undefined) return undefined;
  // The user search refuses some characters, so a link to it must name an identifier it accepts.
  const identifier = [hit.samAccountName, hit.userPrincipalName, hit.mail].find(
    (v) => v !== undefined && v !== "" && validateQuery(v) === undefined,
  );
  if (identifier === undefined) return undefined;
  return `${path}?${new URLSearchParams({ q: identifier }).toString()}`;
}

// ---- Failures ----------------------------------------------------------------------------------

function codeOf(error: ApiError): string | undefined {
  return error.problem.errors?.find((e) => e.code !== "")?.code ?? error.problem.code;
}

/**
 * Maps a failed search to what the page says. Never repeats the search text and never shows a
 * stack trace or an unknown payload; the trace ID is carried so an admin can quote it.
 */
export function searchFailureOf(error: unknown): Failure {
  if (error instanceof ApiError) {
    const traceId = typeof error.problem.traceId === "string" ? error.problem.traceId : undefined;
    const withId = traceId === undefined ? {} : { traceId };
    switch (error.status) {
      case 400: {
        const code = codeOf(error);
        if (code === "query_refused") {
          return {
            kind: "invalid",
            title: "That search was refused",
            detail: RECOVERY_PASSWORD_MESSAGE,
            ...withId,
          };
        }
        if (code === "cursor_invalid" || code === "cursor_requires_type") {
          return {
            kind: "invalid",
            title: "That page of results is no longer available",
            detail: "Search again to start from the first page.",
            ...withId,
          };
        }
        return {
          kind: "invalid",
          title: "The server could not use that search text",
          detail: error.problem.detail ?? error.problem.title,
          ...withId,
        };
      }
      case 401:
        return {
          kind: "unauthenticated",
          title: "Your session has ended",
          detail: "Sign in again; you will come back to this search.",
          ...withId,
        };
      case 403:
        return {
          kind: "denied",
          title: "You don't have permission to search the directory",
          detail:
            "Searching directory objects needs the directory.read permission. Ask an administrator to grant it.",
          ...withId,
        };
      case 429:
        return {
          kind: "rate-limited",
          title: "Too many searches",
          detail: "Wait a moment, then retry.",
          ...withId,
        };
      case 503:
        return {
          kind: "error",
          title: "Search is unavailable right now",
          detail:
            "The search could not finish in time. Retry; if it keeps failing, quote the trace ID to your administrator.",
          ...withId,
        };
      default:
        return {
          kind: "error",
          title: "The search failed",
          detail:
            "The server could not answer. Retry; if it keeps failing, quote the trace ID to your administrator.",
          ...withId,
        };
    }
  }
  return {
    kind: "unreachable",
    title: "Can't reach the server",
    detail: "Check your connection, then retry.",
  };
}
