import type { components } from "../api/schema.gen";
import type { PaletteChip, PaletteGroup, PaletteItem } from "../ds/components";
import type { PaletteEntry, RouteSpec } from "./modules";

export type DirectorySearchHit = components["schemas"]["DirectorySearchHit"];
export type DirectorySearchResult = components["schemas"]["DirectorySearchResult"];
export type DirectorySearchChip = components["schemas"]["DirectorySearchChip"];

/** IA §5.2 message when a 48-digit BitLocker recovery password is typed. */
export const RECOVERY_PASSWORD_MESSAGE =
  "That looks like a recovery password. Search by the 8-character key ID instead.";

/** 5 minutes TTL for the last query before resetting on palette open (AC 1). */
export const QUERY_TTL_MS = 5 * 60 * 1000;

/** Debounce interval before sending directory search request (AC 2). */
export const SEARCH_DEBOUNCE_MS = 250;

/**
 * Recognises a 48-digit recovery password (BitLocker) per IA §5.2 and ADR-0011 rule 7 / T-1096 AC5.
 * Normalises with NFKC, removes whitespace and dashes (\p{Pd}), then checks for 48+ decimal digits (\p{Nd}).
 */
export function isRecoveryPassword(raw: string): boolean {
  const norm = raw.normalize("NFKC");
  const stripped = norm.replace(/[\s\p{Pd}]/gu, "");
  return /\p{Nd}{48}/u.test(stripped);
}

const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

export function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    const hh = String(d.getUTCHours()).padStart(2, "0");
    const mm = String(d.getUTCMinutes()).padStart(2, "0");
    return `${hh}:${mm}`;
  } catch {
    return "";
  }
}

export function formatDate(iso: string): string {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
  } catch {
    return "";
  }
}

export function mapStatusChip(chip: DirectorySearchChip): PaletteChip | undefined {
  switch (chip.kind) {
    case "locked":
      return { tone: "warn", label: chip.at ? `Locked ${formatTime(chip.at)}` : "Locked" };
    case "disabled":
      return { tone: "muted", label: "Disabled" };
    case "passwordExpired":
      return { tone: "crit", label: "Password expired" };
    case "passwordExpiresInDays":
      return {
        tone: "warn",
        label:
          chip.days === 1
            ? "Password expires in 1 day"
            : `Password expires in ${chip.days ?? 0} days`,
      };
    case "accountExpires":
      return { tone: "warn", label: chip.at ? `Expires ${formatDate(chip.at)}` : "Account expires" };
    case "deleted":
      return { tone: "muted", label: chip.at ? `Deleted ${formatDate(chip.at)}` : "Deleted" };
    case "tier0":
      return { tone: "crit", label: "TIER 0" };
    case "cloudOnly":
      return { tone: "muted", label: "Cloud only" };
    default:
      return undefined;
  }
}

export function mapHitToPaletteItem(hit: DirectorySearchHit): PaletteItem {
  const typeTag =
    hit.type === "users"
      ? "User"
      : hit.type === "groups"
        ? "Group"
        : hit.type === "computers"
          ? "Computer"
          : hit.type === "contacts"
            ? "Contact"
            : hit.type;

  let identifier: string | undefined;
  if (hit.type === "users") {
    const upnOrMail = hit.userPrincipalName || hit.mail;
    identifier =
      hit.samAccountName && upnOrMail
        ? `${hit.samAccountName} · ${upnOrMail}`
        : hit.samAccountName || upnOrMail;
  } else {
    identifier = hit.samAccountName || hit.mail;
  }

  let disambiguator: string | undefined;
  if (hit.disambiguator) {
    const parts = [
      hit.disambiguator.title,
      hit.disambiguator.office,
      hit.disambiguator.department,
    ].filter(Boolean);
    if (parts.length > 0) {
      disambiguator = parts.join(" · ");
    }
  }

  const chips = hit.status
    ? hit.status.map(mapStatusChip).filter((c): c is PaletteChip => c !== undefined)
    : undefined;

  const item: PaletteItem = {
    id: hit.objectId,
    typeTag,
    name: hit.displayName,
    ...(identifier ? { identifier } : {}),
    ...(disambiguator ? { disambiguator } : {}),
    ...(hit.distinguishedName ? { dn: hit.distinguishedName } : {}),
    ...(hit.domain ? { domain: hit.domain } : {}),
    ...(chips && chips.length > 0 ? { chips } : {}),
  };
  return item;
}

export function matchPages(
  registeredPalette: readonly PaletteEntry[],
  routes: readonly RouteSpec[],
  query: string,
): PaletteItem[] {
  const q = query.trim().toLowerCase();
  if (q === "") return [];

  const matched: PaletteItem[] = [];
  for (const entry of registeredPalette) {
    const routeExists = routes.some(
      (r) =>
        r.path === entry.route ||
        (r.path.endsWith("/*") && entry.route.startsWith(r.path.slice(0, -2))),
    );
    if (!routeExists) continue;

    const matchesLabel = entry.label.toLowerCase().includes(q);
    const matchesKeyword = entry.keywords.some((k) => k.toLowerCase().includes(q));
    if (matchesLabel || matchesKeyword) {
      matched.push({
        id: `page:${entry.id}`,
        typeTag: "Page",
        name: entry.label,
      });
    }
  }
  return matched;
}

export function buildPaletteGroups(
  result: DirectorySearchResult,
  registeredPalette: readonly PaletteEntry[],
  routes: readonly RouteSpec[],
  query: string,
): PaletteGroup[] {
  const groups: PaletteGroup[] = [];

  // 1. Exact matches first (across all object types)
  const exactHits: DirectorySearchHit[] = [];
  for (const g of result.groups ?? []) {
    for (const h of g.items ?? []) {
      if (h.matchClass === "exact") exactHits.push(h);
    }
  }
  if (exactHits.length > 0) {
    groups.push({
      id: "exact",
      label: "Exact",
      items: exactHits.slice(0, 5).map(mapHitToPaletteItem),
    });
  }

  // 2. Object types: Users, Groups, Computers, Contacts (up to 5 each)
  const types = ["users", "groups", "computers", "contacts"] as const;
  for (const type of types) {
    const g = result.groups?.find((grp) => grp.type === type);
    if (!g || !g.items || g.items.length === 0) continue;

    // Filter out items that already appear in the Exact group
    const items = g.items.filter((h) => h.matchClass !== "exact");
    if (items.length > 0) {
      const total = g.count ?? (g.more ? items.length + 1 : undefined);
      groups.push({
        id: type,
        label: type.charAt(0).toUpperCase() + type.slice(1),
        items: items.slice(0, 5).map(mapHitToPaletteItem),
        ...(total !== undefined ? { total } : {}),
      });
    }
  }

  // 3. Registered Pages matching query
  const pages = matchPages(registeredPalette, routes, query);
  if (pages.length > 0) {
    groups.push({
      id: "pages",
      label: "Pages",
      items: pages.slice(0, 5),
    });
  }

  // Note: per AC 3, no actions group exists at 2a.
  return groups;
}
