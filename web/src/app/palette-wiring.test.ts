import { describe, expect, it } from "vitest";

import type {
  DirectorySearchChip,
  DirectorySearchHit,
  DirectorySearchResult,
} from "./palette-wiring";
import {
  buildPaletteGroups,
  formatDate,
  formatTime,
  isRecoveryPassword,
  mapHitToPaletteItem,
  mapStatusChip,
  matchPages,
  RECOVERY_PASSWORD_MESSAGE,
} from "./palette-wiring";
import type { PaletteEntry, RouteSpec } from "./modules";

describe("palette-wiring: isRecoveryPassword", () => {
  it("refuses 48-digit recovery passwords in plain, dashed, and full-width formats", () => {
    const plain48 = "123456789012345678901234567890123456789012345678";
    expect(isRecoveryPassword(plain48)).toBe(true);

    const dashed48 = "123456-789012-345678-901234-567890-123456-789012-345678";
    expect(isRecoveryPassword(dashed48)).toBe(true);

    const spaced48 = "123456 789012 345678 901234 567890 123456 789012 345678";
    expect(isRecoveryPassword(spaced48)).toBe(true);

    // Full-width decimal digits
    const fullWidth48 =
      "１２３４５６７８９０１２３４５６７８９０１２３４５６７８９０１２３４５６７８９０１２３４５６７８";
    expect(isRecoveryPassword(fullWidth48)).toBe(true);

    expect(RECOVERY_PASSWORD_MESSAGE).toBe(
      "That looks like a recovery password. Search by the 8-character key ID instead.",
    );
  });

  it("does not refuse 47 digits or normal queries", () => {
    const plain47 = "12345678901234567890123456789012345678901234567";
    expect(isRecoveryPassword(plain47)).toBe(false);
    expect(isRecoveryPassword("alovelace")).toBe(false);
    expect(isRecoveryPassword("Ada Lovelace")).toBe(false);
    expect(isRecoveryPassword("12345678")).toBe(false);
  });
});

describe("palette-wiring: formatters and status chips", () => {
  it("formats time and date predictably in UTC", () => {
    expect(formatTime("2026-11-01T09:12:00Z")).toBe("09:12");
    expect(formatDate("2026-11-01T09:12:00Z")).toBe("1 Nov");
    expect(formatDate("2027-03-31T00:00:00Z")).toBe("31 Mar");
  });

  it("maps every status chip kind correctly", () => {
    const lockedWithTime: DirectorySearchChip = { kind: "locked", at: "2026-11-01T09:12:00Z" };
    expect(mapStatusChip(lockedWithTime)).toEqual({ tone: "warn", label: "Locked 09:12" });

    const lockedNoTime: DirectorySearchChip = { kind: "locked" };
    expect(mapStatusChip(lockedNoTime)).toEqual({ tone: "warn", label: "Locked" });

    const disabled: DirectorySearchChip = { kind: "disabled" };
    expect(mapStatusChip(disabled)).toEqual({ tone: "muted", label: "Disabled" });

    const expired: DirectorySearchChip = { kind: "passwordExpired" };
    expect(mapStatusChip(expired)).toEqual({ tone: "crit", label: "Password expired" });

    const expiresIn3d: DirectorySearchChip = { kind: "passwordExpiresInDays", days: 3 };
    expect(mapStatusChip(expiresIn3d)).toEqual({
      tone: "warn",
      label: "Password expires in 3 days",
    });

    const acctExpires: DirectorySearchChip = {
      kind: "accountExpires",
      at: "2027-03-31T00:00:00Z",
    };
    expect(mapStatusChip(acctExpires)).toEqual({ tone: "warn", label: "Expires 31 Mar" });

    const deleted: DirectorySearchChip = { kind: "deleted", at: "2026-10-01T16:42:00Z" };
    expect(mapStatusChip(deleted)).toEqual({ tone: "muted", label: "Deleted 1 Oct" });

    const tier0: DirectorySearchChip = { kind: "tier0" };
    expect(mapStatusChip(tier0)).toEqual({ tone: "crit", label: "TIER 0" });

    const cloudOnly: DirectorySearchChip = { kind: "cloudOnly" };
    expect(mapStatusChip(cloudOnly)).toEqual({ tone: "muted", label: "Cloud only" });
  });
});

describe("palette-wiring: mapHitToPaletteItem", () => {
  it("maps user hit with secondary identifier, disambiguator, and chips", () => {
    const hit: DirectorySearchHit = {
      objectId: "00000000-0000-4000-8000-000000000001",
      type: "users",
      displayName: "Priya Raman",
      samAccountName: "praman",
      userPrincipalName: "priya.raman@corp.example.test",
      distinguishedName: "CN=Priya Raman,OU=Staff,DC=corp,DC=example,DC=test",
      domain: "corp.example.test",
      matchClass: "exact",
      disambiguator: {
        title: "Service desk lead",
        office: "London",
      },
      status: [{ kind: "locked", at: "2026-11-01T09:12:00Z" }],
      highlights: [],
    };

    const item = mapHitToPaletteItem(hit);
    expect(item.id).toBe("00000000-0000-4000-8000-000000000001");
    expect(item.typeTag).toBe("User");
    expect(item.name).toBe("Priya Raman");
    expect(item.identifier).toBe("praman · priya.raman@corp.example.test");
    expect(item.disambiguator).toBe("Service desk lead · London");
    expect(item.dn).toBe("CN=Priya Raman,OU=Staff,DC=corp,DC=example,DC=test");
    expect(item.domain).toBe("corp.example.test");
    expect(item.chips).toEqual([{ tone: "warn", label: "Locked 09:12" }]);
  });
});

describe("palette-wiring: matchPages and buildPaletteGroups", () => {
  const routes: RouteSpec[] = [
    { path: "/directory/users", component: () => null },
    { path: "/reports", component: () => null },
    { path: "/reports/*", component: () => null },
  ];

  const paletteEntries: PaletteEntry[] = [
    {
      id: "directory.search-users",
      label: "Search users",
      keywords: ["find", "user", "account", "people"],
      route: "/directory/users",
    },
    {
      id: "reports.library",
      label: "Reports library",
      keywords: ["definitions", "compliance"],
      route: "/reports",
    },
    {
      id: "dead.page",
      label: "Nonexistent screen",
      keywords: ["ghost"],
      route: "/nonexistent-route",
    },
  ];

  it("lists only registered entries whose route exists and matches query", () => {
    // Match by label
    const byLabel = matchPages(paletteEntries, routes, "reports");
    expect(byLabel).toHaveLength(1);
    expect(byLabel[0]?.name).toBe("Reports library");

    // Match by keyword
    const byKeyword = matchPages(paletteEntries, routes, "people");
    expect(byKeyword).toHaveLength(1);
    expect(byKeyword[0]?.name).toBe("Search users");

    // Ghost route is ignored even if keyword matches
    const ghost = matchPages(paletteEntries, routes, "ghost");
    expect(ghost).toHaveLength(0);
  });

  it("builds groups in order: Exact first, then Users, Groups, Computers, Contacts, Pages", () => {
    const mockResult: DirectorySearchResult = {
      asOf: "2026-11-01T15:00:00Z",
      refine: false,
      groups: [
        {
          type: "users",
          count: 6,
          items: [
            {
              objectId: "u-exact",
              type: "users",
              displayName: "Exact User",
              samAccountName: "euser",
              distinguishedName: "CN=Exact User,DC=corp,DC=test",
              domain: "corp.test",
              matchClass: "exact",
              status: [],
              highlights: [],
            },
            {
              objectId: "u-prefix",
              type: "users",
              displayName: "Prefix User",
              samAccountName: "puser",
              distinguishedName: "CN=Prefix User,DC=corp,DC=test",
              domain: "corp.test",
              matchClass: "prefix",
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
              displayName: "Engineers",
              samAccountName: "GG-Engineers",
              distinguishedName: "CN=Engineers,DC=corp,DC=test",
              domain: "corp.test",
              matchClass: "prefix",
              status: [],
              highlights: [],
            },
          ],
        },
      ],
    };

    const groups = buildPaletteGroups(mockResult, paletteEntries, routes, "user");
    expect(groups.map((g) => g.id)).toEqual(["exact", "users", "groups", "pages"]);
    expect(groups[0]?.label).toBe("Exact");
    expect(groups[0]?.items[0]?.name).toBe("Exact User");
    expect(groups[1]?.label).toBe("Users");
    expect(groups[1]?.items[0]?.name).toBe("Prefix User");
    expect(groups[2]?.label).toBe("Groups");
    expect(groups[3]?.label).toBe("Pages");
    // Verify no actions group exists
    expect(groups.some((g) => g.id === "actions")).toBe(false);
  });
});
