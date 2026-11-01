// SAMPLE DATA. Invented for the T-0867 design prototype of the 2a report flows. Nothing here is a
// real person, domain, count or product number. Fixtures are allowed only in Storybook and tests
// (OPERATING-MODEL quality rules); nothing in src/app or src/modules may import this file.
//
// The 16 report definitions, their presets and ME names are copied from
// knowledge/product/specs/reports-2a.md §6.2. Row values and counts are generated.

export type Kind = "user" | "group" | "computer" | "ou" | "contact" | "member";

export interface PresetDef {
  readonly id: string;
  /** Our preset name. Per spec §6.1 rule 2 each ME name is a preset, so this is the ME name. */
  readonly name: string;
  /** Sample count of matching rows at the preset's default period. */
  readonly base: number;
  /** Default period in days, or null when the preset has no period. */
  readonly period: number | null;
  /** Shown as a caveat banner (spec §6.4). */
  readonly caveat?: string;
}

export interface ReportDef {
  readonly id: string;
  readonly name: string;
  readonly category: Category;
  readonly dataset: string;
  readonly desc: string;
  readonly kind: Kind;
  readonly columns: readonly string[];
  readonly presets: readonly PresetDef[];
  /** Replicated logon reports: no period under 30 days (spec §6.4). */
  readonly minPeriod?: number;
  readonly requires?: "group" | "user";
  readonly perDc?: boolean;
  /** E2: probable service accounts hidden by default. */
  readonly svcHidden?: boolean;
}

export const CATEGORIES = [
  "Users",
  "Passwords",
  "Groups",
  "Computers",
  "Contacts",
  "Organizational units",
] as const;
export type Category = (typeof CATEGORIES)[number];

const p = (
  id: string,
  name: string,
  base: number,
  period: number | null = null,
  caveat?: string,
) => (caveat === undefined ? { id, name, base, period } : { id, name, base, period, caveat });

export const REPORTS: readonly ReportDef[] = [
  {
    id: "USR-01",
    name: "Users",
    category: "Users",
    dataset: "inventory.users",
    desc: "Every live user with status, OU and manager.",
    kind: "user",
    columns: ["Name", "Logon name", "UPN", "Status", "Domain", "OU path", "Manager", "Created"],
    presets: [
      p("all", "All Users", 12431),
      p("enabled", "Enabled Users", 11208),
      p("disabled", "Disabled Users", 1223),
      p("nomgr", "Users Without Managers", 342),
      p("recent", "Recently Created Users", 96, 30),
    ],
  },
  {
    id: "USR-02",
    name: "Account expiry",
    category: "Users",
    dataset: "inventory.users",
    desc: "Accounts that have expired, will expire soon, or never expire.",
    kind: "user",
    columns: [
      "Name",
      "Logon name",
      "Domain",
      "OU path",
      "Account expires",
      "Days to / since expiry",
      "Status",
    ],
    presets: [
      p("expired", "Account Expired Users", 58),
      p("recently", "Recently Account Expired Users", 9, 30),
      p("soon", "Soon-to-expire User Accounts", 21, 14),
      p("never", "Account Never Expires Users", 11902),
    ],
  },
  {
    id: "USR-03",
    name: "Logon activity",
    category: "Users",
    dataset: "inventory.users",
    desc: "Inactive, recently active and never-logged-on users from the replicated logon time.",
    kind: "user",
    columns: [
      "Name",
      "Logon name",
      "Domain",
      "OU path",
      "Last logon (replicated)",
      "Days since",
      "Created",
      "Status",
      "Probable service account",
    ],
    minPeriod: 30,
    svcHidden: true,
    presets: [
      p("inactive", "Inactive Users", 1204, 90),
      p("recent", "Recently Logged on Users", 9876, 30),
      p(
        "never",
        "Users Never Logged On",
        214,
        null,
        "No qualifying logon was recorded. That is not proof the account never logged on, because the replicated logon time lags by up to 14 days. “Real last logon” gives the exact answer.",
      ),
    ],
  },
  {
    id: "USR-04",
    name: "Real last logon",
    category: "Users",
    dataset: "inventory.users + per-DC read",
    desc: "Reads every domain controller and shows the latest logon and how many DCs answered.",
    kind: "user",
    columns: [
      "Name",
      "Logon name",
      "Domain",
      "OU path",
      "Real last logon",
      "From DC",
      "DC coverage",
      "Days since",
      "Status",
    ],
    perDc: true,
    presets: [p("real", "Real Last Logon", 842, 90)],
  },
  {
    id: "USR-05",
    name: "Locked-out users",
    category: "Users",
    dataset: "inventory.users",
    desc: "Accounts locked out now, computed from the lockout policy that applies to each.",
    kind: "user",
    columns: [
      "Name",
      "Logon name",
      "Domain",
      "OU path",
      "Locked out since",
      "Lockout ends",
      "Policy source",
      "Data as of",
    ],
    presets: [p("locked", "Locked-out Users", 37)],
  },
  {
    id: "PWD-01",
    name: "Password status",
    category: "Passwords",
    dataset: "inventory.users",
    desc: "Expired, soon-to-expire, never-expiring and must-change passwords.",
    kind: "user",
    columns: [
      "Name",
      "Logon name",
      "Domain",
      "OU path",
      "Password last set",
      "Password expires",
      "Password state",
      "Policy source",
      "Status",
      "Probable service account",
    ],
    svcHidden: true,
    presets: [
      p("expired", "Password Expired Users", 163),
      p("soon", "Soon-to-expire User Passwords", 318, 14),
      p("never", "Users with Password Never Expires", 1486),
      p("must", "Users with Change Password at Next Logon", 44),
    ],
  },
  {
    id: "PWD-02",
    name: "Password age",
    category: "Passwords",
    dataset: "inventory.users",
    desc: "Who changed their password recently, and who has not.",
    kind: "user",
    columns: [
      "Name",
      "Logon name",
      "Domain",
      "OU path",
      "Password last set",
      "Days since",
      "Status",
    ],
    presets: [
      p("changed", "Password Changed Users", 2310, 30),
      p("unchanged", "Password Unchanged Users", 3902, 90),
    ],
  },
  {
    id: "PWD-03",
    name: "Recent logon failures",
    category: "Passwords",
    dataset: "inventory.users + per-DC read",
    desc: "Failed sign-ins in the last 7 days, counted per domain controller.",
    kind: "user",
    columns: [
      "Name",
      "Logon name",
      "Domain",
      "OU path",
      "Last failed logon",
      "From DC",
      "Failures on that DC",
      "DC coverage",
    ],
    perDc: true,
    presets: [p("fail", "Recent Logon Failures", 188, 7)],
  },
  {
    id: "GRP-01",
    name: "Groups",
    category: "Groups",
    dataset: "inventory.groups",
    desc: "All groups with type, scope, member counts and owner.",
    kind: "group",
    columns: [
      "Name",
      "Domain",
      "OU path",
      "Type",
      "Scope",
      "Direct members",
      "Effective members",
      "Managed by",
      "Created",
    ],
    presets: [
      p("all", "All Groups", 4180),
      p("sec", "Security Groups", 3510),
      p("dist", "Distribution Groups", 670),
      p("empty", "Groups Without Members", 212),
      p("managed", "Managed Groups", 905),
      p("unmanaged", "Unmanaged Groups", 3275),
      p("top", "Top N Big Groups", 25),
      p("recent", "Recently Created Groups", 31, 30),
    ],
  },
  {
    id: "GRP-02",
    name: "Group members",
    category: "Groups",
    dataset: "inventory.group_members",
    desc: "Direct or nested (effective) members of one or more groups, with the path each came through.",
    kind: "member",
    requires: "group",
    columns: [
      "Group",
      "Member",
      "Member type",
      "Domain",
      "OU path",
      "Status",
      "Membership kind",
      "Via",
    ],
    presets: [
      p("detailed", "Detailed Group Members", 14),
      p("direct", "Group Members", 4),
      p("users", "Users in Groups", 11),
    ],
  },
  {
    id: "GRP-03",
    name: "Groups for users",
    category: "Groups",
    dataset: "inventory.group_members",
    desc: "Every group one or more users belong to, including nested and primary group.",
    kind: "member",
    requires: "user",
    columns: ["User", "Group", "Group type", "Group scope", "Membership kind", "Via"],
    presets: [p("gfu", "Groups for Users", 23)],
  },
  {
    id: "GRP-04",
    name: "Not in any group",
    category: "Groups",
    dataset: "inventory.users, inventory.computers",
    desc: "Users or computers that are in no group, after counting the primary group.",
    kind: "user",
    columns: [
      "Name",
      "Domain",
      "OU path",
      "Primary group",
      "Status",
      "Created",
      "Last logon (replicated)",
    ],
    presets: [p("users", "Users Not in Groups", 87), p("computers", "Computers Not in Groups", 29)],
  },
  {
    id: "CMP-01",
    name: "Computers",
    category: "Computers",
    dataset: "inventory.computers",
    desc: "Computers by status, type, operating system and delegation.",
    kind: "computer",
    columns: [
      "Name",
      "DNS name",
      "Domain",
      "OU path",
      "Type",
      "Operating system",
      "OS version",
      "Status",
      "Delegation",
      "Created",
    ],
    presets: [
      p("all", "All computers", 9120),
      p("enabled", "Enabled Computers", 8760),
      p("disabled", "Disabled Computers", 360),
      p("ws", "Workstation Computers", 7410),
      p("dc", "Domain Controllers", 11),
      p("deleg", "Computers Trusted for Delegation", 14),
      p("os", "OS based computers", 9120),
      p("recent", "Recently Created Computers", 77, 30),
    ],
  },
  {
    id: "CMP-02",
    name: "Computer activity",
    category: "Computers",
    dataset: "inventory.computers",
    desc: "Inactive and active computers from replicated logon and machine-password age.",
    kind: "computer",
    columns: [
      "Name",
      "DNS name",
      "Domain",
      "OU path",
      "Operating system",
      "Last activity",
      "Activity source",
      "Days since",
      "Status",
      "Created",
    ],
    minPeriod: 30,
    presets: [
      p("inactive", "Inactive computers", 612, 90),
      p("active", "Active Computers", 8104, 30),
    ],
  },
  {
    id: "OU-01",
    name: "Organizational units",
    category: "Organizational units",
    dataset: "inventory.ous",
    desc: "OUs by content: empty, users only, computers only.",
    kind: "ou",
    columns: [
      "Name",
      "Domain",
      "Path",
      "Users",
      "Computers",
      "Groups",
      "Other objects",
      "Objects in subtree",
      "Created",
    ],
    presets: [
      p("all", "All OUs", 640),
      p("empty", "Empty OUs", 52),
      p("users", "Users-Only OUs", 118),
      p("computers", "Computers-Only OUs", 74),
      p("recent", "Recently Created OUs", 6, 30),
    ],
  },
  {
    id: "CTC-01",
    name: "Contacts",
    category: "Contacts",
    dataset: "inventory.contacts",
    desc: "Contacts, mail-enabled and recent.",
    kind: "contact",
    columns: ["Name", "E-mail", "Domain", "OU path", "Created"],
    presets: [
      p("all", "All Contacts", 1530),
      p("mail", "Mail Enabled Contacts", 1498),
      p("recent", "Recently Created Contacts", 12, 30),
    ],
  },
];

/** Registered dataset columns an admin can add beyond the defaults (ADM-099). Sample list. */
export function extraColumns(report: ReportDef): string[] {
  if (report.kind === "member") return [];
  return ["E-mail", "Department", "Description"].filter((c) => !report.columns.includes(c));
}

export const domainNames = ["corp.example", "emea.corp.example", "labs.example"] as const;
export type DomainName = (typeof domainNames)[number];
/** Sample users per domain; they add to 12,431, the figure the empty state quotes. */
export const DOMAIN_COUNT: Record<DomainName, number> = {
  "corp.example": 7812,
  "emea.corp.example": 3512,
  "labs.example": 1107,
};
export const TOTAL_CHECKED = 12431;

export const AS_OF = "09:41";
export const RUN_TIME = "09:43";
export const ZONE = "GMT";
export const TODAY = "Fri 30 Oct 2026";

/** Sample groups the GRP-02 picker and the search hits know. */
export interface GroupDef {
  readonly name: string;
  readonly direct: number;
  readonly effective: number;
  readonly cycles: number;
}
export const GROUPS: readonly GroupDef[] = [
  { name: "Domain Admins", direct: 4, effective: 14, cycles: 1 },
  { name: "Finance-Approvers", direct: 61, effective: 203, cycles: 0 },
  {
    name: "SG-Finance-Operations-EMEA-Regional-Approvers-and-Delegates",
    direct: 3000,
    effective: 3000,
    cycles: 0,
  },
];

export interface SampleAccount {
  readonly name: string;
  readonly mail: string;
}
export const ACCOUNTS: readonly SampleAccount[] = [
  { name: "Tomás Villanueva", mail: "tomas.villanueva@example.test" },
  { name: "Compliance mailbox", mail: "compliance@example.test" },
  { name: "Ananya Iyer", mail: "ananya.iyer@example.test" },
];
/** E-mail domains the tenant allows (spec §8.4). Empty at install; this sample tenant added one. */
export const ALLOWED_DOMAINS = ["example.test"] as const;

// ---- deterministic generator ----------------------------------------------------------------

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}
function rng(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const FIRST = [
  "Alma",
  "Bruno",
  "Chiara",
  "Dmitri",
  "Esther",
  "Farid",
  "Greta",
  "Hugo",
  "Ines",
  "Jonas",
  "Katarzyna",
  "Lars",
  "Mei",
  "Noor",
  "Olumide",
  "Priya",
  "Quentin",
  "Rosa",
  "Søren",
  "Thandiwe",
  "李",
  "Мария",
  "Ørjan",
  "Zoë",
];
const LAST = [
  "Abbott",
  "Barros",
  "Castillo",
  "Dvořák",
  "Eriksen",
  "Fontaine",
  "Grünewald",
  "Hoang",
  "Ito",
  "Jovanović",
  "Kowalczyk",
  "Lindqvist",
  "Mbeki",
  "Nakamura",
  "O’Brien",
  "Petrov",
  "Raman",
  "Okafor",
  "伟",
  "Иванова",
];
const SITES = ["London", "Rotterdam", "Mumbai", "Shanghai", "Lagos", "Oslo"];
const DEPTS = ["Finance", "Research", "Sales", "Engineering", "Operations", "Legal"];
const OSES = [
  ["Windows 11 Enterprise", "10.0 (22631)"],
  ["Windows 10 Enterprise", "10.0 (19045)"],
  ["Windows Server 2022 Standard", "10.0 (20348)"],
  ["Windows Server 2019 Datacenter", "10.0 (17763)"],
] as const;
const GROUP_WORDS = [
  "Finance",
  "VPN",
  "Printers",
  "Research",
  "Approvers",
  "ReadOnly",
  "Backup",
  "Helpdesk",
  "Payroll",
  "Audit",
];

export type Cell = string | number;
export interface Row {
  readonly key: string;
  readonly cells: Readonly<Record<string, Cell>>;
  /** Set on probable service accounts: the reason shown when they are included (E2). */
  readonly svc?: string;
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-");
export const colKey = slug;

function fmtDate(daysAgo: number): string {
  const d = new Date(Date.UTC(2026, 9, 30) - daysAgo * 86400000);
  return d.toISOString().slice(0, 10);
}
function fmtFuture(days: number): string {
  return fmtDate(-days);
}

interface Identity {
  readonly name: string;
  readonly sam: string;
  readonly domain: DomainName;
  readonly ou: string;
}

function identity(r: () => number, i: number): Identity {
  const f = FIRST[Math.floor(r() * FIRST.length)] ?? "Alma";
  const l = LAST[Math.floor(r() * LAST.length)] ?? "Abbott";
  const long = i % 97 === 11;
  const name = long ? `${f} ${l}-Hendriksen-van der Berg (Research, Rotterdam site)` : `${f} ${l}`;
  const ascii = `${f}.${l}`.toLowerCase().replace(/[^a-z.]/g, "") || `user${i}`;
  const sam = `${ascii.slice(0, 14)}${i % 9 === 0 ? String(i % 90) : ""}`;
  const dr = r();
  const domain: DomainName =
    dr < 0.628 ? "corp.example" : dr < 0.911 ? "emea.corp.example" : "labs.example";
  const site = SITES[Math.floor(r() * SITES.length)] ?? "London";
  const dept = DEPTS[Math.floor(r() * DEPTS.length)] ?? "Finance";
  const deep = i % 131 === 5;
  const ou = deep
    ? `Staff / ${site} / ${dept} / Quarterly-Reporting / Temporary-Contractors / Offboarding-Pending-Review`
    : `Staff / ${site} / ${dept}`;
  return { name, sam, domain, ou };
}

function statusFor(r: () => number): string {
  return r() < 0.9 ? "Enabled" : "Disabled";
}

const DCS = ["dc-lon-01", "dc-lon-02", "dc-ams-01", "dc-ams-03", "dc-bom-01", "dc-sha-01"];

/** The hand-built membership of Domain Admins: direct and nested, with a cycle and an external principal. */
export const DOMAIN_ADMINS_ROWS: readonly Row[] = (() => {
  const g = "Domain Admins";
  const m = (
    member: string,
    type: string,
    domain: string,
    ou: string,
    status: string,
    kind: string,
    via: string,
  ): Row => ({
    key: `${member}|${via}`,
    cells: {
      group: g,
      member,
      "member-type": type,
      domain,
      "ou-path": ou,
      status,
      "membership-kind": kind,
      via,
    },
  });
  return [
    m("Administrator", "User", "corp.example", "Users", "Enabled", "Direct", "—"),
    m("adm.khalid.alharbi", "User", "corp.example", "Admin / Tier 0", "Enabled", "Direct", "—"),
    m(
      "adm.s.okonkwo-richardson",
      "User",
      "corp.example",
      "Admin / Tier 0",
      "Enabled",
      "Direct",
      "—",
    ),
    m("Tier0-Operators", "Group", "corp.example", "Admin / Groups", "—", "Direct", "—"),
    m(
      "adm.priya.raman",
      "User",
      "corp.example",
      "Admin / Tier 0",
      "Enabled",
      "Effective",
      "Tier0-Operators",
    ),
    m(
      "svc-backup-legacy",
      "User",
      "corp.example",
      "Service accounts",
      "Disabled",
      "Effective",
      "Tier0-Operators",
    ),
    m(
      "Server-Admins-EMEA",
      "Group",
      "emea.corp.example",
      "Admin / Groups",
      "—",
      "Effective",
      "Tier0-Operators",
    ),
    m(
      "adm.李伟 (Li Wei)",
      "User",
      "emea.corp.example",
      "Admin / Tier 0",
      "Enabled",
      "Effective",
      "Tier0-Operators › Server-Admins-EMEA",
    ),
    m(
      "adm.m.dubois-lefèvre-de-la-tour-d’auvergne-senior",
      "User",
      "emea.corp.example",
      "Admin / Tier 0",
      "Enabled",
      "Effective",
      "Tier0-Operators › Server-Admins-EMEA",
    ),
    m(
      "S-1-5-21-0000000000-1104 (sample SID)",
      "External principal (unresolved)",
      "partner.example",
      "—",
      "Unknown",
      "Effective",
      "Tier0-Operators › Server-Admins-EMEA",
    ),
    m(
      "Backup-Operators-Tier0",
      "Group",
      "corp.example",
      "Admin / Groups",
      "—",
      "Effective",
      "Tier0-Operators",
    ),
    m(
      "adm.dmitri.petrov",
      "User",
      "corp.example",
      "Admin / Tier 0",
      "Enabled",
      "Effective",
      "Tier0-Operators › Backup-Operators-Tier0",
    ),
    m(
      "adm.zoë.mbeki",
      "User",
      "corp.example",
      "Admin / Tier 0",
      "Enabled",
      "Effective",
      "Tier0-Operators › Backup-Operators-Tier0",
    ),
    m(
      "adm.lars.eriksen",
      "User",
      "emea.corp.example",
      "Admin / Tier 0",
      "Disabled",
      "Effective",
      "Tier0-Operators › Backup-Operators-Tier0",
    ),
  ];
})();

export const CYCLE_FINDING = "Domain Admins › Tier0-Operators › Server-Admins-EMEA › Domain Admins";

function memberRows(group: string, n: number): Row[] {
  const r = rng(hash(group));
  const out: Row[] = [];
  for (let i = 0; i < n; i += 1) {
    const id = identity(r, i);
    const kind = i % 5 === 0 ? "Direct" : "Effective";
    out.push({
      key: `${group}|${i}`,
      cells: {
        group,
        member: id.name,
        "member-type": "User",
        domain: id.domain,
        "ou-path": id.ou,
        status: statusFor(r),
        "membership-kind": kind,
        via:
          kind === "Direct" ? "—" : `Finance-Team-${(i % 7) + 1} › Finance-Regional-${(i % 3) + 1}`,
      },
    });
  }
  return out;
}

export interface RunInput {
  readonly report: ReportDef;
  readonly presetId: string;
  readonly days: number | null;
  readonly group?: string | undefined;
}

/** Row count and rows for one run. Sample data: the counts are invented, the structure follows §6.2. */
export function buildRows(input: RunInput): { rows: Row[]; svcHidden: number } {
  const { report, presetId, days } = input;
  const preset = report.presets.find((x) => x.id === presetId) ?? report.presets[0];
  if (!preset) return { rows: [], svcHidden: 0 };
  if (report.id === "GRP-02") {
    const g = input.group ?? "Domain Admins";
    if (g === "Domain Admins") {
      const rows =
        preset.id === "direct"
          ? DOMAIN_ADMINS_ROWS.filter((x) => x.cells["membership-kind"] === "Direct")
          : preset.id === "users"
            ? DOMAIN_ADMINS_ROWS.filter((x) => x.cells["member-type"] === "User")
            : [...DOMAIN_ADMINS_ROWS];
      return { rows, svcHidden: 0 };
    }
    const def = GROUPS.find((x) => x.name === g);
    return { rows: memberRows(g, def?.effective ?? 200), svcHidden: 0 };
  }
  const scale = days === null || preset.period === null ? 1 : preset.period / days;
  const total = Math.max(
    3,
    Math.round(preset.base * (report.minPeriod !== undefined ? Math.pow(scale, 0.9) : 1)),
  );
  const r = rng(hash(`${report.id}|${preset.id}|${days ?? 0}`));
  const svcN = report.svcHidden ? Math.max(1, Math.round(total * 0.03)) : 0;
  const rows: Row[] = [];
  for (let i = 0; i < total + svcN; i += 1) {
    const id = identity(r, i);
    const cells: Record<string, Cell> = {};
    const isSvc = i >= total;
    const age = Math.round((days ?? 90) * (1 + r() * 2.2));
    const comp = report.kind === "computer";
    const name = comp
      ? `${i % 4 === 0 ? "SRV" : "LT"}-${(SITES[i % SITES.length] ?? "LON").slice(0, 3).toUpperCase()}-${String(1000 + ((i * 37) % 9000))}`
      : report.kind === "group"
        ? `${["SG", "DL", "GG"][i % 3]}-${GROUP_WORDS[i % GROUP_WORDS.length]}-${GROUP_WORDS[(i * 3) % GROUP_WORDS.length]}${i % 53 === 7 ? "-Regional-Operations-and-Delegated-Administrators-Group" : ""}`
        : report.kind === "ou"
          ? `${DEPTS[i % DEPTS.length]}-${SITES[(i * 5) % SITES.length]}${i % 41 === 3 ? "-Legacy-Migration-Staging-Do-Not-Use" : ""}`
          : isSvc
            ? `svc-${GROUP_WORDS[i % GROUP_WORDS.length]?.toLowerCase()}-${i}`
            : id.name;
    for (const col of [...report.columns, ...extraColumns(report)]) {
      const k = slug(col);
      const c = col.toLowerCase();
      let v: Cell;
      if (col === "Name" || col === "User" || col === "Group") v = name;
      else if (c === "logon name") v = isSvc ? name : id.sam;
      else if (c === "upn") v = `${id.sam}@${id.domain}`;
      else if (c === "dns name") v = `${name.toLowerCase()}.${id.domain}`;
      else if (c === "domain") v = id.domain;
      else if (c === "ou path" || c === "path") v = isSvc ? "Service accounts" : id.ou;
      else if (c === "status") v = statusFor(r);
      else if (c === "manager" || c === "managed by")
        v =
          r() < 0.08
            ? "—"
            : `${FIRST[Math.floor(r() * FIRST.length)]} ${LAST[Math.floor(r() * LAST.length)]}`;
      else if (c === "type")
        v =
          report.kind === "group"
            ? r() < 0.84
              ? "Security"
              : "Distribution"
            : r() < 0.8
              ? "Workstation"
              : "Server";
      else if (c === "scope") v = ["Global", "Domain local", "Universal"][i % 3] ?? "Global";
      else if (c === "operating system") v = OSES[i % OSES.length]?.[0] ?? "Windows 11 Enterprise";
      else if (c === "os version") v = OSES[i % OSES.length]?.[1] ?? "10.0";
      else if (c === "delegation") v = i % 11 === 0 ? "Unconstrained" : "None";
      else if (c === "e-mail") v = `${id.sam}@example.test`;
      else if (c === "primary group") v = "Domain Users";
      else if (c === "department") v = DEPTS[i % DEPTS.length] ?? "Finance";
      else if (c === "description") v = i % 4 === 0 ? "Migrated from the 2016 forest" : "—";
      else if (c === "policy source") v = i % 13 === 0 ? "PSO: Admins-Strict-14" : "Domain policy";
      else if (c === "password state")
        v =
          presetId === "expired"
            ? "Expired"
            : presetId === "must"
              ? "Must change at next logon"
              : presetId === "never"
                ? i % 3 === 0
                  ? "Never expires (account flag)"
                  : "Never expires (policy)"
                : "Expires soon";
      else if (c === "password expires")
        v =
          presetId === "expired"
            ? fmtDate(1 + (i % 40))
            : presetId === "never"
              ? "—"
              : fmtFuture(1 + (i % 14));
      else if (c === "account expires")
        v =
          presetId === "never"
            ? "—"
            : presetId === "soon"
              ? fmtFuture(1 + (i % 14))
              : fmtDate(1 + (i % 200));
      else if (c === "days to / since expiry")
        v = presetId === "soon" ? `in ${1 + (i % 14)} d` : `${1 + (i % 200)} d ago`;
      else if (c === "probable service account") v = isSvc ? "Yes" : "No";
      else if (c === "locked out since")
        v = `${RUN_TIME.slice(0, 2)}:${String(10 + (i % 40)).padStart(2, "0")}`;
      else if (c === "lockout ends")
        v = i % 6 === 0 ? "Until an admin unlocks" : `10:${String(10 + (i % 40)).padStart(2, "0")}`;
      else if (c === "data as of") v = `${AS_OF} from dc-lon-0${1 + (i % 2)}`;
      else if (c === "from dc") v = DCS[i % DCS.length] ?? "dc-lon-01";
      else if (c === "dc coverage") v = "—";
      else if (c === "failures on that dc") v = 1 + (i % 9);
      else if (c === "last failed logon")
        v = `${fmtDate(i % 7)} ${String(7 + (i % 12)).padStart(2, "0")}:${String((i * 7) % 60).padStart(2, "0")}`;
      else if (c === "real last logon")
        v =
          presetId === "real"
            ? `${fmtDate(Math.min(age, 400))} ${String(7 + (i % 12)).padStart(2, "0")}:${String((i * 11) % 60).padStart(2, "0")}`
            : "—";
      else if (c === "last activity") v = fmtDate(age);
      else if (c === "activity source") v = i % 3 === 0 ? "Machine password" : "Replicated logon";
      else if (c === "days since") v = age;
      else if (c.startsWith("last logon")) v = presetId === "never" ? "No value" : fmtDate(age);
      else if (c === "created" || c === "password last set")
        v = fmtDate(Math.round(r() * 2400) + 5);
      else if (c === "users") v = Math.round(r() * 300);
      else if (c === "computers") v = Math.round(r() * 120);
      else if (c === "groups") v = Math.round(r() * 20);
      else if (c === "other objects") v = Math.round(r() * 5);
      else if (c === "objects in subtree") v = Math.round(r() * 440);
      else if (c === "direct members") v = Math.round(r() * 600);
      else if (c === "effective members") v = Math.round(r() * 2400);
      else v = "—";
      cells[k] = v;
    }
    const rowKey = `${report.id}|${preset.id}|${i}`;
    rows.push(
      isSvc
        ? {
            key: rowKey,
            cells,
            svc: i % 2 === 0 ? "servicePrincipalName set" : "Logon name starts with svc-",
          }
        : { key: rowKey, cells },
    );
  }
  return { rows, svcHidden: svcN };
}

// ---- schedules -----------------------------------------------------------------------------

export type RecipientState = "sent" | "queued" | "failed" | "gave-up";
export interface SchedRecipient {
  readonly who: string;
  readonly external: boolean;
  readonly format: string;
  readonly method: "Attachment" | "Link";
  readonly state: RecipientState;
  readonly detail: string;
}
export interface Schedule {
  readonly id: string;
  readonly name: string;
  readonly report: string;
  readonly when: string;
  readonly next: string;
  readonly owner: string;
  readonly state: "active" | "paused";
  readonly pausedWhy?: string | undefined;
  readonly last: string;
  readonly lastTone: "ok" | "muted" | "warn" | "crit";
  readonly recipients: readonly SchedRecipient[];
  readonly notifyOnlyIfData: boolean;
  readonly runs: readonly { at: string; rows: number; outcome: string; scope: string }[];
}

export const SCHEDULES: readonly Schedule[] = [
  {
    id: "S-1",
    name: "Domain Admins, nested members, monthly",
    report: "Group members · Detailed Group Members · Domain Admins",
    when: "Monthly, 1st at 08:00",
    next: "Tue 1 Dec 2026 08:00 GMT",
    owner: "You",
    state: "active",
    last: "1 of 3 deliveries failed",
    lastTone: "crit",
    notifyOnlyIfData: false,
    recipients: [
      {
        who: "compliance@example.test",
        external: false,
        format: "XLSX",
        method: "Attachment",
        state: "sent",
        detail: "Sent 1 Nov 08:00",
      },
      {
        who: "tomas.villanueva@example.test",
        external: false,
        format: "XLSX",
        method: "Link",
        state: "sent",
        detail: "Sent 1 Nov 08:00 · link opened 1 Nov 08:14",
      },
      {
        who: "auditor@partner.example",
        external: true,
        format: "XLSX",
        method: "Attachment",
        state: "failed",
        detail:
          "Owner lacks external delivery permission. The other 2 recipients were sent. Ask an administrator for reports.deliver.external, or remove this address.",
      },
    ],
    runs: [
      {
        at: "Sun 1 Nov 08:00",
        rows: 14,
        outcome: "2 sent, 1 failed",
        scope: "Your scope: 3 domains",
      },
      { at: "Thu 1 Oct 08:00", rows: 13, outcome: "3 sent", scope: "Your scope: 3 domains" },
    ],
  },
  {
    id: "S-2",
    name: "Password never expires, monthly",
    report: "Password status · Users with Password Never Expires",
    when: "Monthly, 1st at 08:00",
    next: "Tue 1 Dec 2026 08:00 GMT",
    owner: "You",
    state: "active",
    last: "Sent to 2 recipients",
    lastTone: "ok",
    notifyOnlyIfData: false,
    recipients: [
      {
        who: "compliance@example.test",
        external: false,
        format: "XLSX",
        method: "Attachment",
        state: "sent",
        detail: "Sent 1 Nov 08:00",
      },
      {
        who: "ananya.iyer@example.test",
        external: false,
        format: "CSV",
        method: "Attachment",
        state: "sent",
        detail: "Sent 1 Nov 08:00",
      },
    ],
    runs: [
      { at: "Sun 1 Nov 08:00", rows: 1486, outcome: "2 sent", scope: "Your scope: 3 domains" },
    ],
  },
  {
    id: "S-3",
    name: "Inactive users 90 days, weekly",
    report: "Logon activity · Inactive Users",
    when: "Weekly, Monday at 08:00",
    next: "Mon 2 Nov 2026 08:00 GMT",
    owner: "You",
    state: "active",
    last: "Ran, nothing to send",
    lastTone: "muted",
    notifyOnlyIfData: true,
    recipients: [
      {
        who: "tomas.villanueva@example.test",
        external: false,
        format: "CSV",
        method: "Attachment",
        state: "queued",
        detail: "Nothing queued: “Only send if there is data” is on and the last run had 0 rows.",
      },
    ],
    runs: [
      {
        at: "Mon 26 Oct 08:00",
        rows: 0,
        outcome: "Ran, nothing to send",
        scope: "Your scope: 3 domains",
      },
    ],
  },
  {
    id: "S-4",
    name: "Locked-out users, daily",
    report: "Locked-out users · Locked-out Users",
    when: "Daily at 08:00",
    next: "Paused",
    owner: "Dana Whitlock",
    state: "paused",
    pausedWhy:
      "Paused 29 Oct 08:00: the owner, Dana Whitlock, is disabled. Tenant owners were notified. Nothing is sent until someone with “manage all schedules” reassigns it and the new owner resumes it.",
    last: "Paused, owner disabled",
    lastTone: "warn",
    notifyOnlyIfData: false,
    recipients: [
      {
        who: "tomas.villanueva@example.test",
        external: false,
        format: "CSV",
        method: "Attachment",
        state: "queued",
        detail: "Not sent: the schedule is paused.",
      },
    ],
    runs: [
      { at: "Wed 28 Oct 08:00", rows: 31, outcome: "1 sent", scope: "Dana Whitlock's scope: 1 OU" },
    ],
  },
  {
    id: "S-5",
    name: "Real last logon, daily",
    report: "Real last logon · Real Last Logon",
    when: "Daily at 06:00",
    next: "Sat 31 Oct 2026 06:00 GMT",
    owner: "You",
    state: "active",
    last: "Sent as link: file over 10 MB",
    lastTone: "ok",
    notifyOnlyIfData: false,
    recipients: [
      {
        who: "tomas.villanueva@example.test",
        external: false,
        format: "XLSX",
        method: "Link",
        state: "sent",
        detail: "Attachment was over 10 MB, so it went as a link. Link opened 30 Oct 06:12.",
      },
    ],
    runs: [
      {
        at: "Fri 30 Oct 06:00",
        rows: 842,
        outcome: "1 sent (link)",
        scope: "Your scope: 3 domains · read from 6 of 6 DCs",
      },
    ],
  },
];
