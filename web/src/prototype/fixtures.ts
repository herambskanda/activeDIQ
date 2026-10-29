// SAMPLE DATA. Invented for the T-0672 design prototype. Nothing here is a real person, domain or
// product number. Fixtures are allowed only in Storybook and tests (OPERATING-MODEL quality rules);
// nothing in src/app or src/modules may import this file.

export type Factor = "sms" | "none";
export type Access = "ok" | "denied" | "privileged";

export interface SampleUser {
  readonly sam: string;
  readonly upn: string;
  readonly name: string;
  readonly mail: string;
  readonly dn: string;
  readonly title: string;
  readonly phone: string; // masked, as the console would show it
  readonly factor: Factor;
  readonly lockedSince: string | null;
  readonly lockouts: number;
  readonly lockSource: string | null;
  readonly pwdExpired: boolean;
  readonly access: Access;
  readonly manager: string;
  readonly groups: readonly string[];
  readonly history: readonly { when: string; who: string; what: string }[];
}

export const SAMPLE_TIME = "2026-10-29 09:14";
export const SAMPLE_CODE = "482916";
export const DOMAIN_USER_COUNT = 12000;

const history = (n: string): SampleUser["history"] => [
  { when: "2026-10-29 09:12", who: "DC-LON-02", what: `Account locked out (${n})` },
  { when: "2026-10-27 16:40", who: "Self-service", what: "Password changed" },
  { when: "2026-09-02 11:05", who: "A. Brandt", what: "Added to Finance-Reports" },
];

export const NAMED: readonly SampleUser[] = [
  {
    sam: "priya.raman",
    upn: "priya.raman@corp.example.test",
    name: "Priya Raman",
    mail: "priya.raman@example.test",
    dn: "CN=Priya Raman,OU=Finance,OU=London,OU=Staff,DC=corp,DC=example,DC=test",
    title: "Accounts Payable Analyst",
    phone: "•••• 4821",
    factor: "sms",
    lockedSince: "09:12",
    lockouts: 3,
    lockSource: "LT-LON-0421",
    pwdExpired: false,
    access: "ok",
    manager: "Tomás Villanueva",
    groups: ["Finance-Reports", "Finance-AP-Approvers", "VPN-Users", "SG-London-Printers"],
    history: history("3rd today, from LT-LON-0421"),
  },
  {
    sam: "p.ramanathan",
    upn: "p.ramanathan@corp.example.test",
    name: "Prakash Ramanathan",
    mail: "prakash.ramanathan@example.test",
    dn: "CN=Prakash Ramanathan,OU=Sales,OU=Mumbai,OU=Staff,DC=corp,DC=example,DC=test",
    title: "Regional Sales Lead",
    phone: "•••• 0937",
    factor: "sms",
    lockedSince: null,
    lockouts: 0,
    lockSource: null,
    pwdExpired: true,
    access: "ok",
    manager: "Ananya Iyer",
    groups: ["Sales-APAC", "VPN-Users"],
    history: history("none"),
  },
  {
    sam: "j.hendriksen-vanderberg",
    upn: "j.hendriksen-vanderberg@corp.example.test",
    name: "Dr. Johanna Hendriksen-van der Berg (Research, Rotterdam site)",
    mail: "johanna.hendriksen-van-der-berg@example.test",
    dn: "CN=Dr. Johanna Hendriksen-van der Berg,OU=Research,OU=Rotterdam,OU=Staff,DC=corp,DC=example,DC=test",
    title: "Principal Investigator",
    phone: "none enrolled",
    factor: "none",
    lockedSince: null,
    lockouts: 0,
    lockSource: null,
    pwdExpired: false,
    access: "ok",
    manager: "Pieter de Vries",
    groups: ["Research-Lab-Access", "VPN-Users"],
    history: history("none"),
  },
  {
    sam: "李伟",
    upn: "li.wei@corp.example.test",
    name: "李伟 (Li Wei)",
    mail: "li.wei@example.test",
    dn: "CN=李伟,OU=Engineering,OU=Shanghai,OU=Staff,DC=corp,DC=example,DC=test",
    title: "Support Engineer",
    phone: "•••• 6602",
    factor: "sms",
    lockedSince: "08:47",
    lockouts: 1,
    lockSource: "WS-SHA-0112",
    pwdExpired: false,
    access: "denied",
    manager: "Chen Jun",
    groups: ["Engineering-Shanghai", "VPN-Users"],
    history: history("1st today, from WS-SHA-0112"),
  },
  {
    sam: "hannah.okafor",
    upn: "hannah.okafor@corp.example.test",
    name: "Hannah Okafor",
    mail: "hannah.okafor@example.test",
    dn: "CN=Hannah Okafor,OU=Admins,OU=IT,OU=Staff,DC=corp,DC=example,DC=test",
    title: "Systems Administrator",
    phone: "•••• 3150",
    factor: "sms",
    lockedSince: null,
    lockouts: 0,
    lockSource: null,
    pwdExpired: false,
    access: "privileged",
    manager: "Marcus Lindqvist",
    groups: ["IT-Server-Admins", "Server Operators (protected)", "VPN-Users"],
    history: history("none"),
  },
];

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
];
const LAST = [
  "Abbott",
  "Barros",
  "Castillo",
  "Dvorak",
  "Eriksen",
  "Fontaine",
  "Grünewald",
  "Hoang",
  "Ito",
  "Jovanović",
];

/** Deterministic filler so the search runs over 12,000 rows, not ten. */
export function buildDirectory(): readonly SampleUser[] {
  const out: SampleUser[] = [...NAMED];
  for (let i = 0; out.length < DOMAIN_USER_COUNT; i += 1) {
    const f = FIRST[i % FIRST.length] ?? "Alma";
    const l = LAST[Math.floor(i / FIRST.length) % LAST.length] ?? "Abbott";
    const n = Math.floor(i / (FIRST.length * LAST.length)) + 1;
    const sam = `${f}.${l}${n}`.toLowerCase().replace(/[ü]/g, "u").replace(/ć/g, "c");
    out.push({
      sam,
      upn: `${sam}@corp.example.test`,
      name: `${f} ${l} ${n}`,
      mail: `${sam}@example.test`,
      dn: "CN=Sample filler user,OU=Staff,DC=corp,DC=example,DC=test",
      title: "Staff",
      phone: "•••• 1000",
      factor: "sms",
      lockedSince: null,
      lockouts: 0,
      lockSource: null,
      pwdExpired: false,
      access: "ok",
      manager: "Tomás Villanueva",
      groups: ["VPN-Users"],
      history: history("none"),
    });
  }
  return out;
}

const WORDS = [
  "harbor",
  "violet",
  "maple",
  "copper",
  "lantern",
  "meadow",
  "orbit",
  "cobalt",
  "willow",
  "ember",
  "quartz",
  "falcon",
];
const NATO: Record<string, string> = {
  h: "Hotel",
  v: "Victor",
  m: "Mike",
  c: "Charlie",
  l: "Lima",
  o: "Oscar",
  w: "Whiskey",
  e: "Echo",
  q: "Quebec",
  f: "Foxtrot",
  a: "Alfa",
  r: "Romeo",
  t: "Tango",
  p: "Papa",
  n: "November",
  i: "India",
  b: "Bravo",
  d: "Delta",
  s: "Sierra",
  y: "Yankee",
  u: "Uniform",
  z: "Zulu",
  x: "X-ray",
  k: "Kilo",
  g: "Golf",
  j: "Juliett",
};

/** Sample generator: a policy-meeting passphrase (three words and two digits). Real generation is server-side. */
export function samplePassphrase(seed: number): string {
  const w = (k: number) => WORDS[(seed * 7 + k * 5) % WORDS.length] ?? "harbor";
  const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
  return `${cap(w(0))}-${w(1)}-${cap(w(2))}-${10 + ((seed * 13) % 90)}`;
}

export function phonetic(pw: string): string {
  return [...pw]
    .map((c) =>
      /[a-z]/i.test(c)
        ? `${/[A-Z]/.test(c) ? "capital " : ""}${NATO[c.toLowerCase()] ?? c}`
        : c === "-"
          ? "dash"
          : c,
    )
    .join(" · ");
}
