/* PREVIEW FIXTURE — invented sample directory data. Not real people, not a real domain. */
const NOW = Date.UTC(2026, 9, 2, 10, 42);          // fixed preview clock: Fri 2 Oct 2026, 10:42 UTC
const DAY = 86400000;
const DOMAIN = 'corp.example.test';
const DC_SUFFIX = 'DC=corp,DC=example,DC=test';
function mulberry(seed) { return () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const fold = (s) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/ł/g, 'l').replace(/Ł/g, 'L').replace(/ø/g, 'o').replace(/Ø/g, 'O').replace(/ı/g, 'i').replace(/ğ/g, 'g').replace(/ß/g, 'ss');
const FIRST = ['Aaliyah','Mateusz','Ingrid','Tomás','Noor','Katarzyna','Rahul','Chidi','Freya','Yusuf','Mei','Dmitri','Sofía','Kwame','Elena','Hiroshi','Olu','Brigitte','Arjun','Camille','Nikolai','Fatima','Jonas','Amara','Lucía','Stefan','Priyanka','Emre','Hannah','Viktor','Ayesha','Tobias','Ngozi','Marit','Santiago'];
const LAST = ['Okafor','Lindqvist','Nakamura','Petrov','Alvarez','Haddad','Kowalski','Sharma','Eriksen','Bianchi','Mensah','Fitzgerald','Yilmaz','Dubois','Novak','Tanaka','Oyelaran','Brandt','Iyer','Moreau','Kovač','Rahman','Svensson','Castillo','Nwosu','Hoffmann','Verma','Çelik','Baumann','Andersen','Costa','Ndlovu','Papadopoulos','Rinaldi','Gustafsson'];
const OUS = [['Finance','London'],['Finance','Hyderabad'],['Sales','Chicago'],['Sales','Singapore'],['Engineering','Berlin'],['Engineering','Austin'],['Support','Manila'],['People','London'],['Legal','New York'],['Operations','Warsaw'],['Marketing','Toronto'],['IT','London'],['Contractors','Remote']];
const TITLES = ['Analyst','Senior Analyst','Account Manager','Engineer','Senior Engineer','Support Specialist','HR Partner','Paralegal','Operations Lead','Designer','Team Lead','Coordinator'];
const dnOf = (name, ou) => 'CN=' + name.replace(/,/g, '\\,') + ',' + ou.map((o) => 'OU=' + o).join(',') + ',OU=Staff,' + DC_SUFFIX;
const sid = (n) => 'S-1-5-21-3623811015-3361044348-30300820-' + (1100 + n);
const guid = (n) => { const h = (k) => ((n * 2654435761 + k * 40503) >>> 0).toString(16).padStart(8, '0'); return `${h(1)}-${h(2).slice(0,4)}-${h(3).slice(0,4)}-${h(4).slice(0,4)}-${h(5)}${h(6).slice(0,4)}`; };

function mk(i, o) {
  const ou = o.ou || OUS[i % OUS.length];
  const u = {
    n: i, name: o.name, sam: o.sam, ou, title: o.title || 'Analyst', dept: ou[0], office: ou[1],
    upn: o.upn || `${o.sam}@${DOMAIN}`, mail: o.mail || `${o.sam}@example.test`,
    lastLogon: o.lastLogon === undefined ? NOW - DAY * 0.2 : o.lastLogon,
    pwdSet: o.pwdSet || NOW - DAY * 30, pwdNever: !!o.pwdNever,
    locked: !!o.locked, lockedAt: o.lockedAt || null, lockouts: o.lockouts || 0, lockSource: o.lockSource || null,
    disabled: !!o.disabled, tier0: !!o.tier0, kind: o.kind || 'User', entra: o.entra !== undefined ? o.entra : true,
    created: o.created || Date.UTC(2023, 2, 14), manager: o.manager || 'Marta Lindqvist-Okonkwo',
    groups: o.groups || [['Domain Users','Security · Global'], ['All-Staff','Distribution · Universal']],
  };
  u.dn = o.dn || dnOf(u.name, ou); u.sid = sid(i); u.guid = guid(i);
  u.pwdExpires = u.pwdNever ? null : u.pwdSet + 90 * DAY;
  return u;
}
const CURATED = [
  { name: 'Priya Raghunathan-Venkataraman', sam: 'praghunathan', ou: ['Finance','London'], title: 'Senior Financial Controller', locked: true, lockedAt: NOW - 90 * 60000, lockouts: 3, lockSource: 'LT-LON-0421', lastLogon: NOW - 3 * 3600000, pwdSet: NOW - 76 * DAY, mail: 'priya.raghunathan@example.test',
    groups: [['Finance-Controllers','Security · Global'],['SAP-Finance-Approvers','Security · Global'],['VPN-Users','Security · Global'],['M365-E3-Licensed','Security · Universal'],['Finance-London-Printers','Security · Domain local'],['Domain Users','Security · Global']] },
  { name: 'Dr. Alexandra Konstantinopoulos-Fitzgerald', sam: 'akonstantinopoulos', ou: ['Legal','New York'], title: 'General Counsel, Corporate Affairs' },
  { name: 'Zoë Müller-Åkerblom', sam: 'zmuller-akerblom', ou: ['Engineering','Berlin'], title: 'Staff Engineer', pwdSet: NOW - 84 * DAY },
  { name: 'Łukasz Wiśniewski', sam: 'lwisniewski', ou: ['Operations','Warsaw'], title: 'Operations Lead', locked: true, lockedAt: NOW - 25 * 60000, lockouts: 1, lockSource: 'WS-WAW-0117' },
  { name: 'Yağmur Çelik', sam: 'ycelik', ou: ['Support','Manila'], title: 'Support Specialist', disabled: true, lastLogon: NOW - 140 * DAY },
  { name: 'Søren Østergaard', sam: 'sostergaard', ou: ['Sales','Chicago'], title: 'Account Manager', pwdSet: NOW - 95 * DAY },
  { name: 'Анастасия Ковалёва', sam: 'akovaleva', ou: ['Finance','Hyderabad'], title: 'Analyst' },
  { name: '田中 太郎', sam: 'ttanaka', ou: ['Sales','Singapore'], title: 'Regional Manager', lastLogon: NOW - 120 * DAY },
  { name: 'Marcus Adeyemi (admin)', sam: 'adm_madeyemi', ou: ['IT','London'], title: 'Infrastructure Engineer', tier0: true, pwdNever: false, groups: [['Domain Admins','Security · Global · Tier 0'],['Domain Users','Security · Global']] },
  { name: 'Svetlana Novak (admin)', sam: 'adm_snovak', ou: ['IT','London'], title: 'Identity Engineer', tier0: true, groups: [['Domain Admins','Security · Global · Tier 0'],['Domain Users','Security · Global']] },
  { name: 'svc-backup01', sam: 'svc-backup01', ou: ['IT','London'], title: 'Service account', kind: 'Service account', pwdNever: true, lastLogon: NOW - 2 * 3600000, entra: false },
  { name: 'Rahul Verma', sam: 'rverma', ou: ['Engineering','Austin'], title: 'Senior Engineer', locked: true, lockedAt: NOW - 3 * 3600000, lockouts: 6, lockSource: 'MOBILE-EAS (Exchange)' },
  { name: 'Ngozi Oyelaran', sam: 'noyelaran', ou: ['People','London'], title: 'HR Partner', disabled: true, lastLogon: NOW - 31 * DAY },
  { name: 'Hannah Brandt', sam: 'hbrandt', ou: ['Contractors','Remote'], title: 'Contractor', pwdSet: NOW - 92 * DAY, lastLogon: NOW - 40 * DAY },
  { name: 'Camille Dubois', sam: 'cdubois', ou: ['Marketing','Toronto'], title: 'Designer', lastLogon: null },
].map((o, i) => mk(i, o));

const TOTAL = 12431;
function generate() {
  const r = mulberry(20261002); const seen = new Set(CURATED.map((u) => u.sam)); const out = CURATED.slice();
  while (out.length < TOTAL) {
    const i = out.length; const f = FIRST[Math.floor(r() * FIRST.length)], l = LAST[Math.floor(r() * LAST.length)];
    const name = `${f} ${l}`; let sam = fold((f[0] + l).toLowerCase()).replace(/[^a-z0-9._-]/g, '').slice(0, 17); let k = 1, s = sam;
    while (seen.has(s)) s = sam + (++k); seen.add(s);
    const p = r(); const ou = OUS[Math.floor(r() * OUS.length)];
    out.push(mk(i, { name, sam: s, ou, title: TITLES[Math.floor(r() * TITLES.length)],
      disabled: p < 0.09, locked: p > 0.9993, lockedAt: NOW - Math.floor(r() * 5) * 3600000 - 600000, lockouts: 1 + Math.floor(r() * 3), lockSource: 'WS-' + ['LON','CHI','BER','SIN'][Math.floor(r() * 4)] + '-0' + (100 + Math.floor(r() * 800)),
      lastLogon: r() < 0.04 ? null : NOW - Math.floor(Math.pow(r(), 2.2) * 260) * DAY - Math.floor(r() * DAY),
      pwdSet: NOW - Math.floor(r() * 108) * DAY, pwdNever: r() < 0.03, entra: r() < 0.72, manager: 'Marta Lindqvist-Okonkwo' }));
  }
  return out;
}
const USERS = generate();
const BY_SAM = new Map(USERS.map((u) => [u.sam, u]));
