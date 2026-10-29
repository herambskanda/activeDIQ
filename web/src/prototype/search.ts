import type { SampleUser } from "./fixtures";

export const RESULT_LIMIT = 8;

/** Every whitespace-separated term must appear in the name, account name, UPN or e-mail (case-insensitive). */
export function searchUsers(
  all: readonly SampleUser[],
  query: string,
): { hits: SampleUser[]; total: number } {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return { hits: [], total: 0 };
  const scored: { u: SampleUser; score: number }[] = [];
  for (const u of all) {
    const hay = `${u.name} ${u.sam} ${u.upn} ${u.mail}`.toLowerCase();
    if (!terms.every((t) => hay.includes(t))) continue;
    const first = terms[0] ?? "";
    const score =
      u.sam.toLowerCase() === query.toLowerCase()
        ? 0
        : u.sam.toLowerCase().startsWith(first) || u.name.toLowerCase().startsWith(first)
          ? 1
          : 2;
    scored.push({ u, score });
  }
  // Locked accounts first within a rank: the help desk is usually looking for the one who just called.
  scored.sort((a, b) => a.score - b.score || Number(!!b.u.lockedSince) - Number(!!a.u.lockedSince));
  return { hits: scored.slice(0, RESULT_LIMIT).map((s) => s.u), total: scored.length };
}
