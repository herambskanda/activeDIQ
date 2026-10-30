import { GROUPS, REPORTS, type GroupDef, type PresetDef, type ReportDef } from "./fixtures";

export interface Hit {
  readonly report: ReportDef;
  readonly preset: PresetDef;
  /** A group the query named: GRP-02 opens with it filled in, so no picker step. */
  readonly group?: GroupDef | undefined;
  /** The ME name that matched, when it is not our report name. Shown as "Also known as". */
  readonly alias: string | null;
  readonly label: string;
  readonly sub: string;
}

export const HIT_LIMIT = 6;

const FILLER = new Set([
  "members",
  "member",
  "nested",
  "group",
  "groups",
  "effective",
  "detailed",
  "report",
  "of",
  "in",
]);

/**
 * Report search for the `/` overlay (spec §5 Flow A step 1, FR-02). Every term must appear in the
 * report name, ID, category, or a preset/ME name. A term that names a sample group turns GRP-02
 * hits into "Detailed Group Members · <group>" so the admin never meets a group picker.
 */
export function searchReports(query: string, allowed: boolean): { hits: Hit[]; total: number } {
  if (!allowed) return { hits: [], total: 0 };
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return { hits: [], total: 0 };
  const rest = terms.filter((t) => !FILLER.has(t));
  const group =
    rest.length > 0
      ? GROUPS.find((g) => rest.every((t) => g.name.toLowerCase().includes(t)))
      : undefined;
  const hits: { h: Hit; score: number }[] = [];

  if (group) {
    const rep = REPORTS.find((r) => r.id === "GRP-02");
    if (rep) {
      for (const [i, pr] of rep.presets.entries()) {
        hits.push({
          h: {
            report: rep,
            preset: pr,
            group,
            alias: null,
            label: `${pr.name} · ${group.name}`,
            sub: `${rep.name} · ${rep.category}`,
          },
          score: i,
        });
      }
    }
  }

  for (const rep of REPORTS) {
    for (const pr of rep.presets) {
      const hay = `${rep.name} ${rep.id} ${rep.category} ${pr.name}`.toLowerCase();
      if (!terms.every((t) => hay.includes(t))) continue;
      if (group && rep.id === "GRP-02") continue;
      const presetStarts = pr.name.toLowerCase().startsWith(terms[0] ?? "");
      const nameStarts = rep.name.toLowerCase().startsWith(terms[0] ?? "");
      const alias = pr.name.toLowerCase() === rep.name.toLowerCase() ? null : pr.name;
      hits.push({
        h: {
          report: rep,
          preset: pr,
          alias,
          label: rep.name,
          sub: `${rep.category} · preset ${pr.name}`,
        },
        score: 10 + (presetStarts ? 0 : nameStarts ? 1 : 2) + (rep.requires ? 2 : 0),
      });
    }
  }
  hits.sort((a, b) => a.score - b.score);
  return { hits: hits.slice(0, HIT_LIMIT).map((x) => x.h), total: hits.length };
}
