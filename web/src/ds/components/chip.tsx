import type { ReactNode } from "react";

export type ChipTone = "ok" | "muted" | "warn" | "crit";

/** Warn and crit carry a glyph of their own shape, so the two never differ by colour alone. */
const GLYPH: Partial<Record<ChipTone, string>> = { warn: "⚠", crit: "✕" };

/** A status chip. The tone is never the only signal: the text always says the state, and warn / crit add a glyph. */
export function Chip({
  tone,
  children,
}: {
  readonly tone: ChipTone;
  readonly children: ReactNode;
}) {
  const glyph = GLYPH[tone];
  return (
    <span className={`diq-chip diq-chip--${tone}`}>
      {glyph !== undefined && (
        <span className="diq-chip__glyph" aria-hidden="true">
          {glyph}
        </span>
      )}
      {children}
    </span>
  );
}
