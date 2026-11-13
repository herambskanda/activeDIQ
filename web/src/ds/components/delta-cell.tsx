import type { ReactNode } from "react";

/**
 * How a value compares with its baseline. The screen decides (direction rules are domain knowledge,
 * not the cell's): `differs` is for a difference whose direction is not confirmed.
 */
export type DeltaDirection = "stricter" | "weaker" | "same" | "differs";

const GLYPH: Record<DeltaDirection, string> = {
  stricter: "▲",
  weaker: "▼",
  same: "=",
  differs: "≠",
};

export interface DeltaCellProps {
  /** The value as the screen formats it ("12 characters", "Never locks"). */
  readonly value: ReactNode;
  readonly direction: DeltaDirection;
  /** The signed size of the change, already formatted ("+12", "−2"). Omit when it has no number. */
  readonly amount?: string | undefined;
  /** What the value is compared with, in words: "the domain policy". Completes the spoken sentence. */
  readonly comparedTo: string;
  /** Show the word ("stricter") beside the glyph. Off in a grid cell, on in a detail pane. */
  readonly showWord?: boolean | undefined;
}

/**
 * A value with its difference from a baseline: `12 ▲ +12`. The glyph and number are the visible
 * signal, a visually hidden sentence ("stricter than the domain policy, +12") is the spoken one, and
 * only `weaker` is coloured (warn): stricter is not "better", so it is plain text, never green.
 * Colour is never the only carrier, `differs` and `same` have glyphs of their own.
 */
export function DeltaCell({
  value,
  direction,
  amount,
  comparedTo,
  showWord = false,
}: DeltaCellProps) {
  const spoken =
    direction === "same"
      ? `same as ${comparedTo}`
      : direction === "differs"
        ? `differs from ${comparedTo}`
        : `${direction} than ${comparedTo}`;
  return (
    <span className="diq-delta">
      <span className="diq-delta__value">{value}</span>
      <span className={`diq-delta__mark diq-delta__mark--${direction}`}>
        <span aria-hidden="true">
          {GLYPH[direction]}
          {amount !== undefined && amount !== "" ? ` ${amount}` : ""}
          {showWord ? ` ${direction === "same" ? "same" : direction}` : ""}
        </span>
        <span className="diq-sr-only">
          {` (${spoken}${amount !== undefined && amount !== "" ? `, ${amount}` : ""})`}
        </span>
      </span>
    </span>
  );
}
