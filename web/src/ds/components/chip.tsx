import type { ReactNode } from "react";

/** A status chip. The tone is never the only signal: the text always says the state. */
export function Chip({
  tone,
  children,
}: {
  readonly tone: "ok" | "muted";
  readonly children: ReactNode;
}) {
  return <span className={`diq-chip diq-chip--${tone}`}>{children}</span>;
}
