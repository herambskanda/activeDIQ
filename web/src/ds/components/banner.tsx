import type { ReactNode } from "react";

export type BannerTone = "info" | "warn" | "crit";

/** One glyph shape per tone, so tone is never carried by colour alone (WCAG 1.4.1). */
const GLYPH: Record<BannerTone, string> = { info: "ⓘ", warn: "⚠", crit: "✕" };

/**
 * An in-page state banner (stale data, partial result, not synced). `crit` is announced at once
 * (role=alert); `info` and `warn` are polite (role=status). The text must say the state in words.
 */
export function Banner({
  tone,
  title,
  children,
  actions,
}: {
  readonly tone: BannerTone;
  readonly title?: string;
  readonly children?: ReactNode;
  /** Buttons or links; shown after the text, wrapping below it on a narrow screen. */
  readonly actions?: ReactNode;
}) {
  return (
    <div className={`diq-banner diq-banner--${tone}`} role={tone === "crit" ? "alert" : "status"}>
      <span className="diq-banner__glyph" aria-hidden="true">
        {GLYPH[tone]}
      </span>
      <div className="diq-banner__body">
        {title !== undefined && <p className="diq-banner__title">{title}</p>}
        {children !== undefined && <div className="diq-banner__text">{children}</div>}
      </div>
      {actions !== undefined && <div className="diq-banner__actions">{actions}</div>}
    </div>
  );
}
