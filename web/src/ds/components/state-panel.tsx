import type { ReactNode } from "react";

/**
 * An empty / error panel with a title, body and optional actions. Errors are announced (role=alert).
 * `actions` takes Buttons (or links); the panel adds no callbacks of its own.
 */
export function StatePanel({
  tone = "neutral",
  title,
  children,
  actions,
}: {
  readonly tone?: "neutral" | "error";
  readonly title?: string;
  readonly children?: ReactNode;
  readonly actions?: ReactNode;
}) {
  return (
    <div
      className={tone === "error" ? "diq-state diq-state--error" : "diq-state"}
      role={tone === "error" ? "alert" : undefined}
    >
      {title !== undefined && <p className="diq-state__title">{title}</p>}
      {children}
      {actions !== undefined && <div className="diq-state__actions">{actions}</div>}
    </div>
  );
}
