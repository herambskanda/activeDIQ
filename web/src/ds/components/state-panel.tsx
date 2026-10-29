import type { ReactNode } from "react";

/** An empty / error panel with a title, body and optional action. Errors are announced (role=alert). */
export function StatePanel({
  tone = "neutral",
  title,
  children,
}: {
  readonly tone?: "neutral" | "error";
  readonly title?: string;
  readonly children?: ReactNode;
}) {
  return (
    <div
      className={tone === "error" ? "diq-state diq-state--error" : "diq-state"}
      role={tone === "error" ? "alert" : undefined}
    >
      {title !== undefined && <p className="diq-state__title">{title}</p>}
      {children}
    </div>
  );
}
