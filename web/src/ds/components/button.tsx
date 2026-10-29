import type { ButtonHTMLAttributes } from "react";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  readonly variant?: "secondary" | "primary";
  /** Work is in flight: the button stays focusable and announces busy, but ignores clicks. */
  readonly loading?: boolean;
}

/** The one button. Defaults to type="button" so it never submits a form by accident. */
export function Button({
  variant = "secondary",
  loading = false,
  className,
  type = "button",
  onClick,
  ...rest
}: ButtonProps) {
  const cls = ["diq-btn", variant === "primary" ? "diq-btn--primary" : "", className ?? ""]
    .filter(Boolean)
    .join(" ");
  return (
    <button
      {...rest}
      type={type}
      className={cls}
      aria-busy={loading || undefined}
      aria-disabled={loading || undefined}
      onClick={loading ? undefined : onClick}
    />
  );
}
