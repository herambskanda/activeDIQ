import { type ReactNode } from "react";
import { createPortal } from "react-dom";

export interface ToastProps {
  readonly tone?: "info" | "ok";
  readonly children: ReactNode;
  /** One follow-up on what just happened ("Undo", "Run details"). */
  readonly action?: { readonly label: string; readonly onAction: () => void };
  /** Dismiss button, and the dismissal after the action ran. Without it the toast has no ×. */
  readonly onDismiss?: () => void;
  readonly dismissLabel?: string;
}

/**
 * A short message about something that just happened, with at most one action. It stays until it is
 * dismissed or replaced: nothing times out under a keyboard or screen-reader user who has not got
 * to the action yet (WCAG 2.2.1). Activating the action calls `onAction` once, then `onDismiss`.
 * Render it inside a `ToastRegion`, which is what makes it announced. Errors and anything the admin
 * must act on do not belong here: use a banner or `StatePanel`.
 */
export function Toast({
  tone = "info",
  children,
  action,
  onDismiss,
  dismissLabel = "Dismiss",
}: ToastProps) {
  return (
    <div className={`diq-toast diq-toast--${tone}`}>
      <span className="diq-toast__text">{children}</span>
      {action ? (
        <button
          type="button"
          className="diq-btn"
          onClick={() => {
            action.onAction();
            onDismiss?.();
          }}
        >
          {action.label}
        </button>
      ) : null}
      {onDismiss ? (
        <button
          type="button"
          className="diq-toast__x"
          aria-label={dismissLabel}
          onClick={onDismiss}
        >
          <span aria-hidden="true">×</span>
        </button>
      ) : null}
    </div>
  );
}

/**
 * The one live region toasts appear in, mounted once per screen and always present, so a toast
 * added later is announced politely (`role="status"`) without taking focus. It sits on `body`,
 * outside the app root, so an open SideSheet's inert page does not silence it.
 */
export function ToastRegion({ children }: { readonly children?: ReactNode }) {
  return createPortal(
    <div
      className="diq-toasts"
      role="status"
      aria-live="polite"
      aria-atomic="true"
      data-diq-live=""
    >
      {children}
    </div>,
    document.body,
  );
}
