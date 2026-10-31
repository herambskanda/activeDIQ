import { type ReactNode, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";

import { tabbables } from "./popover";

export interface SideSheetProps {
  readonly open: boolean;
  /** Escape, the Close button and a press on the scrim all call this. The caller decides whether to confirm. */
  readonly onClose: () => void;
  /** The sheet's name; it is the heading and the dialog's accessible name. */
  readonly title: ReactNode;
  /** One line under the title: what this sheet acts on. */
  readonly description?: ReactNode;
  readonly width?: "default" | "wide";
  readonly closeLabel?: string;
  readonly children: ReactNode;
}

/**
 * A modal panel from the inline-end edge for work that needs room and a Save: schedule, create,
 * run details. While open, focus is trapped inside, the page behind is inert, Escape closes it and
 * focus returns to the element that opened it. Children own their layout (put the form, with its
 * own submit button, inside). Not for a quick choice (use `PopoverMenu`) or a short confirmation.
 * It leaves instantly (no exit animation), so a quick reopen is never blocked.
 */
export function SideSheet(props: SideSheetProps) {
  return props.open ? <Sheet {...props} /> : null;
}

function Sheet({
  onClose,
  title,
  description,
  width = "default",
  closeLabel = "Close",
  children,
}: SideSheetProps) {
  const uid = useId();
  const scrim = useRef<HTMLDivElement>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const pressedOnScrim = useRef(false);
  // The opener is read during the first render, before any child `autoFocus` moves focus.
  const [opener] = useState<Element | null>(() => document.activeElement);

  useEffect(() => {
    const d = dialog.current;
    const s = scrim.current;
    if (!d || !s) return;
    // Make the page behind inert, except live regions (toasts) so announcements still reach AT.
    const inerted: Element[] = [];
    for (const el of Array.from(document.body.children)) {
      if (el === s || el.hasAttribute("inert") || el.hasAttribute("data-diq-live")) continue;
      if (el.tagName === "SCRIPT" || el.tagName === "STYLE") continue;
      el.setAttribute("inert", "");
      inerted.push(el);
    }
    if (!d.contains(document.activeElement)) {
      (d.querySelector<HTMLElement>("[data-autofocus]") ?? tabbables(d)[0] ?? d).focus();
    }
    const stray = (e: FocusEvent) => {
      const t = e.target as Element | null;
      if (t && !d.contains(t) && !t.closest("[data-diq-live]")) (tabbables(d)[0] ?? d).focus();
    };
    document.addEventListener("focusin", stray);
    return () => {
      document.removeEventListener("focusin", stray);
      for (const el of inerted) el.removeAttribute("inert");
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus();
    };
  }, [opener]);

  return createPortal(
    <div
      ref={scrim}
      className="diq-sheet__scrim"
      onMouseDown={(e) => {
        pressedOnScrim.current = e.target === e.currentTarget;
      }}
      // Close on click, not on press: the press moves focus to the page, and the close must run
      // after that so focus lands on the opener. A drag that began inside the sheet never closes.
      onClick={(e) => {
        const pressed = pressedOnScrim.current;
        pressedOnScrim.current = false;
        if (pressed && e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={dialog}
        className={`diq-sheet${width === "wide" ? " diq-sheet--wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={`${uid}-t`}
        aria-describedby={description ? `${uid}-d` : undefined}
        tabIndex={-1}
        onKeyDown={(e) => {
          if (e.nativeEvent.isComposing) return;
          if (e.key === "Escape" && !e.defaultPrevented) {
            e.stopPropagation();
            onClose();
          } else if (e.key === "Tab" && dialog.current) {
            const items = tabbables(dialog.current);
            const first = items[0];
            const last = items[items.length - 1];
            const at = document.activeElement;
            if (!first || !last) {
              e.preventDefault();
              dialog.current.focus();
            } else if (e.shiftKey && (at === first || at === dialog.current)) {
              e.preventDefault();
              last.focus();
            } else if (!e.shiftKey && at === last) {
              e.preventDefault();
              first.focus();
            }
          }
        }}
      >
        <header className="diq-sheet__head">
          <div className="diq-sheet__titles">
            <h2 id={`${uid}-t`} className="diq-sheet__title">
              {title}
            </h2>
            {description ? (
              <p id={`${uid}-d`} className="diq-sheet__desc">
                {description}
              </p>
            ) : null}
          </div>
          <button type="button" className="diq-sheet__close" onClick={onClose}>
            {closeLabel}
          </button>
        </header>
        <div className="diq-sheet__body">{children}</div>
      </div>
    </div>,
    document.body,
  );
}
