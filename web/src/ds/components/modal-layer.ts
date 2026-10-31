import { type RefObject, useEffect, useState } from "react";

import { tabbables } from "./popover";

/**
 * What every modal overlay (SideSheet, CommandPalette) shares: while mounted, the page behind is
 * `inert` (live regions marked `data-diq-live` are exempt so announcements still arrive), focus
 * that strays outside the dialog is pulled back in, and on unmount focus returns to the element
 * that had it when the overlay first rendered. The opener is read during the first render, before
 * any child `autoFocus` moves focus. `initialFocus` picks the element that takes focus if the
 * dialog does not already hold it.
 */
export function useModalLayer(
  scrim: RefObject<HTMLElement | null>,
  dialog: RefObject<HTMLElement | null>,
  initialFocus?: (dialog: HTMLElement) => HTMLElement | null,
): void {
  const [opener] = useState<Element | null>(() => document.activeElement);

  useEffect(() => {
    const d = dialog.current;
    const s = scrim.current;
    if (!d || !s) return;
    const inerted: Element[] = [];
    for (const el of Array.from(document.body.children)) {
      if (el === s || el.hasAttribute("inert") || el.hasAttribute("data-diq-live")) continue;
      if (el.tagName === "SCRIPT" || el.tagName === "STYLE") continue;
      el.setAttribute("inert", "");
      inerted.push(el);
    }
    if (!d.contains(document.activeElement)) {
      (
        initialFocus?.(d) ??
        d.querySelector<HTMLElement>("[data-autofocus]") ??
        tabbables(d)[0] ??
        d
      ).focus();
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
    // `initialFocus` is read once, on open.
  }, [opener, scrim, dialog]);
}
