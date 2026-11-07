import { type ReactNode, useEffect, useId, useRef } from "react";

export interface DetailDockProps {
  /** The dock's name and heading: what is being shown ("Wei Okafor"). Changes when the row changes. */
  readonly title: ReactNode;
  /** Plain-text form of `title` for the announcement. Defaults to `title` when it is a string. */
  readonly titleText?: string | undefined;
  /** One line under the title: the kind or the object's path. */
  readonly description?: ReactNode | undefined;
  /** Esc (focus inside the dock), and the Close button. The caller drops `?row=`. */
  readonly onClose: () => void;
  /** Previous / next row. Give both, with `position`, to show the stepper; the first / last row disables its end. */
  readonly onPrev?: (() => void) | undefined;
  readonly onNext?: (() => void) | undefined;
  /** 1-based place of the shown row among all rows: shown as "5 of 214". */
  readonly position?: { readonly index: number; readonly total: number } | undefined;
  /** Pinned under the body (a link row, "Copy link"). */
  readonly footer?: ReactNode | undefined;
  /** Spoken and shown place text. Default "5 of 214". */
  readonly positionLabel?: ((index: number, total: number) => string) | undefined;
  readonly closeLabel?: string | undefined;
  readonly prevLabel?: string | undefined;
  readonly nextLabel?: string | undefined;
  /** Scrollable detail content. */
  readonly children: ReactNode;
}

/**
 * A docked, non-modal detail pane beside a grid (520 px, `--diq-sheet-w`). The grid stays live:
 * opening the dock moves no focus, so ↑/↓ in the grid keep stepping through rows and the pane
 * follows (the screen swaps its content), and the Previous / Next buttons do the same for the
 * pointer. Esc inside the dock closes it and focus returns to where it was before. It is a labelled
 * `complementary` landmark, not a dialog: no focus trap, the page behind is not inert.
 * Put it in `DockLayout` next to the grid. For work that needs a Save use `SideSheet` (modal).
 */
export function DetailDock(props: DetailDockProps) {
  const {
    title,
    titleText,
    description,
    onClose,
    onPrev,
    onNext,
    position,
    positionLabel = (i, n) => `${i.toLocaleString("en")} of ${n.toLocaleString("en")}`,
    footer,
    closeLabel = "Close details",
    prevLabel = "Previous",
    nextLabel = "Next",
    children,
  } = props;
  const uid = useId();
  const root = useRef<HTMLElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const live = useRef<HTMLDivElement>(null);
  const body = useRef<HTMLDivElement>(null);
  const name = titleText ?? (typeof title === "string" ? title : undefined);

  // Remember what had focus when the dock opened; give it back on close if focus is lost with the dock.
  useEffect(() => {
    const el = document.activeElement;
    opener.current = el instanceof HTMLElement && el !== document.body ? el : null;
    return () => {
      const back = opener.current;
      const a = document.activeElement;
      const lost = !a || a === document.body || root.current?.contains(a);
      if (back && back.isConnected && lost) back.focus({ preventScroll: true });
    };
  }, []);

  // The announcement: on open, and when the row changes while focus is in the dock (stepper).
  const first = useRef(true);
  useEffect(() => {
    const inside = root.current?.contains(document.activeElement) ?? false;
    if (!first.current && !inside) return;
    first.current = false;
    if (live.current && name !== undefined) {
      live.current.textContent = `${name}${position ? `, ${positionLabel(position.index, position.total)}` : ""}`;
    }
    // A new row starts at the top of its detail.
    if (body.current) body.current.scrollTop = 0;
  }, [name, position?.index, position?.total]);

  const stepper = position !== undefined && (onPrev !== undefined || onNext !== undefined);
  // The end buttons are aria-disabled, not disabled: stepping onto the last row must not drop focus to <body>.
  const atStart = onPrev === undefined || (position?.index ?? 0) <= 1;
  const atEnd = onNext === undefined || (position?.index ?? 0) >= (position?.total ?? 0);
  return (
    <aside
      ref={root}
      className="diq-dock"
      aria-labelledby={`${uid}-t`}
      onKeyDown={(e) => {
        if (e.nativeEvent.isComposing) return;
        if (e.key === "Escape" && !e.defaultPrevented) {
          e.preventDefault();
          e.stopPropagation();
          onClose();
        }
      }}
    >
      <header className="diq-dock__head">
        <div className="diq-dock__titles">
          <h2 id={`${uid}-t`} className="diq-dock__title">
            {title}
          </h2>
          {description ? <p className="diq-dock__desc">{description}</p> : null}
        </div>
        <button type="button" className="diq-dock__btn" onClick={onClose}>
          {closeLabel}
        </button>
      </header>
      {stepper ? (
        <div className="diq-dock__step">
          <button
            type="button"
            className="diq-dock__btn"
            aria-disabled={atStart || undefined}
            onClick={atStart ? undefined : onPrev}
          >
            <span aria-hidden="true">↑ </span>
            {prevLabel}
          </button>
          <button
            type="button"
            className="diq-dock__btn"
            aria-disabled={atEnd || undefined}
            onClick={atEnd ? undefined : onNext}
          >
            <span aria-hidden="true">↓ </span>
            {nextLabel}
          </button>
          <span className="diq-dock__pos" dir="auto">
            {positionLabel(position.index, position.total)}
          </span>
        </div>
      ) : null}
      <div ref={body} className="diq-dock__body">
        {children}
      </div>
      {footer ? <footer className="diq-dock__foot">{footer}</footer> : null}
      <div ref={live} className="diq-sr-only" role="status" aria-live="polite" />
    </aside>
  );
}

/**
 * The grid beside its dock. Side by side while the width allows (the grid scrolls sideways beside
 * the dock, its name column stays in view); when it does not, the dock drops below the grid at full
 * width. No breakpoints: it wraps on the dock's own width token.
 */
export function DockLayout({
  children,
  dock,
}: {
  readonly children: ReactNode;
  readonly dock?: ReactNode;
}) {
  return (
    <div className="diq-dock-layout">
      <div className="diq-dock-layout__main">{children}</div>
      {dock}
    </div>
  );
}
