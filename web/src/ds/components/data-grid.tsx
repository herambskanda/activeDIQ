import {
  type CSSProperties,
  type KeyboardEvent,
  type MouseEvent,
  type PointerEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";

export interface DataGridColumn<Row> {
  readonly key: string;
  /** Plain text: it is the column's accessible name and the sort announcement. */
  readonly header: string;
  readonly cell: (row: Row) => ReactNode;
  /** Full text for the cell's `title` when the content is truncated. Defaults to the cell's text when it is a string or number. */
  readonly title?: (row: Row) => string;
  /** The row-header column (th scope=row). Defaults to the first column; keep it first, it stays in view when the grid scrolls sideways. */
  readonly rowHeader?: boolean;
  /** Initial width in characters (ch). Default 16. */
  readonly width?: number;
  readonly sortable?: boolean;
  readonly mono?: boolean;
  /** Numbers and dates align to the end. */
  readonly align?: "start" | "end";
}

export interface DataGridSort {
  readonly key: string;
  readonly dir: "asc" | "desc";
}

export interface DataGridProps<Row> {
  /** Accessible name, announced when the grid is entered; visually hidden. Include the row count. */
  readonly caption: string;
  readonly columns: readonly DataGridColumn<Row>[];
  readonly rows: readonly Row[];
  readonly rowKey: (row: Row) => string;
  /** The current sort. The grid does not sort: the server (or the screen) does, on `onSort`. */
  readonly sort?: DataGridSort | null | undefined;
  /** A sortable header was activated (click, Enter or Space). Fires once per activation. */
  readonly onSort?: ((key: string) => void) | undefined;
  /** Row selection is on when `onSelectedChange` is given. `selected` holds row keys. */
  readonly selected?: ReadonlySet<string> | undefined;
  readonly onSelectedChange?: ((next: ReadonlySet<string>) => void) | undefined;
  /** The row whose detail a `DetailDock` shows: marked `aria-current`, tinted, and scrolled into view when it changes (focus does not move). */
  readonly currentRowKey?: string | null | undefined;
  /** Focus moved onto a different data row (arrows, Tab in, click). A detail pane uses it to follow the row. Not called for the header. */
  readonly onActiveRowChange?: ((row: Row) => void) | undefined;
  /** Escape on a cell of the grid (not inside a widget). Closing a docked detail pane. */
  readonly onEscape?: (() => void) | undefined;
  /** Enter on a row cell. */
  readonly onRowActivate?: ((row: Row) => void) | undefined;
  /** Columns can be resized by pointer and with Shift+Left/Right on a focused header. */
  readonly resizable?: boolean | undefined;
  readonly onColumnResize?: ((key: string, widthCh: number) => void) | undefined;
  /** Body rows visible before the grid scrolls (default 15). Row height is --diq-row, so density follows the theme. */
  readonly visibleRows?: number | undefined;
  /** Server work in flight: the grid stays in place, dimmed, and announces busy. */
  readonly busy?: boolean | undefined;
  /** Shown instead of rows when there are none. */
  readonly empty?: ReactNode | undefined;
}

/** Rows rendered beyond the viewport on each side, so scrolling never shows a blank band. */
const OVERSCAN = 3;
const DEFAULT_VISIBLE_ROWS = 15;
const DEFAULT_WIDTH_CH = 16;
const MIN_WIDTH_CH = 6;
const MAX_WIDTH_CH = 120;
const RESIZE_STEP_CH = 2;
/** Used only where layout is unavailable (tests). Must equal --diq-row-compact; a test keeps them equal. */
export const FALLBACK_ROW_PX = 32;
const INTERACTIVE = "a[href], button, input, select, textarea, [tabindex]";

function textOf(v: ReactNode): string | undefined {
  return typeof v === "string" || typeof v === "number" ? String(v) : undefined;
}

/**
 * How far the content must move sideways (positive = towards the right) so a focused cell is not
 * under the sticky columns nor past the far edge. `stuck` is the width the sticky columns cover at
 * the inline start; `rtl` mirrors it. Pure: rectangles in, pixels out. The caller does
 * `scrollLeft -= shift` (that holds in LTR and RTL).
 */
export function inlineShift(
  cell: { readonly left: number; readonly right: number },
  view: { readonly left: number; readonly right: number },
  stuck: number,
  rtl: boolean,
): number {
  const freeL = rtl ? view.left : view.left + stuck;
  const freeR = rtl ? view.right - stuck : view.right;
  const atLeft = cell.left < freeL ? freeL - cell.left : 0;
  const atRight = cell.right > freeR ? freeR - cell.right : 0;
  // A cell wider than the free area lines up with the inline start.
  return rtl ? atRight || atLeft : atLeft || atRight;
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

/**
 * The one data grid: windowed rows (12,000 cost the same as 40), sticky header and row-header column,
 * server-driven sort, resizable columns and optional row selection. ARIA grid pattern: one tab stop,
 * arrow keys move between cells. Rows are one line high (--diq-row); long values truncate with the
 * full text in `title`. For a short, read-only list use `Table`.
 */
export function DataGrid<Row>(props: DataGridProps<Row>) {
  const {
    caption,
    columns,
    rows,
    rowKey,
    sort = null,
    onSort,
    selected,
    onSelectedChange,
    onRowActivate,
    currentRowKey = null,
    onActiveRowChange,
    onEscape,
    resizable = false,
    onColumnResize,
    visibleRows = DEFAULT_VISIBLE_ROWS,
    busy = false,
    empty,
  } = props;
  const selectable = onSelectedChange !== undefined;
  const sel = selected ?? EMPTY;
  const offset = selectable ? 1 : 0; // visual column index of columns[0]

  const box = useRef<HTMLDivElement>(null);
  const chProbe = useRef<HTMLSpanElement>(null);
  const allBox = useRef<HTMLInputElement>(null);
  const [top, setTop] = useState(0);
  const [viewH, setViewH] = useState(0);
  const [rowH, setRowH] = useState(FALLBACK_ROW_PX);
  const [active, setActive] = useState({ r: 0, c: 0 });
  const [widths, setWidths] = useState<Readonly<Record<string, number>>>({});
  const [announce, setAnnounce] = useState("");
  const [scrolledX, setScrolledX] = useState(false);
  const pendingFocus = useRef<{ r: number; c: number } | null>(null);
  const anchor = useRef(0);
  const reportedRow = useRef<string | null>(null);

  // Row height follows --diq-row (density); viewport height follows the box. Re-measured on resize and density change.
  const measure = useCallback(() => {
    const el = box.current;
    if (!el) return;
    const px = parseFloat(getComputedStyle(el).getPropertyValue("--diq-row"));
    if (Number.isFinite(px) && px > 0) setRowH(px);
    setViewH(el.clientHeight);
  }, []);
  useLayoutEffect(() => {
    measure();
    const el = box.current;
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(measure);
    if (el && ro) ro.observe(el);
    const mo = new MutationObserver(measure);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-density"] });
    return () => {
      ro?.disconnect();
      mo.disconnect();
    };
  }, [measure]);

  // A new result set starts at the top.
  useEffect(() => {
    if (box.current) box.current.scrollTop = 0;
    setTop(0);
    setActive((a) => (a.r <= rows.length ? a : { r: rows.length, c: a.c }));
  }, [rows]);

  // Selection and sort changes are announced politely.
  const firstRun = useRef(true);
  useEffect(() => {
    if (firstRun.current) return;
    const h = columns.find((c) => c.key === sort?.key)?.header;
    setAnnounce(
      h ? `Sorted by ${h}, ${sort?.dir === "desc" ? "descending" : "ascending"}` : "Sort cleared",
    );
  }, [sort?.key, sort?.dir]);
  useEffect(() => {
    if (firstRun.current) {
      firstRun.current = false;
      return;
    }
    if (selectable)
      setAnnounce(
        `${sel.size.toLocaleString("en")} of ${rows.length.toLocaleString("en")} selected`,
      );
  }, [sel.size]);

  const bodyH = (viewH > 0 ? viewH : (visibleRows + 1) * rowH) - rowH; // the sticky header covers the first rowH
  const first = Math.max(0, Math.floor(top / rowH) - OVERSCAN);
  const last = Math.min(rows.length, Math.ceil((top + bodyH) / rowH) + OVERSCAN);
  const slice = rows.slice(first, last);

  const widthOf = (c: DataGridColumn<Row>) => widths[c.key] ?? c.width ?? DEFAULT_WIDTH_CH;
  const nCols = columns.length + offset;
  const rhIndex =
    columns.findIndex((c) => c.rowHeader) >= 0 ? columns.findIndex((c) => c.rowHeader) : 0;

  const allSelected = rows.length > 0 && sel.size >= rows.length;
  useEffect(() => {
    if (allBox.current) allBox.current.indeterminate = sel.size > 0 && !allSelected;
  }, [sel.size, allSelected]);

  // ---- focus and scrolling ---------------------------------------------------
  const reveal = (r: number) => {
    const el = box.current;
    if (!el || r < 1) return;
    const i = r - 1;
    const viewport = viewH > 0 ? viewH : (visibleRows + 1) * rowH;
    let st = el.scrollTop;
    if (i * rowH < st) st = i * rowH;
    else if ((i + 2) * rowH > st + viewport) st = (i + 2) * rowH - viewport;
    if (st !== el.scrollTop) {
      el.scrollTop = st;
      setTop(st);
    }
  };
  // Sideways: keep the focused cell clear of the sticky name column and inside the box.
  const revealX = (cell: HTMLElement) => {
    const el = box.current;
    if (!el || cell.classList.contains("diq-grid__rh") || cell.hasAttribute("data-sel")) return;
    const stuck = Array.from(
      el.querySelectorAll<HTMLElement>("thead .diq-grid__sel, thead .diq-grid__rh"),
    ).reduce((n, h) => n + h.offsetWidth, 0);
    const b = el.getBoundingClientRect();
    const left = b.left + el.clientLeft;
    const rtl = getComputedStyle(el).direction === "rtl";
    const dx = inlineShift(
      cell.getBoundingClientRect(),
      { left, right: left + el.clientWidth },
      stuck,
      rtl,
    );
    if (dx !== 0) el.scrollLeft -= dx;
  };
  // The row a detail pane shows scrolls into view when it changes.
  const currentIdx =
    currentRowKey === null ? -1 : rows.findIndex((r) => rowKey(r) === currentRowKey);
  useEffect(() => {
    if (currentIdx >= 0) reveal(currentIdx + 1);
  }, [currentRowKey]);
  const goto = (r: number, c: number) => {
    const next = { r: clamp(r, 0, rows.length), c: clamp(c, 0, nCols - 1) };
    reveal(next.r);
    pendingFocus.current = next;
    setActive(next);
  };
  useLayoutEffect(() => {
    const want = pendingFocus.current;
    if (!want) return;
    const cell = box.current?.querySelector<HTMLElement>(
      `[data-r="${want.r}"][data-c="${want.c}"]`,
    );
    if (cell) {
      pendingFocus.current = null;
      cell.focus({ preventScroll: true });
      revealX(cell);
    }
  });
  // One tab stop: widgets inside cells (links, buttons) are reachable with Tab only from their own, active cell.
  useLayoutEffect(() => {
    box.current?.querySelectorAll<HTMLElement>("td[data-r]:not([data-sel])").forEach((cell) => {
      const on =
        cell.getAttribute("data-r") === String(active.r) &&
        cell.getAttribute("data-c") === String(active.c);
      cell.querySelectorAll<HTMLElement>(INTERACTIVE).forEach((w) => {
        w.tabIndex = on ? 0 : -1;
      });
    });
  });

  // The cell that holds the tab stop: the active one if it is rendered, else the first rendered row's first cell.
  const activeRendered = active.r === 0 || (active.r - 1 >= first && active.r - 1 < last);
  const stop = activeRendered ? active : { r: first + 1, c: 0 };
  const tab = (r: number, c: number) =>
    rows.length === 0 && r > 0 ? undefined : r === stop.r && c === stop.c ? 0 : -1;

  // ---- selection -------------------------------------------------------------
  const emit = (next: Set<string>) => onSelectedChange?.(next);
  const toggleRow = (idx: number, range: boolean) => {
    const row = rows[idx];
    if (!row) return;
    const next = new Set(sel);
    const key = rowKey(row);
    if (range) {
      const [a, b] = [Math.min(anchor.current, idx), Math.max(anchor.current, idx)];
      for (let i = a; i <= b; i++) {
        const r = rows[i];
        if (r) next.add(rowKey(r));
      }
    } else {
      if (next.has(key)) next.delete(key);
      else next.add(key);
      anchor.current = idx;
    }
    emit(next);
  };
  const toggleAll = () => emit(allSelected ? new Set() : new Set(rows.map(rowKey)));

  // ---- resizing --------------------------------------------------------------
  const resize = (col: DataGridColumn<Row>, w: number) => {
    const next = clamp(Math.round(w * 10) / 10, MIN_WIDTH_CH, MAX_WIDTH_CH);
    setWidths((m) => ({ ...m, [col.key]: next }));
    onColumnResize?.(col.key, next);
  };
  const startDrag = (col: DataGridColumn<Row>, e: PointerEvent<HTMLElement>) => {
    const chPx = chProbe.current?.getBoundingClientRect().width ?? 0;
    if (chPx <= 0) return;
    e.preventDefault();
    e.stopPropagation();
    const dir = box.current && getComputedStyle(box.current).direction === "rtl" ? -1 : 1;
    const x0 = e.clientX;
    const w0 = widthOf(col);
    const el = e.currentTarget;
    el.setPointerCapture(e.pointerId);
    const move = (m: globalThis.PointerEvent) => resize(col, w0 + (dir * (m.clientX - x0)) / chPx);
    const up = () => {
      el.removeEventListener("pointermove", move);
      el.removeEventListener("pointerup", up);
      el.removeEventListener("pointercancel", up);
    };
    el.addEventListener("pointermove", move);
    el.addEventListener("pointerup", up);
    el.addEventListener("pointercancel", up);
  };

  // ---- keyboard --------------------------------------------------------------
  const onKeyDown = (e: KeyboardEvent<HTMLTableElement>) => {
    const target = e.target as HTMLElement;
    const cell = target.closest<HTMLElement>("[data-r]");
    if (!cell || e.defaultPrevented) return;
    const r = Number(cell.dataset.r);
    const c = Number(cell.dataset.c);
    const isSel = cell.hasAttribute("data-sel");
    if (target !== cell && !isSel) {
      // Focus is on a widget inside the cell: Escape returns to the cell, everything else belongs to the widget.
      if (e.key === "Escape") {
        e.preventDefault();
        cell.focus();
      }
      return;
    }
    const rtl = box.current ? getComputedStyle(box.current).direction === "rtl" : false;
    const page = Math.max(1, visibleRows - 1);
    const ctrl = e.ctrlKey || e.metaKey;
    const col = c - offset >= 0 ? columns[c - offset] : undefined;
    const go = (nr: number, nc: number) => {
      e.preventDefault();
      goto(nr, nc);
    };
    switch (e.key) {
      case "ArrowDown":
        return go(r + 1, c);
      case "ArrowUp":
        return go(r - 1, c);
      case "ArrowRight":
      case "ArrowLeft": {
        const forward = (e.key === "ArrowRight") !== rtl;
        if (e.shiftKey && r === 0 && resizable && col) {
          e.preventDefault();
          return resize(col, widthOf(col) + (forward ? RESIZE_STEP_CH : -RESIZE_STEP_CH));
        }
        return go(r, c + (forward ? 1 : -1));
      }
      case "Escape":
        if (onEscape) {
          e.preventDefault();
          onEscape();
        }
        return;
      case "Home":
        return go(ctrl ? 0 : r, 0);
      case "End":
        return go(ctrl ? rows.length : r, nCols - 1);
      case "PageDown":
        return go(r + page, c);
      case "PageUp":
        return go(r - page, c);
      case "a":
      case "A":
        if (ctrl && selectable) {
          e.preventDefault();
          toggleAll();
        }
        return;
      case " ":
      case "Enter": {
        if (r === 0) {
          e.preventDefault();
          if (isSel) toggleAll();
          else if (col?.sortable) onSort?.(col.key);
          return;
        }
        if (e.key === " ") {
          if (selectable) {
            e.preventDefault();
            toggleRow(r - 1, e.shiftKey);
          }
          return;
        }
        const widget = cell.querySelector<HTMLElement>(INTERACTIVE);
        if (widget && !isSel) {
          e.preventDefault();
          widget.focus();
        } else if (onRowActivate && rows[r - 1]) {
          e.preventDefault();
          onRowActivate(rows[r - 1] as Row);
        }
        return;
      }
    }
  };

  const onFocus = (e: React.FocusEvent<HTMLTableElement>) => {
    const cell = (e.target as HTMLElement).closest<HTMLElement>("[data-r]");
    if (!cell) return;
    const next = { r: Number(cell.dataset.r), c: Number(cell.dataset.c) };
    if (next.r !== active.r || next.c !== active.c) setActive(next);
    // Keyboard moves set `active` before focus lands, so "changed" is judged against the last reported row (by key,
    // so replaced rows report too). Leaving the grid forgets it (onBlur), so coming back to the same row reports again.
    const row = next.r >= 1 ? rows[next.r - 1] : undefined;
    if (row === undefined) return;
    const key = rowKey(row);
    if (key === reportedRow.current) return;
    reportedRow.current = key;
    onActiveRowChange?.(row);
  };
  const onBlur = (e: React.FocusEvent<HTMLTableElement>) => {
    if (!e.currentTarget.contains(e.relatedTarget as Node | null)) reportedRow.current = null;
  };

  const headerClick = (col: DataGridColumn<Row>) => {
    if (col.sortable) onSort?.(col.key);
  };
  const rowClick = (e: MouseEvent<HTMLElement>, idx: number) => {
    // Clicks on the checkbox cell toggle; shift extends from the last toggled row.
    toggleRow(idx, e.shiftKey);
  };

  const style = { "--diq-grid-rows": visibleRows } as CSSProperties;
  const tableW = useMemo(() => {
    const sum = columns.reduce((n, c) => n + (widths[c.key] ?? c.width ?? DEFAULT_WIDTH_CH), 0);
    return `calc(${sum}ch${selectable ? " + var(--diq-row)" : ""})`;
  }, [columns, widths, selectable]);

  return (
    <div
      ref={box}
      className={`diq-grid${selectable ? " diq-grid--selectable" : ""}`}
      style={style}
      data-busy={busy ? "true" : undefined}
      data-scrolled-x={scrolledX ? "true" : undefined}
      onScroll={(e) => {
        setTop(e.currentTarget.scrollTop);
        setScrolledX(e.currentTarget.scrollLeft !== 0);
      }}
    >
      <span ref={chProbe} className="diq-grid__ch" aria-hidden="true" />
      <table
        role="grid"
        className="diq-grid__table"
        style={{ width: tableW }}
        aria-rowcount={rows.length + 1}
        aria-colcount={nCols}
        aria-multiselectable={selectable ? true : undefined}
        aria-busy={busy ? true : undefined}
        onKeyDown={onKeyDown}
        onFocus={onFocus}
        onBlur={onBlur}
      >
        <caption className="diq-sr-only">{caption}</caption>
        <colgroup>
          {selectable ? <col className="diq-grid__col-sel" /> : null}
          {columns.map((c) => (
            <col key={c.key} style={{ width: `${widthOf(c)}ch` }} />
          ))}
        </colgroup>
        <thead>
          <tr aria-rowindex={1}>
            {selectable ? (
              <th
                scope="col"
                className="diq-grid__sel"
                data-r={0}
                data-c={0}
                data-sel=""
                tabIndex={tab(0, 0)}
                onClick={toggleAll}
              >
                <input
                  ref={allBox}
                  type="checkbox"
                  tabIndex={-1}
                  aria-label={`Select all ${rows.length.toLocaleString("en")} rows`}
                  checked={allSelected}
                  onChange={() => undefined}
                />
              </th>
            ) : null}
            {columns.map((c, i) => {
              const dir = sort?.key === c.key ? sort.dir : null;
              return (
                <th
                  key={c.key}
                  scope="col"
                  className={`diq-grid__th${c.align === "end" ? " diq-grid__end" : ""}${i === 0 && rhIndex === 0 ? " diq-grid__rh" : ""}`}
                  data-r={0}
                  data-c={i + offset}
                  data-sortable={c.sortable ? "" : undefined}
                  tabIndex={tab(0, i + offset)}
                  aria-sort={
                    c.sortable
                      ? dir === "asc"
                        ? "ascending"
                        : dir === "desc"
                          ? "descending"
                          : "none"
                      : undefined
                  }
                  onClick={() => headerClick(c)}
                >
                  <span className="diq-grid__label">{c.header}</span>
                  {c.sortable ? (
                    <span aria-hidden="true" className="diq-grid__mark">
                      {dir === "asc" ? "▲" : dir === "desc" ? "▼" : ""}
                    </span>
                  ) : null}
                  {resizable ? (
                    <span
                      aria-hidden="true"
                      className="diq-grid__resize"
                      onPointerDown={(e) => startDrag(c, e)}
                      onClick={(e) => e.stopPropagation()}
                    />
                  ) : null}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {first > 0 ? (
            <tr aria-hidden="true" style={{ height: first * rowH }}>
              <td colSpan={nCols} className="diq-grid__spacer" />
            </tr>
          ) : null}
          {slice.map((row, k) => {
            const idx = first + k;
            const r = idx + 1;
            const key = rowKey(row);
            const isSel = sel.has(key);
            const label =
              textOf(columns[rhIndex]?.cell(row)) ?? columns[rhIndex]?.title?.(row) ?? `row ${r}`;
            return (
              <tr
                key={key}
                data-row={r}
                aria-rowindex={r + 1}
                aria-selected={selectable ? isSel : undefined}
                aria-current={idx === currentIdx ? "true" : undefined}
                className={
                  [
                    isSel ? "diq-grid__row--selected" : "",
                    idx === currentIdx ? "diq-grid__row--current" : "",
                  ]
                    .filter(Boolean)
                    .join(" ") || undefined
                }
                style={{ height: rowH }}
              >
                {selectable ? (
                  <td
                    className="diq-grid__sel"
                    data-r={r}
                    data-c={0}
                    data-sel=""
                    tabIndex={tab(r, 0)}
                    onClick={(e) => rowClick(e, idx)}
                  >
                    <input
                      type="checkbox"
                      tabIndex={-1}
                      aria-label={`Select ${label}`}
                      checked={isSel}
                      onChange={() => undefined}
                    />
                  </td>
                ) : null}
                {columns.map((c, i) => {
                  const body = c.cell(row);
                  const props = {
                    "data-r": r,
                    "data-c": i + offset,
                    tabIndex: tab(r, i + offset),
                    className: `diq-grid__cell${c.mono ? " diq-mono" : ""}${c.align === "end" ? " diq-grid__end" : ""}${i === 0 && rhIndex === 0 ? " diq-grid__rh" : ""}`,
                    title: c.title?.(row) ?? textOf(body),
                  };
                  return i === rhIndex ? (
                    <th key={c.key} scope="row" {...props}>
                      {body}
                    </th>
                  ) : (
                    <td key={c.key} {...props}>
                      {body}
                    </td>
                  );
                })}
              </tr>
            );
          })}
          {last < rows.length ? (
            <tr aria-hidden="true" style={{ height: (rows.length - last) * rowH }}>
              <td colSpan={nCols} className="diq-grid__spacer" />
            </tr>
          ) : null}
        </tbody>
      </table>
      {rows.length === 0 && empty ? <div className="diq-grid__empty">{empty}</div> : null}
      <div className="diq-sr-only" role="status" aria-live="polite">
        {announce}
      </div>
    </div>
  );
}

const EMPTY: ReadonlySet<string> = new Set();
