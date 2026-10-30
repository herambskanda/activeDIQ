import { type ReactNode, useEffect, useRef, useState } from "react";

import type { Cell, Row } from "./fixtures";

export interface Col {
  readonly key: string;
  readonly header: string;
}
export interface Sort {
  readonly key: string;
  readonly dir: "asc" | "desc";
}

const OVERSCAN = 6;

function widthFor(key: string): string {
  if (key === "name" || key === "member" || key === "user") return "15rem";
  if (key === "group") return "9rem";
  if (key.includes("ou-path") || key === "path") return "11.5rem";
  if (key === "via") return "15rem";
  if (key === "domain" || key === "upn" || key === "dns-name" || key === "e-mail") return "10rem";
  if (key.startsWith("days") || key === "users" || key === "computers" || key === "groups")
    return "6.5rem";
  if (key === "status" || key === "membership-kind" || key === "member-type") return "9rem";
  if (key === "probable-service-account") return "13rem";
  return "9.5rem";
}

/**
 * A read-only, windowed table for a run's stored result. Only the rows in view are in the DOM, so
 * 12,000 rows cost the same as 40. Sorting is reported up (the server sorts); there is no row
 * selection at 2a (FR-13).
 */
export function Grid(props: {
  readonly caption: string;
  readonly columns: readonly Col[];
  readonly rows: readonly Row[];
  readonly sort: Sort | null;
  readonly onSort: (key: string) => void;
  readonly render: (col: string, value: Cell | undefined, row: Row) => ReactNode;
  readonly busy?: boolean;
}) {
  const { caption, columns, rows, sort, onSort, render, busy } = props;
  const box = useRef<HTMLDivElement>(null);
  const [top, setTop] = useState(0);
  const [h, setH] = useState(480);
  const [rowH, setRowH] = useState(32);

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const px = parseFloat(getComputedStyle(el).getPropertyValue("--diq-row"));
    if (Number.isFinite(px) && px > 0) setRowH(px);
    setH(el.clientHeight);
  }, []);
  useEffect(() => {
    if (box.current) box.current.scrollTop = 0;
    setTop(0);
  }, [rows]);

  const start = Math.max(0, Math.floor(top / rowH) - OVERSCAN);
  const end = Math.min(rows.length, Math.ceil((top + h) / rowH) + OVERSCAN);
  const slice = rows.slice(start, end);

  return (
    <div
      ref={box}
      className="rp__scroll"
      tabIndex={0}
      role="region"
      aria-label={`${caption}, scrollable`}
      aria-busy={busy ? true : undefined}
      onScroll={(e) => setTop(e.currentTarget.scrollTop)}
    >
      <table className="rp__grid" aria-rowcount={rows.length + 1}>
        <caption className="rp__sr">{caption}</caption>
        <colgroup>
          {columns.map((c) => (
            <col key={c.key} style={{ width: widthFor(c.key) }} />
          ))}
        </colgroup>
        <thead>
          <tr aria-rowindex={1}>
            {columns.map((c) => (
              <th
                key={c.key}
                scope="col"
                aria-sort={
                  sort?.key === c.key ? (sort.dir === "asc" ? "ascending" : "descending") : "none"
                }
              >
                <button type="button" className="rp__th" onClick={() => onSort(c.key)}>
                  {c.header}
                  <span aria-hidden="true" className="rp__sortmark">
                    {sort?.key === c.key ? (sort.dir === "asc" ? "▲" : "▼") : ""}
                  </span>
                </button>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {start > 0 ? (
            <tr aria-hidden="true" style={{ height: start * rowH }}>
              <td colSpan={columns.length} className="rp__spacer" />
            </tr>
          ) : null}
          {slice.map((r, i) => (
            <tr key={r.key} aria-rowindex={start + i + 2} style={{ height: rowH }}>
              {columns.map((c, ci) => {
                const v = r.cells[c.key];
                const text = v === undefined ? "" : String(v);
                const body = render(c.key, v, r);
                return ci === 0 ? (
                  <th key={c.key} scope="row" className="rp__cell rp__rowhead" title={text}>
                    {body}
                  </th>
                ) : (
                  <td key={c.key} className="rp__cell" title={text}>
                    {body}
                  </td>
                );
              })}
            </tr>
          ))}
          {end < rows.length ? (
            <tr aria-hidden="true" style={{ height: (rows.length - end) * rowH }}>
              <td colSpan={columns.length} className="rp__spacer" />
            </tr>
          ) : null}
        </tbody>
      </table>
    </div>
  );
}
