import type { ReactNode } from "react";

export interface Column<Row> {
  readonly key: string;
  readonly header: string;
  /** The first column's cells render as row headers (th scope=row). */
  readonly rowHeader?: boolean;
  readonly mono?: boolean;
  /** Long prose (reasons, details): wrap instead of truncating. Use sparingly; truncation is the default. */
  readonly wrap?: boolean;
  readonly cell: (row: Row) => ReactNode;
  /** Plain text for the cell's title when the content is truncated. */
  readonly title?: (row: Row) => string;
}

export interface TableProps<Row> {
  /** Accessible name; visually hidden. */
  readonly caption: string;
  readonly columns: readonly Column<Row>[];
  readonly rows: readonly Row[];
  readonly rowKey: (row: Row) => string;
}

/** A read-only data table: sticky header, density from --diq-row, truncation with the full text in a title. */
export function Table<Row>({ caption, columns, rows, rowKey }: TableProps<Row>) {
  return (
    <div className="diq-table-wrap">
      <table className="diq-table">
        <caption className="diq-sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col">
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={rowKey(r)}>
              {columns.map((c) => {
                const props = {
                  className:
                    [c.mono ? "diq-mono" : "", c.wrap ? "diq-table__wrap" : ""]
                      .filter(Boolean)
                      .join(" ") || undefined,
                  title: c.title?.(r),
                };
                return c.rowHeader ? (
                  <th key={c.key} scope="row" {...props}>
                    {c.cell(r)}
                  </th>
                ) : (
                  <td key={c.key} {...props}>
                    {c.cell(r)}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
