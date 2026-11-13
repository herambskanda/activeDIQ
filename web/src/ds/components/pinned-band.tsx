import { type ReactNode, useId, useState } from "react";

export type PinnedBandTone = "crit" | "warn" | "info";

const GLYPH: Record<PinnedBandTone, string> = { crit: "✕", warn: "⚠", info: "ⓘ" };
const DEFAULT_LIMIT = 4;

export interface PinnedBandProps<Item> {
  /** What is pinned, with its count: "Did not answer (3)". It names the group for assistive technology. */
  readonly label: string;
  /** Why it is pinned, one line: "a blind spot matters more than any row below". */
  readonly note?: ReactNode | undefined;
  readonly tone?: PinnedBandTone | undefined;
  readonly items: readonly Item[];
  readonly itemKey: (item: Item) => string;
  readonly children: (item: Item) => ReactNode;
  /** Items shown before "Show all" (default 4). */
  readonly limit?: number | undefined;
  /** Label of the expand button; receives the number hidden. Default "Show N more". */
  readonly moreLabel?: ((hidden: number) => string) | undefined;
  readonly lessLabel?: string | undefined;
}

/**
 * A band above a `DataGrid` for rows that must not be sorted among the others, such as the blind
 * spots of a report ("Did not answer (3)"). It is outside the grid, so it is never sorted, filtered
 * away by the grid's scroll or virtualised. Nothing here is a row of the grid: items are free
 * content (compose them with `diq-pinned__cell` spans or your own layout). Renders nothing when
 * `items` is empty, because an empty "Did not answer (0)" is noise.
 *
 * It is a `group`, not `role=rowgroup`: ARIA requires a rowgroup to live inside a table or grid.
 */
export function PinnedBand<Item>(props: PinnedBandProps<Item>) {
  const {
    label,
    note,
    tone = "crit",
    items,
    itemKey,
    children,
    limit = DEFAULT_LIMIT,
    moreLabel = (n) => `Show ${n.toLocaleString("en")} more`,
    lessLabel = "Show fewer",
  } = props;
  const uid = useId();
  const [open, setOpen] = useState(false);
  if (items.length === 0) return null;
  const hidden = Math.max(0, items.length - limit);
  const shown = open ? items : items.slice(0, limit);
  return (
    <div className={`diq-pinned diq-pinned--${tone}`} role="group" aria-labelledby={`${uid}-l`}>
      <div className="diq-pinned__head">
        <span aria-hidden="true" className="diq-pinned__glyph">
          {GLYPH[tone]}
        </span>
        <span id={`${uid}-l`} className="diq-pinned__label">
          {label}
        </span>
        {note ? <span className="diq-pinned__note">{note}</span> : null}
      </div>
      <ul
        className="diq-pinned__list"
        id={`${uid}-list`}
        // Expanded, the list may scroll: a scroll box has to be reachable by keyboard.
        tabIndex={open && hidden > 0 ? 0 : undefined}
        aria-label={open && hidden > 0 ? label : undefined}
      >
        {shown.map((item) => (
          <li key={itemKey(item)} className="diq-pinned__item">
            {children(item)}
          </li>
        ))}
      </ul>
      {hidden > 0 ? (
        <button
          type="button"
          className="diq-pinned__more"
          aria-expanded={open}
          aria-controls={`${uid}-list`}
          onClick={() => setOpen((o) => !o)}
        >
          {open ? lessLabel : moreLabel(hidden)}
        </button>
      ) : null}
    </div>
  );
}
