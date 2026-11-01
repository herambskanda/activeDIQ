import {
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";

import { Button } from "./button";
import { Chip, type ChipTone } from "./chip";
import { Kbd } from "./kbd";
import { useModalLayer } from "./modal-layer";
import { tabbables } from "./popover";
import { Skeleton } from "./skeleton";
import { StatePanel } from "./state-panel";

/** A status chip on a result row. The label always says the state in words. */
export interface PaletteChip {
  readonly tone: ChipTone;
  readonly label: string;
}

/**
 * One row. Everything is plain text: names, identifiers and DNs come from a directory and are
 * rendered as text nodes, never as markup.
 */
export interface PaletteItem {
  readonly id: string;
  /** "User", "Group", "Report", "Action"... */
  readonly typeTag: string;
  /** The display name; the query's words are highlighted in it. */
  readonly name: string;
  /** sAMAccountName · UPN or e-mail, shown in mono. */
  readonly identifier?: string;
  readonly chips?: readonly PaletteChip[];
  /** Title · office or department: what tells two people with one name apart. */
  readonly disambiguator?: string;
  /** Shown truncated in the middle; the full value is the tooltip and shows on the highlighted row. */
  readonly dn?: string;
  /** Only when the account sees more than one domain. */
  readonly domain?: string;
  /** Visible but not runnable, e.g. an action blocked for this object. Say why in `disabledReason`. */
  readonly disabled?: boolean;
  readonly disabledReason?: string;
  /** Right arrow calls `onExpand` for this row. */
  readonly expandable?: boolean;
}

export interface PaletteGroup {
  readonly id: string;
  /** The group's heading and its accessible name. */
  readonly label: string;
  readonly items: readonly PaletteItem[];
  /** The full count in scope. When it exceeds `items` and `onShowAll` is set, a "Show all N" row ends the group. */
  readonly total?: number;
}

/**
 * `idle`: empty query, `groups` are recent and suggested items. `loading`: a search is in flight.
 * `results`: `groups` answer the query (none at all is "no results"). `error`: the search failed.
 * `denied`: the account may not search; the input is read-only.
 */
export type PaletteStatus = "idle" | "loading" | "results" | "error" | "denied";

export interface PaletteNotice {
  readonly title: string;
  readonly body?: ReactNode;
  /** Extra actions (links or Buttons) under the body. They join the Tab cycle. */
  readonly actions?: ReactNode;
}

export interface CommandPaletteProps {
  readonly open: boolean;
  /** Escape and a click on the scrim call this. Focus returns to the opener. */
  readonly onClose: () => void;
  /** Controlled. The caller debounces and fetches; the palette only reports typing. */
  readonly query: string;
  readonly onQueryChange: (query: string) => void;
  readonly status: PaletteStatus;
  readonly groups: readonly PaletteGroup[];
  /** Enter or a click on a row that is not disabled. The caller closes the palette if it navigates. */
  readonly onSelect: (item: PaletteItem) => void;
  /** Right arrow (caret at the end of the text) on an `expandable` row. */
  readonly onExpand?: (item: PaletteItem) => void;
  /** Enter or a click on a group's "Show all N" row. */
  readonly onShowAll?: (group: PaletteGroup) => void;
  /** Overrides the built-in text for no results, error and denied. */
  readonly notice?: PaletteNotice;
  /** Adds a "Try again" button to the error state. */
  readonly onRetry?: () => void;
  /** Left of the key hints: "index as of 1 min ago", a stale-index warning. */
  readonly footer?: ReactNode;
  /** The dialog's name. */
  readonly label?: string;
  readonly placeholder?: string;
  /** Milliseconds typing must pause, with results unchanged, before the count is announced. */
  readonly announceDelay?: number;
  /** Builds the polite announcement for a result set. Defaults to English "N results, M groups". */
  readonly announce?: (counts: { readonly results: number; readonly groups: number }) => string;
}

// ---- Pure helpers (exported for tests) --------------------------------------------------------

/**
 * Character ranges of `text` that match any word of `query`, case-insensitively, merged. Words are
 * split on whitespace and commas ("Smith, Jo"). Plain substring search: the query is never
 * compiled into a pattern.
 */
export function highlightRanges(text: string, query: string): Array<readonly [number, number]> {
  const words = [
    ...new Set(
      query
        .toLowerCase()
        .split(/[\s,]+/)
        .filter(Boolean),
    ),
  ];
  const hay = text.toLowerCase();
  // Case folding that changes the length (e.g. "İ") would shift every offset: skip the highlight.
  if (words.length === 0 || hay.length !== text.length) return [];
  const found: Array<[number, number]> = [];
  for (const w of words) {
    for (let at = hay.indexOf(w); at >= 0; at = hay.indexOf(w, at + w.length)) {
      found.push([at, at + w.length]);
    }
  }
  found.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const merged: Array<[number, number]> = [];
  for (const r of found) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]);
    else merged.push([r[0], r[1]]);
  }
  return merged;
}

/** Shortens to at most `max` characters by replacing the middle with an ellipsis (code-point safe). */
export function truncateMiddle(text: string, max: number): string {
  const chars = Array.from(text);
  if (chars.length <= max) return text;
  const keep = Math.max(2, max - 1);
  const head = Math.ceil(keep / 2);
  const tail = keep - head;
  return `${chars.slice(0, head).join("")}…${chars.slice(chars.length - tail).join("")}`;
}

/** The default polite announcement: "12 results, 3 groups"; "No results" when empty. */
export function resultsAnnouncement(counts: {
  readonly results: number;
  readonly groups: number;
}): string {
  if (counts.results === 0) return "No results";
  const r = counts.results === 1 ? "1 result" : `${counts.results} results`;
  const g = counts.groups === 1 ? "1 group" : `${counts.groups} groups`;
  return `${r}, ${g}`;
}

const DN_MAX = 56;

// ---- Shortcut ---------------------------------------------------------------------------------

function isEditable(t: EventTarget | null): boolean {
  if (!(t instanceof HTMLElement)) return false;
  return t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName);
}

/**
 * Calls `onOpen` for Ctrl/⌘+K anywhere and for `/` when focus is not in a field. Bind it once, in
 * the shell that owns the palette's open state. Pass `enabled: false` while the palette is open.
 */
export function usePaletteShortcut(onOpen: () => void, enabled = true): void {
  const latest = useRef(onOpen);
  latest.current = onOpen;
  useEffect(() => {
    if (!enabled) return;
    const handler = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.isComposing) return;
      const mod = (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey;
      const k = e.key.toLowerCase();
      if (
        (mod && k === "k") ||
        (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey && !isEditable(e.target))
      ) {
        e.preventDefault();
        latest.current();
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [enabled]);
}

// ---- Component --------------------------------------------------------------------------------

interface Entry {
  readonly key: string;
  readonly group: PaletteGroup;
  /** Absent on a group's "Show all N" row. */
  readonly item?: PaletteItem;
}

/**
 * The command palette: one overlay that finds objects, pages and actions. A modal `dialog` holding
 * an ARIA 1.2 combobox (the input) over a grouped listbox. It is presentational: the caller owns
 * the query, fetches, and passes `status` and `groups`; it fetches and routes nothing itself.
 *
 * Keys: Up/Down move the highlight (wrapping), Home/End jump to the first/last row, Enter runs the
 * highlighted row, Right (caret at the end) calls `onExpand`, Escape closes. Focus never leaves the
 * input: the highlight is `aria-activedescendant`. Tab cycles only inside the dialog (it has no
 * other stop unless the error notice carries a button). Not for choosing from a short fixed list
 * (use `Select` or `PopoverMenu`) or picking directory objects into a form field (use `TokenInput`).
 */
export function CommandPalette(props: CommandPaletteProps) {
  return props.open ? <Palette {...props} /> : null;
}

function Palette({
  onClose,
  query,
  onQueryChange,
  status,
  groups,
  onSelect,
  onExpand,
  onShowAll,
  notice,
  onRetry,
  footer,
  label = "Search",
  placeholder = "Search people, groups, computers, reports and actions",
  announceDelay = 400,
  announce = resultsAnnouncement,
}: CommandPaletteProps) {
  const uid = useId();
  const scrim = useRef<HTMLDivElement>(null);
  const dialog = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const pressedOnScrim = useRef(false);
  useModalLayer(scrim, dialog, () => input.current);

  const showList = status === "idle" || status === "results";
  const entries = useMemo<Entry[]>(() => {
    if (!showList) return [];
    const out: Entry[] = [];
    for (const group of groups) {
      for (const item of group.items) out.push({ key: `i:${group.id}:${item.id}`, group, item });
      if (onShowAll && group.total !== undefined && group.total > group.items.length) {
        out.push({ key: `a:${group.id}`, group });
      }
    }
    return out;
  }, [showList, groups, onShowAll]);
  const itemCount = entries.filter((e) => e.item).length;
  const groupCount = groups.filter((g) => g.items.length > 0).length;
  const hasOptions = entries.length > 0;

  const [activeKey, setActiveKey] = useState<string | null>(null);
  const active =
    entries.find((e) => e.key === activeKey) ??
    entries.find((e) => !e.item?.disabled) ??
    entries[0];
  const domId = (e: Entry) => `${uid}-o${entries.indexOf(e)}`;
  const activeDomId = active ? domId(active) : undefined;

  useEffect(() => {
    if (activeDomId) document.getElementById(activeDomId)?.scrollIntoView?.({ block: "nearest" });
  }, [activeDomId]);

  // Polite announcement once the result set has settled: typing restarts the clock, and the text
  // is cleared first so an identical count after a new search is announced again.
  const [spoken, setSpoken] = useState("");
  const message = status === "results" ? announce({ results: itemCount, groups: groupCount }) : "";
  useEffect(() => {
    setSpoken("");
    if (!message) return;
    const t = setTimeout(() => setSpoken(message), announceDelay);
    return () => clearTimeout(t);
  }, [message, announceDelay, query]);

  const run = (e: Entry | undefined) => {
    if (!e) return;
    if (!e.item) onShowAll?.(e.group);
    else if (!e.item.disabled) onSelect(e.item);
  };
  const move = (to: "next" | "prev" | "first" | "last") => {
    if (entries.length === 0) return;
    const at = active ? entries.indexOf(active) : -1;
    const n = entries.length;
    const i =
      to === "first" ? 0 : to === "last" ? n - 1 : to === "next" ? (at + 1) % n : (at - 1 + n) % n;
    const next = entries[i];
    if (next) setActiveKey(next.key);
  };

  const onInputKeyDown = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.nativeEvent.isComposing || e.ctrlKey || e.metaKey || e.altKey) return;
    let handled = true;
    switch (e.key) {
      case "ArrowDown":
        move("next");
        break;
      case "ArrowUp":
        move("prev");
        break;
      case "Home":
        if (hasOptions) move("first");
        else handled = false;
        break;
      case "End":
        if (hasOptions) move("last");
        else handled = false;
        break;
      case "Enter":
        run(active);
        break;
      case "ArrowRight": {
        const el = e.currentTarget;
        const atEnd = el.selectionStart === el.value.length && el.selectionEnd === el.value.length;
        if (atEnd && active?.item?.expandable && onExpand) onExpand(active.item);
        else handled = false;
        break;
      }
      default:
        handled = false;
    }
    if (handled) e.preventDefault();
  };

  const denied = status === "denied";
  const defaultNotice: PaletteNotice | null =
    status === "results" && !hasOptions
      ? {
          title: query.trim() ? `No results for “${query.trim()}”` : "No results",
        }
      : status === "error"
        ? { title: "Search failed" }
        : denied
          ? { title: "Search is not available to your account" }
          : null;
  const shownNotice = defaultNotice ? (notice ?? defaultNotice) : null;

  return createPortal(
    <div
      ref={scrim}
      className="diq-pal__scrim"
      onMouseDown={(e) => {
        pressedOnScrim.current = e.target === e.currentTarget;
      }}
      onClick={(e) => {
        const pressed = pressedOnScrim.current;
        pressedOnScrim.current = false;
        if (pressed && e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={dialog}
        className="diq-pal"
        role="dialog"
        aria-modal="true"
        aria-label={label}
        tabIndex={-1}
        onKeyDown={(e) => {
          if (e.nativeEvent.isComposing) return;
          if (e.key === "Escape" && !e.defaultPrevented) {
            e.stopPropagation();
            onClose();
          } else if (e.key === "Tab" && dialog.current) {
            // Tab cycles inside the dialog; with only the input, it stays there.
            const items = tabbables(dialog.current);
            const first = items[0];
            const last = items[items.length - 1];
            const at = document.activeElement;
            if (!first || !last || first === last) {
              e.preventDefault();
              (first ?? dialog.current).focus();
            } else if (e.shiftKey && at === first) {
              e.preventDefault();
              last.focus();
            } else if (!e.shiftKey && at === last) {
              e.preventDefault();
              first.focus();
            }
          }
        }}
      >
        <input
          ref={input}
          className="diq-pal__input"
          type="text"
          role="combobox"
          aria-label={label}
          aria-autocomplete="list"
          aria-haspopup="listbox"
          aria-expanded={hasOptions}
          aria-controls={hasOptions ? `${uid}-list` : undefined}
          aria-activedescendant={hasOptions ? activeDomId : undefined}
          aria-disabled={denied || undefined}
          readOnly={denied}
          autoComplete="off"
          spellCheck={false}
          placeholder={placeholder}
          value={query}
          data-autofocus=""
          onChange={(e) => {
            setActiveKey(null);
            onQueryChange(e.target.value);
          }}
          onKeyDown={onInputKeyDown}
        />

        <div className="diq-pal__body">
          {status === "loading" ? <Skeleton rows={4} label="Searching" /> : null}
          {shownNotice ? (
            <StatePanel
              tone={status === "error" ? "error" : "neutral"}
              title={shownNotice.title}
              actions={
                shownNotice.actions || (status === "error" && onRetry) ? (
                  <>
                    {status === "error" && onRetry ? (
                      <Button onClick={onRetry}>Try again</Button>
                    ) : null}
                    {shownNotice.actions}
                  </>
                ) : undefined
              }
            >
              {shownNotice.body}
            </StatePanel>
          ) : null}
          {hasOptions ? (
            <div id={`${uid}-list`} className="diq-pal__list" role="listbox" aria-label={label}>
              {groups.map((g) => {
                const rows = entries.filter((e) => e.group === g);
                if (rows.length === 0) return null;
                return (
                  <div key={g.id} role="group" aria-labelledby={`${uid}-g-${g.id}`}>
                    <div id={`${uid}-g-${g.id}`} role="presentation" className="diq-pal__gh">
                      {g.label}
                      {g.total !== undefined ? (
                        <span className="diq-pal__count">{g.total}</span>
                      ) : null}
                    </div>
                    {rows.map((e) => (
                      <Option
                        key={e.key}
                        id={domId(e)}
                        entry={e}
                        query={status === "results" ? query : ""}
                        active={e === active}
                        onHover={() => setActiveKey(e.key)}
                        onRun={() => {
                          run(e);
                          input.current?.focus();
                        }}
                      />
                    ))}
                  </div>
                );
              })}
            </div>
          ) : null}
        </div>

        <div className="diq-pal__foot">
          {footer ? <div className="diq-pal__note">{footer}</div> : <span />}
          <div className="diq-pal__keys">
            <span>
              <Kbd>↑</Kbd> <Kbd>↓</Kbd> move
            </span>
            <span>
              <Kbd>↵</Kbd> open
            </span>
            {onExpand ? (
              <span>
                <Kbd>→</Kbd> actions
              </span>
            ) : null}
            <span>
              <Kbd>Esc</Kbd> close
            </span>
          </div>
        </div>

        <div className="diq-sr-only" role="status" aria-live="polite" aria-atomic="true">
          {spoken}
        </div>
      </div>
    </div>,
    document.body,
  );
}

function Highlighted({ text, query }: { readonly text: string; readonly query: string }) {
  const ranges = highlightRanges(text, query);
  if (ranges.length === 0) return <>{text}</>;
  const parts: ReactNode[] = [];
  let at = 0;
  ranges.forEach(([s, e], i) => {
    if (s > at) parts.push(text.slice(at, s));
    parts.push(
      <mark key={i} className="diq-pal__mark">
        {text.slice(s, e)}
      </mark>,
    );
    at = e;
  });
  if (at < text.length) parts.push(text.slice(at));
  return <>{parts}</>;
}

function Option({
  id,
  entry,
  query,
  active,
  onHover,
  onRun,
}: {
  readonly id: string;
  readonly entry: Entry;
  readonly query: string;
  readonly active: boolean;
  readonly onHover: () => void;
  readonly onRun: () => void;
}) {
  const { item, group } = entry;
  const common = {
    id,
    role: "option",
    "aria-selected": active,
    // Keep focus in the input: a press on a row must not move it.
    onMouseDown: (e: React.MouseEvent) => e.preventDefault(),
    onMouseMove: onHover,
    onClick: onRun,
  } as const;

  if (!item) {
    return (
      <div {...common} className="diq-pal__opt diq-pal__opt--all" data-active={active || undefined}>
        Show all {group.total}
        <span className="diq-sr-only"> {group.label}</span>
      </div>
    );
  }
  return (
    <div
      {...common}
      aria-disabled={item.disabled || undefined}
      className="diq-pal__opt"
      data-active={active || undefined}
    >
      <div className="diq-pal__l1">
        <span className="diq-pal__tag">{item.typeTag}</span>
        <span className="diq-pal__name">
          <Highlighted text={item.name} query={query} />
        </span>
        {item.chips && item.chips.length > 0 ? (
          <span className="diq-pal__chips">
            {item.chips.map((c) => (
              <Chip key={c.label} tone={c.tone}>
                {c.label}
              </Chip>
            ))}
          </span>
        ) : null}
      </div>
      {item.identifier || item.disambiguator ? (
        <div className="diq-pal__l2">
          {item.identifier ? (
            <span className="diq-pal__ident">
              <Highlighted text={item.identifier} query={query} />
            </span>
          ) : null}
          {item.disambiguator ? <span className="diq-pal__dis">{item.disambiguator}</span> : null}
        </div>
      ) : null}
      {item.dn || item.domain ? (
        <div className="diq-pal__l3">
          {item.dn ? (
            <span className="diq-pal__dn" title={item.dn}>
              {active || Array.from(item.dn).length <= DN_MAX ? (
                item.dn
              ) : (
                <>
                  <span aria-hidden="true">{truncateMiddle(item.dn, DN_MAX)}</span>
                  <span className="diq-sr-only">{item.dn}</span>
                </>
              )}
            </span>
          ) : null}
          {item.domain ? <span className="diq-pal__domain">{item.domain}</span> : null}
        </div>
      ) : null}
      {item.disabled && item.disabledReason ? (
        <div className="diq-pal__why">{item.disabledReason}</div>
      ) : null}
    </div>
  );
}
