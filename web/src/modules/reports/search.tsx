import { type KeyboardEvent, useEffect, useId, useState } from "react";

import { navigate } from "../../app/location";
import { Button, Kbd, Popover, Skeleton, TextInput } from "../../ds/components";
import type { ApiClient } from "./api";
import { type Hit, hitHref, searchHits } from "./model";
import { useDefinitions } from "./use-definitions";

/** How long typing must pause before the search is sent. */
export const SEARCH_DEBOUNCE_MS = 200;

const isTyping = (el: EventTarget | null) =>
  el instanceof HTMLElement &&
  (el.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName));

/**
 * The `/` search (spec §5 Flow A, FR-02): report names, ManageEngine names and categories. `/` opens
 * it anywhere on the reports screens except while typing in a field; Enter opens the first hit with
 * its preset and the report runs at once. The server does the matching (`q`); the hits are only
 * arranged here.
 */
export function ReportSearch({ client }: { readonly client: ApiClient }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [sent, setSent] = useState("");
  const [active, setActive] = useState(0);
  const [pending, setPending] = useState(false);
  const listId = useId();

  const trimmed = text.trim();
  const { state, retry } = useDefinitions(client, { q: sent, category: "" }, open && sent !== "");

  // The shortcut: not while typing, not with a modifier.
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented) return;
      if (isTyping(e.target)) return;
      e.preventDefault();
      setOpen(true);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  // Debounce: send the search once typing pauses.
  useEffect(() => {
    if (trimmed === sent) return;
    const t = setTimeout(() => setSent(trimmed), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [trimmed, sent]);

  const answered = state.status === "ready" && state.query === sent && sent === trimmed;
  const { hits } = answered ? searchHits(state.items, sent) : { hits: [] as Hit[] };

  const go = (hit: Hit) => {
    setOpen(false);
    setText("");
    setSent("");
    setPending(false);
    navigate(hitHref(hit));
  };

  // Enter before the answer is in: open the first hit as soon as it is.
  useEffect(() => {
    if (!pending || !answered) return;
    setPending(false);
    const first = hits[0];
    if (first) go(first);
  }, [pending, answered]);

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.nativeEvent.isComposing) return;
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      if (hits.length === 0) return;
      e.preventDefault();
      setActive((i) => (i + (e.key === "ArrowDown" ? 1 : -1) + hits.length) % hits.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (trimmed === "") return;
      const hit = hits[active];
      if (answered && hit) go(hit);
      else {
        setSent(trimmed); // do not wait for the pause
        setPending(true);
      }
    }
  };

  let body;
  if (trimmed === "") {
    body = (
      <p className="diq-hint">Type a report name, a ManageEngine report name or a category.</p>
    );
  } else if (state.status === "failed" && sent !== "") {
    const forbidden = state.failure.kind === "forbidden";
    body = (
      <div role={forbidden ? undefined : "alert"} className="rp-search__note">
        <p className="rp-search__title">{state.failure.title}</p>
        <p>{forbidden ? "No reports are available to your role." : state.failure.detail}</p>
        {!forbidden && <Button onClick={retry}>Retry</Button>}
      </div>
    );
  } else if (!answered) {
    body = <Skeleton rows={3} label="Searching reports" />;
  } else if (hits.length === 0) {
    body = (
      <div className="rp-search__note" role="status">
        <p className="rp-search__title">Nothing matches “{sent}”</p>
        <p>
          Search checks report names, ManageEngine report names and categories; try fewer letters.
        </p>
      </div>
    );
  } else {
    body = (
      <ul id={listId} role="listbox" aria-label="Reports" className="rp-search__list">
        {hits.map((h, i) => (
          <li
            key={h.key}
            id={`${listId}-${i}`}
            role="option"
            aria-selected={i === active}
            className="rp-search__hit"
            onMouseEnter={() => setActive(i)}
            onClick={() => go(h)}
          >
            <span className="rp-search__label">{h.label}</span>
            <span className="rp-search__sub">{h.sub}</span>
          </li>
        ))}
      </ul>
    );
  }

  return (
    <Popover
      label="Search reports"
      align="end"
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) setPending(false);
      }}
      trigger={(p) => (
        <Button {...p}>
          Search reports <Kbd>/</Kbd>
        </Button>
      )}
    >
      <div className="rp-search">
        <TextInput
          label="Search reports"
          role="combobox"
          aria-expanded={hits.length > 0}
          aria-controls={listId}
          aria-activedescendant={hits.length > 0 ? `${listId}-${active}` : undefined}
          aria-autocomplete="list"
          autoComplete="off"
          spellCheck={false}
          data-autofocus=""
          placeholder="Report name, ManageEngine name or category"
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setActive(0);
          }}
          onKeyDown={onKeyDown}
        />
        {body}
      </div>
    </Popover>
  );
}
