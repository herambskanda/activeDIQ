import { useEffect, useMemo, useRef, useState } from "react";

import { type Token, TokenInput, type TokenInputProps } from "./token-input";

/** One directory object offered by a search. */
export interface PickerObject {
  /** The objectGUID: the key. A name or DN is never the identity. */
  readonly id: string;
  readonly name: string;
  /** sAMAccountName · UPN or e-mail. */
  readonly identifier?: string;
  /** The DN or OU path; what tells two "J. Smith" apart. */
  readonly path?: string;
  readonly domain?: string;
  readonly enabled?: boolean;
}

/** What a search answers. `refine`: the text is too broad to rank; `more`: there are more than `items`. */
export interface PickerAnswer {
  readonly items: readonly PickerObject[];
  readonly more?: boolean;
  readonly refine?: boolean;
}

export interface ObjectPickerProps extends Pick<
  TokenInputProps,
  "label" | "disabled" | "readOnly" | "error" | "className"
> {
  /** What is being picked, in the singular and lower case: "group", "user". Used in the messages. */
  readonly kind: string;
  readonly value: readonly PickerObject[];
  readonly onChange: (value: readonly PickerObject[]) => void;
  /** Asks the server. Abort the request when `signal` aborts; throw to show the error. */
  readonly search: (text: string, signal: AbortSignal) => Promise<PickerAnswer>;
  /** The most objects that may be chosen. Past it, the field refuses more and says so. */
  readonly max?: number;
  /** Quiet period after typing before the search is sent. */
  readonly debounceMs?: number;
  readonly hint?: string;
}

export const PICKER_DEBOUNCE_MS = 200;

const MIN_CHARS = 2;

const toToken = (o: PickerObject): Token => {
  const detail = [o.identifier, o.path, o.domain].filter(Boolean).join(" · ");
  return {
    id: o.id,
    label: o.name,
    ...(detail ? { detail } : {}),
    ...(o.enabled === false ? { badge: "Disabled" } : {}),
  };
};

type Remote =
  | { readonly status: "idle" }
  | { readonly status: "loading" }
  | { readonly status: "error" }
  | { readonly status: "answer"; readonly text: string; readonly answer: PickerAnswer };

/**
 * Picks directory objects (groups, users) by searching on the server, so it works against a directory
 * of 150,000 objects: nothing is loaded up front and only the best matches come back. Typing waits
 * for a pause, an answer to older text is dropped, and the options show the name, the logon name or
 * e-mail, the OU path and an Disabled badge so the right "J. Smith" can be told from the wrong one.
 * Built on TokenInput (ARIA combobox, tokens with their own Remove buttons).
 * Not for a short fixed list (Select).
 */
export function ObjectPicker({
  kind,
  value,
  onChange,
  search,
  max,
  debounceMs = PICKER_DEBOUNCE_MS,
  hint,
  error,
  ...rest
}: ObjectPickerProps) {
  const [text, setText] = useState("");
  const [remote, setRemote] = useState<Remote>({ status: "idle" });
  const searchRef = useRef(search);
  searchRef.current = search;
  const trimmed = text.trim();
  const full = max !== undefined && value.length >= max;

  useEffect(() => {
    if (trimmed.length < MIN_CHARS || full) {
      setRemote({ status: "idle" });
      return;
    }
    setRemote({ status: "loading" });
    const c = new AbortController();
    const t = setTimeout(() => {
      searchRef.current(trimmed, c.signal).then(
        (answer) => !c.signal.aborted && setRemote({ status: "answer", text: trimmed, answer }),
        () => !c.signal.aborted && setRemote({ status: "error" }),
      );
    }, debounceMs);
    return () => {
      clearTimeout(t);
      c.abort();
    };
  }, [trimmed, debounceMs, full]);

  const objects = useMemo(() => {
    const m = new Map<string, PickerObject>();
    for (const o of value) m.set(o.id, o);
    if (remote.status === "answer") for (const o of remote.answer.items) m.set(o.id, o);
    return m;
  }, [value, remote]);

  const suggestions = remote.status === "answer" ? remote.answer.items.map(toToken) : [];
  const answer = remote.status === "answer" ? remote.answer : null;
  let empty: string | undefined;
  if (remote.status === "error") empty = `The ${kind} search failed. Type again to retry.`;
  else if (answer?.refine) empty = `Too many matches. Keep typing to narrow the ${kind} search.`;
  else if (answer && answer.items.length === 0)
    empty = `No ${kind} matches “${remote.status === "answer" ? remote.text : ""}”.`;
  let note = hint;
  if (full) note = `You can choose up to ${max} ${kind}s. Remove one to add another.`;
  else if (answer?.more) note = `Showing the best matches. Type more to narrow the ${kind} search.`;

  return (
    <TokenInput
      {...rest}
      label={rest.label}
      error={error}
      hint={note}
      value={value.map(toToken)}
      onChange={(tokens) =>
        onChange(tokens.map((t) => objects.get(t.id)).filter((o): o is PickerObject => !!o))
      }
      suggestions={suggestions}
      query={text}
      onQueryChange={setText}
      loading={remote.status === "loading"}
      loadingText={`Searching ${kind}s…`}
      {...(empty ? { emptyText: empty } : {})}
      placeholder={full ? "" : `Search ${kind}s by name, logon name or e-mail`}
      tokensLabel={`Chosen ${kind}s`}
    />
  );
}
