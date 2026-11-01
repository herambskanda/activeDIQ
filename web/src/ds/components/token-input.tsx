import { type KeyboardEvent, type Ref, useCallback, useId, useRef, useState } from "react";

import { describedBy, FieldNotes } from "./field";

export interface Token {
  /** Identity: a token with the same id is never added twice. */
  readonly id: string;
  readonly label: string;
  /** A second line in the suggestion list (an e-mail address, an OU path); also the token's tooltip. */
  readonly detail?: string;
  /** A word shown before the label, for a state that must not rely on colour ("Outside"). */
  readonly badge?: string;
  /** Marks a token the user should look at again; the badge or the field's error says why. */
  readonly invalid?: boolean;
}

export interface TokenInputProps {
  readonly label: string;
  readonly value: readonly Token[];
  readonly onChange: (tokens: readonly Token[]) => void;
  /** Typeahead results for the current text. The caller searches (and may ask the server). */
  readonly suggestions?: readonly Token[];
  /** The typed text, when the screen needs to own it (to save what is typed, or restore it). Omit to let the field own it. */
  readonly query?: string;
  /** Called as the user types and with "" when the text is cleared. */
  readonly onQueryChange?: (query: string) => void;
  /**
   * Turns typed text into a token for Enter, comma, semicolon and leaving the field; return null to
   * refuse it (the text stays). Omit it when only suggestions may be chosen.
   */
  readonly parse?: (text: string) => Token | null;
  /** Suggestions are being fetched. */
  readonly loading?: boolean;
  readonly loadingText?: string;
  /** Shown (and announced) when there is text and no suggestion. Omit to show nothing. */
  readonly emptyText?: string;
  readonly placeholder?: string;
  readonly error?: string | undefined;
  readonly hint?: string | undefined;
  readonly disabled?: boolean;
  readonly readOnly?: boolean;
  /** Name of the list of chosen tokens, for screen readers. */
  readonly tokensLabel?: string;
  readonly removeLabel?: (token: Token) => string;
  readonly inputRef?: Ref<HTMLInputElement>;
  readonly className?: string;
}

/**
 * Several values chosen from a directory, typed or picked from a typeahead: recipients, users, groups.
 * ARIA 1.2 combobox: Up/Down move through suggestions, Enter picks, Escape closes then clears the
 * text, Backspace in an empty field removes the last token, each token has its own Remove button.
 * Not for one value from a short list (Select).
 */
export function TokenInput({
  label,
  value,
  onChange,
  suggestions = [],
  query: controlledQuery,
  onQueryChange,
  parse,
  loading = false,
  loadingText = "Searching…",
  emptyText,
  placeholder,
  error,
  hint,
  disabled = false,
  readOnly = false,
  tokensLabel = "Selected",
  removeLabel = (t) => `Remove ${t.label}`,
  inputRef,
  className,
}: TokenInputProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const listId = `${id}-list`;
  const optionId = (i: number) => `${id}-opt-${i}`;
  const input = useRef<HTMLInputElement | null>(null);
  const [ownText, setText] = useState("");
  const text = controlledQuery ?? ownText;
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const [action, setAction] = useState("");
  const editable = !disabled && !readOnly;

  const chosen = new Set(value.map((t) => t.id));
  const options = suggestions.filter((s) => !chosen.has(s.id));
  const showList = editable && open && options.length > 0;
  const query = text.trim();
  // The highlighted option never outlives the list it pointed into (the caller swaps suggestions as it searches).
  const current = active < options.length ? active : -1;

  const setRefs = useCallback(
    (el: HTMLInputElement | null) => {
      input.current = el;
      if (typeof inputRef === "function") inputRef(el);
      else if (inputRef) inputRef.current = el;
    },
    [inputRef],
  );

  const changeText = (next: string) => {
    setText(next);
    setActive(-1);
    setOpen(next.trim() !== "");
    setAction("");
    onQueryChange?.(next);
  };
  const clearText = () => {
    setText("");
    setOpen(false);
    setActive(-1);
    onQueryChange?.("");
  };
  const add = (token: Token) => {
    if (!chosen.has(token.id)) {
      onChange([...value, token]);
      setAction(`Added ${token.label}`);
    }
    clearText();
  };
  const remove = (token: Token) => {
    onChange(value.filter((t) => t.id !== token.id));
    setAction(`Removed ${token.label}`);
    input.current?.focus();
  };
  /** Commits the typed text through `parse`; false when there was nothing to commit or it was refused. */
  const commit = (): boolean => {
    if (parse === undefined || query === "") return false;
    const token = parse(query.replace(/[,;]$/, ""));
    if (token === null) return false;
    add(token);
    return true;
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (!editable || e.nativeEvent.isComposing) return;
    switch (e.key) {
      case "ArrowDown":
      case "ArrowUp": {
        if (options.length === 0) return;
        e.preventDefault();
        if (!showList) {
          setOpen(true);
          setActive(e.key === "ArrowDown" ? 0 : options.length - 1);
          return;
        }
        const step = e.key === "ArrowDown" ? 1 : -1;
        setActive(
          current < 0
            ? step === 1
              ? 0
              : options.length - 1
            : (current + step + options.length) % options.length,
        );
        return;
      }
      case "Enter": {
        const pick = showList ? options[current] : undefined;
        // Enter inside a form submits it; here it means "take this".
        if (pick !== undefined) add(pick);
        else if (query === "" || !commit()) return;
        e.preventDefault();
        return;
      }
      case ",":
      case ";":
        if (parse !== undefined && query !== "") {
          e.preventDefault();
          commit();
        }
        return;
      case "Escape":
        if (showList) {
          e.preventDefault();
          e.stopPropagation();
          setOpen(false);
          setActive(-1);
        } else if (text !== "") {
          e.preventDefault();
          e.stopPropagation();
          clearText();
        }
        return;
      case "Backspace": {
        const last = value[value.length - 1];
        if (text === "" && last !== undefined) {
          e.preventDefault();
          remove(last);
        }
        return;
      }
      default:
    }
  };

  const message = loading
    ? loadingText
    : action !== ""
      ? action
      : showList
        ? `${options.length} ${options.length === 1 ? "suggestion" : "suggestions"}`
        : query !== "" && options.length === 0 && emptyText !== undefined
          ? emptyText
          : "";
  const showStatus =
    editable &&
    open &&
    !showList &&
    (loading || (query !== "" && options.length === 0 && emptyText !== undefined));

  return (
    <div className={className}>
      <label className="diq-field__label" htmlFor={`${id}-input`}>
        {label}
      </label>
      <div className="diq-token">
        {/* Clicking the empty part of the field puts the caret in the input, as in any text field. */}
        <div
          className="diq-token__field"
          data-invalid={error !== undefined || undefined}
          data-disabled={disabled || undefined}
          data-readonly={readOnly || undefined}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget || (e.target as HTMLElement).tagName === "LI") {
              e.preventDefault();
              input.current?.focus();
            }
          }}
        >
          <ul className="diq-token__list" aria-label={tokensLabel}>
            {value.map((t) => (
              <li key={t.id} className="diq-token__item" data-invalid={t.invalid || undefined}>
                <span className="diq-token__text" title={t.detail ?? t.label}>
                  {t.badge !== undefined && <span className="diq-token__badge">{t.badge} </span>}
                  {t.label}
                </span>
                {editable && (
                  <button
                    type="button"
                    className="diq-token__remove"
                    aria-label={removeLabel(t)}
                    onClick={() => remove(t)}
                  >
                    <span aria-hidden="true">×</span>
                  </button>
                )}
              </li>
            ))}
            <li className="diq-token__entry">
              <input
                ref={setRefs}
                id={`${id}-input`}
                className="diq-token__input"
                role="combobox"
                aria-autocomplete="list"
                aria-expanded={showList}
                aria-controls={showList ? listId : undefined}
                aria-activedescendant={showList && current >= 0 ? optionId(current) : undefined}
                aria-invalid={error !== undefined}
                aria-describedby={describedBy(
                  hint === undefined ? undefined : hintId,
                  error === undefined ? undefined : errorId,
                )}
                value={text}
                placeholder={value.length === 0 ? placeholder : undefined}
                disabled={disabled}
                readOnly={readOnly}
                autoComplete="off"
                spellCheck={false}
                onChange={(e) => changeText(e.target.value)}
                onKeyDown={onKeyDown}
                onBlur={() => {
                  setOpen(false);
                  setActive(-1);
                  if (editable) commit();
                }}
              />
            </li>
          </ul>
        </div>
        {showList && (
          <ul id={listId} role="listbox" aria-label={label} className="diq-token__options">
            {options.map((o, i) => (
              <li
                key={o.id}
                id={optionId(i)}
                role="option"
                aria-selected={i === current}
                className="diq-token__option"
                title={o.detail === undefined ? o.label : `${o.label} · ${o.detail}`}
                // Keep focus in the input: a click on a suggestion must not blur (and so commit) the typed text.
                onMouseDown={(e) => e.preventDefault()}
                onMouseEnter={() => setActive(i)}
                onClick={() => {
                  add(o);
                  input.current?.focus();
                }}
              >
                <span className="diq-token__opt-label">
                  {o.badge !== undefined && <span className="diq-token__badge">{o.badge} </span>}
                  {o.label}
                </span>
                {o.detail !== undefined && (
                  <span className="diq-token__opt-detail diq-mono">{o.detail}</span>
                )}
              </li>
            ))}
          </ul>
        )}
        {showStatus && <p className="diq-token__note">{loading ? loadingText : emptyText}</p>}
      </div>
      <FieldNotes hint={hint} error={error} hintId={hintId} errorId={errorId} />
      <div role="status" className="diq-sr-only">
        {message}
      </div>
    </div>
  );
}
