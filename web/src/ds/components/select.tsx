import { type ReactNode, type Ref, type SelectHTMLAttributes, useId } from "react";

import { describedBy, FieldNotes } from "./field";

export interface SelectOption {
  readonly value: string;
  readonly label: string;
  readonly disabled?: boolean;
}

export interface SelectProps extends Omit<
  SelectHTMLAttributes<HTMLSelectElement>,
  "id" | "value" | "onChange" | "children"
> {
  readonly label: string;
  readonly options: readonly SelectOption[];
  readonly value: string;
  readonly onChange: (value: string) => void;
  /** Adds an empty first option with this text. Choosing it clears the field (value ""). */
  readonly placeholder?: string;
  /** Validation message; sets aria-invalid and is announced as the field's description. */
  readonly error?: string | undefined;
  readonly hint?: string | undefined;
  /** Options are on their way: the field stays usable and announces busy. */
  readonly loading?: boolean;
  /** Shown as a focusable, selectable value that cannot be changed (a native select has no read-only). */
  readonly readOnly?: boolean;
  readonly selectRef?: Ref<HTMLSelectElement>;
}

/**
 * A labelled single choice from a short, known list (periods, formats, intervals). It is the platform
 * select, so the keyboard, typeahead and screen-reader behaviour are the browser's. For a long or
 * searchable list use TokenInput; for two to five visible presets use SegmentedControl.
 */
export function Select({
  label,
  options,
  value,
  onChange,
  placeholder,
  error,
  hint,
  loading = false,
  readOnly = false,
  selectRef,
  className,
  ...rest
}: SelectProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedby = describedBy(
    hint === undefined ? undefined : hintId,
    error === undefined ? undefined : errorId,
  );
  let control: ReactNode;
  if (readOnly) {
    const shown = options.find((o) => o.value === value)?.label ?? placeholder ?? "";
    control = (
      <input
        className="diq-input"
        id={id}
        readOnly
        value={shown}
        title={shown}
        aria-invalid={error !== undefined}
        aria-describedby={describedby}
        disabled={rest.disabled}
      />
    );
  } else {
    control = (
      <div className="diq-select">
        <select
          {...rest}
          ref={selectRef}
          id={id}
          className="diq-input diq-select__control"
          value={value}
          aria-busy={loading || undefined}
          aria-invalid={error !== undefined}
          aria-describedby={describedby}
          onChange={(e) => onChange(e.target.value)}
        >
          {placeholder !== undefined && <option value="">{placeholder}</option>}
          {options.map((o) => (
            <option key={o.value} value={o.value} disabled={o.disabled}>
              {o.label}
            </option>
          ))}
        </select>
      </div>
    );
  }
  return (
    <div className={className}>
      <label className="diq-field__label" htmlFor={id}>
        {label}
      </label>
      {control}
      <FieldNotes hint={hint} error={error} hintId={hintId} errorId={errorId} />
    </div>
  );
}
