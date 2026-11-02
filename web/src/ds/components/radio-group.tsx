import { useId, useRef } from "react";

import { Button } from "./button";
import { describedBy, FieldNotes } from "./field";

export interface ChoiceOption {
  readonly value: string;
  readonly label: string;
  /** RadioCardGroup only: the line under the label. */
  readonly description?: string;
  readonly disabled?: boolean;
}

export interface ChoiceGroupProps {
  /** The group's visible name (a legend). */
  readonly label: string;
  readonly options: readonly ChoiceOption[];
  /** The chosen option's value, or null for no choice yet. */
  readonly value: string | null;
  /** Called with the new value, or null when the user clears the choice. */
  readonly onChange: (value: string | null) => void;
  readonly name?: string;
  readonly error?: string | undefined;
  readonly hint?: string | undefined;
  readonly disabled?: boolean;
  readonly readOnly?: boolean;
  /** Adds a Clear button (after a choice is made) for choices that are optional. */
  readonly clearable?: boolean;
  readonly clearLabel?: string;
  readonly className?: string;
}

/**
 * The one radio group behind RadioCardGroup and SegmentedControl: native radios in a fieldset, so
 * Tab enters the group once and the arrow keys move and select, as WAI-ARIA expects, with no script.
 * Internal: screens use the two wrappers, which differ only in how an option looks.
 */
export function ChoiceGroup({
  variant,
  label,
  options,
  value,
  onChange,
  name,
  error,
  hint,
  disabled = false,
  readOnly = false,
  clearable = false,
  clearLabel = "Clear",
  className,
}: ChoiceGroupProps & { readonly variant: "card" | "chip" }) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const ref = useRef<HTMLFieldSetElement>(null);
  const showClear = clearable && value !== null && !disabled && !readOnly;
  const clear = () => {
    // Focus moves to the group before the Clear button leaves the page, so the keyboard user keeps their place.
    ref.current?.querySelector<HTMLInputElement>("input:not(:disabled)")?.focus();
    onChange(null);
  };
  return (
    <div className={className}>
      <fieldset
        ref={ref}
        className="diq-choice"
        role="radiogroup"
        disabled={disabled}
        aria-readonly={readOnly || undefined}
        aria-invalid={error !== undefined}
        aria-describedby={describedBy(
          hint === undefined ? undefined : hintId,
          error === undefined ? undefined : errorId,
        )}
      >
        <legend className="diq-field__label">{label}</legend>
        <div className={`diq-choice__options diq-choice__options--${variant}`}>
          {options.map((o) => {
            const checked = o.value === value;
            return (
              <label
                key={o.value}
                className={variant === "card" ? "diq-card" : "diq-seg"}
                data-checked={checked || undefined}
                data-disabled={o.disabled || disabled || undefined}
              >
                <input
                  type="radio"
                  name={name ?? id}
                  className={variant === "card" ? "diq-card__radio" : "diq-sr-only diq-seg__radio"}
                  value={o.value}
                  checked={checked}
                  disabled={o.disabled}
                  onChange={() => !readOnly && onChange(o.value)}
                />
                {variant === "card" ? (
                  <span className="diq-card__body">
                    <span className="diq-card__title" title={o.label}>
                      {o.label}
                    </span>
                    {o.description !== undefined && (
                      <span className="diq-card__desc" title={o.description}>
                        {o.description}
                      </span>
                    )}
                  </span>
                ) : (
                  <span className="diq-seg__face" title={o.label}>
                    {o.label}
                  </span>
                )}
              </label>
            );
          })}
          {showClear && <Button onClick={clear}>{clearLabel}</Button>}
        </div>
      </fieldset>
      <FieldNotes hint={hint} error={error} hintId={hintId} errorId={errorId} />
    </div>
  );
}
