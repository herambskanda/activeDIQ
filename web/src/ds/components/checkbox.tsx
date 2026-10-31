import { type InputHTMLAttributes, type ReactNode, useEffect, useId, useRef } from "react";

import { describedBy, FieldNotes } from "./field";

export interface CheckboxProps extends Omit<
  InputHTMLAttributes<HTMLInputElement>,
  "id" | "type" | "checked" | "onChange"
> {
  /** The visible label. Rich content is fine; it is the checkbox's accessible name. */
  readonly label: ReactNode;
  readonly checked: boolean;
  readonly onChange: (checked: boolean) => void;
  /** Some, not all, of a group is chosen (a "select all" parent). Cleared by the next change. */
  readonly indeterminate?: boolean;
  readonly description?: string;
  readonly error?: string | undefined;
  /** Focusable and announced as read-only; it cannot be changed. */
  readonly readOnly?: boolean;
}

/** A labelled checkbox. The whole label row is the click target (taller than 24 px, WCAG 2.5.8). */
export function Checkbox({
  label,
  checked,
  onChange,
  indeterminate = false,
  description,
  error,
  readOnly = false,
  className,
  ...rest
}: CheckboxProps) {
  const id = useId();
  const descId = `${id}-desc`;
  const errorId = `${id}-error`;
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current !== null) ref.current.indeterminate = indeterminate;
  }, [indeterminate, checked]);
  return (
    <div className={className}>
      <label className="diq-check" data-disabled={rest.disabled || undefined}>
        <input
          {...rest}
          ref={ref}
          type="checkbox"
          className="diq-check__box"
          checked={checked}
          aria-readonly={readOnly || undefined}
          aria-invalid={error !== undefined}
          aria-describedby={describedBy(
            description === undefined ? undefined : descId,
            error === undefined ? undefined : errorId,
          )}
          onChange={(e) => !readOnly && onChange(e.target.checked)}
        />
        <span className="diq-check__text">{label}</span>
      </label>
      <FieldNotes hint={description} error={error} hintId={descId} errorId={errorId} />
    </div>
  );
}
