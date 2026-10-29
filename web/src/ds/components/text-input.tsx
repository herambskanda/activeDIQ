import { type InputHTMLAttributes, type Ref, useId } from "react";

export interface TextInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "id"> {
  readonly label: string;
  /** Validation message; sets aria-invalid and is announced as the field's description. */
  readonly error?: string | undefined;
  readonly inputRef?: Ref<HTMLInputElement>;
  /** Rendered beside the input (for example a Clear button). */
  readonly trailing?: React.ReactNode;
}

/** A labelled text field. The label is always visible; errors are linked with aria-describedby. */
export function TextInput({
  label,
  error,
  inputRef,
  trailing,
  className,
  ...rest
}: TextInputProps) {
  const id = useId();
  const errorId = `${id}-error`;
  return (
    <div className={className}>
      <label className="diq-field__label" htmlFor={id}>
        {label}
      </label>
      <div className="diq-field__row">
        <input
          {...rest}
          ref={inputRef}
          id={id}
          className="diq-input"
          aria-invalid={error !== undefined}
          aria-describedby={error === undefined ? undefined : errorId}
        />
        {trailing}
      </div>
      {error !== undefined && (
        <p id={errorId} className="diq-field__error">
          {error}
        </p>
      )}
    </div>
  );
}
