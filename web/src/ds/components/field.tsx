/** Shared by the form controls: how a control links its hint and error text as its description. */

/** Joins the ids that describe a control; `undefined` when there are none (never an empty attribute). */
export function describedBy(...ids: ReadonlyArray<string | undefined>): string | undefined {
  const joined = ids.filter((id) => id !== undefined && id !== "").join(" ");
  return joined === "" ? undefined : joined;
}

/** Hint and error paragraphs for a control; `hintId` and `errorId` are what the control's aria-describedby names. */
export function FieldNotes({
  hint,
  error,
  hintId,
  errorId,
}: {
  readonly hint: string | undefined;
  readonly error: string | undefined;
  readonly hintId: string;
  readonly errorId: string;
}) {
  return (
    <>
      {hint !== undefined && (
        <p id={hintId} className="diq-field__hint">
          {hint}
        </p>
      )}
      {error !== undefined && (
        <p id={errorId} className="diq-field__error">
          {error}
        </p>
      )}
    </>
  );
}
