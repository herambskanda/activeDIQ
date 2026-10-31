/**
 * A progress bar. With `value` it is determinate; without, indeterminate (no `aria-valuenow`, per
 * ARIA). The `label` is required and names what is progressing. Show the numbers as text beside it:
 * the bar is not the only carrier of the value.
 */
export function Progress({
  label,
  value,
  max: maxProp = 100,
}: {
  readonly label: string;
  readonly value?: number;
  readonly max?: number;
}) {
  const max = maxProp > 0 ? maxProp : 100; // a non-positive max would make the bar NaN
  const determinate = value !== undefined;
  const now = determinate ? Math.min(Math.max(value, 0), max) : undefined;
  return (
    <div
      className={determinate ? "diq-progress" : "diq-progress diq-progress--indeterminate"}
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-valuenow={now}
    >
      <div
        className="diq-progress__bar"
        style={now === undefined ? undefined : { inlineSize: `${(now / max) * 100}%` }}
      />
    </div>
  );
}
