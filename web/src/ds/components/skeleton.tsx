/** Placeholder rows while a list loads. Announced once as a status; the pulse stops under reduced motion. */
export function Skeleton({ rows = 6, label }: { readonly rows?: number; readonly label: string }) {
  return (
    <div className="diq-skeleton" role="status" aria-label={label}>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="diq-skeleton__row" />
      ))}
    </div>
  );
}
