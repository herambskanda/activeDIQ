// Deliberate FF-SP3 violations. `make ci-proof` lints this file with --no-ignore and requires every
// safe-primitives rule to report. It is never part of the build (eslint ignores proof/ by default).
export function violations(name: string, parent: string, user: string, dn: string, h: string, rows: string[]): unknown[] {
  const filter = `(&(objectClass=user)(cn=${name}))`;
  const newDn = "CN=" + name + "," + parent;
  const quoted = user.replace(/'/g, "''");
  const parts = dn.split(",");
  const blob = new Blob([rows.join("\n")], { type: "text/csv" });
  document.write(h);
  return [filter, newDn, quoted, parts, blob];
}
