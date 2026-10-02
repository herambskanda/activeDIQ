// One spelling of a hand-built LDAP filter per line (line numbers matter: tools/ci/proof.sh requires
// FF-SP3 on every one of them). Never part of the build (eslint ignores proof/ by default).
export function spellings(x: string): unknown[] {
  const a = `(&(objectClass=user)(cn=${x}))`;
  let b = "(&(objectClass=user)(cn=";
  b += x;
  const c = "(&(objectClass=user)(cn=".concat(x, "))");
  const d = ["(&(objectClass=user)(cn=", x, "))"].join("");
  const tpl = "(&(objectClass=user)(cn=%s))";
  const e = "(&(objectClass=user)(cn={n}))".replace("{n}", x);
  return [a, b, c, d, tpl, e];
}
