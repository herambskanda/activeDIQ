---
name: ldapfilter-lessons
description: Shape of the ldapfilter package and its corpus/oracle contract (T-0101)
metadata:
  type: reference
---

- Oracle (go-ldap CompileFilter) checks Eq/Ge/Le/Approx records with args `attr` + `value`: `value`'s raw octets must equal the octets in the rendered assertion, so binary kinds (guid/sid) are passed as `{"hex": stored bytes}` plus a `kind` arg.
- Constructors never fail; all validation is in `Render(f, schema)`. DN values go through an interface until P2 (T-0102) exists.
- `make fitness-safeprim` was already red on main from internal/compose/server/tls_test.go (T-0065); don't chase it from a P1 ticket.
