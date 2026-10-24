// Package sd is safe primitive P6, the typed security-descriptor model (safe-primitives-security-
// descriptor.md): a strict decoder for the self-relative MS-DTYP security descriptor that
// nTSecurityDescriptor carries on the LDAP wire, the SD_FLAGS read control, and a conservative,
// three-valued effective-rights helper.
//
// This is the read half. There is no SDDL parser anywhere in this package, no constructor from a
// string, and no writer: the write half (DACL diffs) is a later ticket (§11) and DisplaySDDL is
// display-only and not built here (§8).
//
// Rules the code holds to: typed in and out (the only bytes that enter are Raw, the only function
// that reads them is Decode), reject never repair (malformed input is an error with a stable code,
// nothing is "fixed"), bounded (MaxSDBytes, and no allocation is sized from an attacker-supplied
// count before it is checked against the bytes actually present), one corpus (sd.read).
package sd
