// Package sd is safe primitive P6, the typed security-descriptor model (safe-primitives-security-
// descriptor.md): a strict decoder for the self-relative MS-DTYP security descriptor that
// nTSecurityDescriptor carries on the LDAP wire, the SD_FLAGS read control, and a conservative,
// three-valued effective-rights helper.
//
// The write half is PlanDACL and PlanInheritance, which turn a base SD and an ACE diff (never a whole
// DACL) into a DACLWrite: a type only those planners can fill, whose Value has zero owner, group and
// SACL offsets, SP clear and DP set, sent with the DACL-only SD_FLAGS control. There is no SDDL parser
// anywhere in this package and no constructor from a string (ParseTrustee takes only S-1-...);
// DisplaySDDL is display-only and not built here (§8).
//
// Rules the code holds to: typed in and out (the only bytes that enter are Raw, the only function
// that reads them is Decode), reject never repair (malformed input is an error with a stable code,
// nothing is "fixed"), bounded (MaxSDBytes, and no allocation is sized from an attacker-supplied
// count before it is checked against the bytes actually present), two corpus units (sd.read, sd.write).
package sd
