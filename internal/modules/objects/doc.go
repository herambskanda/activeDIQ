// Package objects owns the object-management definitions of blueprint §5.4: the versioned Template
// (DM-50) and the NamingFormat (DM-51). This change holds their data model, their Plan-time checks and
// their store; the create/modify Actions that use them are later tickets and compose these by ID.
//
// Two rules shape the package:
//
//   - Plan-time checks are pure. CheckInput (a Template's mandatory, hidden and read-only rules) and
//     NamingFormat.Render (alternatives, tokens, DM-51.I1 length and character rules) read no directory
//     and no database, so a blocked item is blocked before any directory read.
//   - Uniqueness is not decided here. sAMAccountName, UPN and CN-in-container collide at the DC's
//     atomic create (DM-51.I2/I7, ADR-0005 rule 4). Candidate only proposes the next suffixed name; the
//     caller learns that one is taken from the DC's entryAlreadyExists, never from a lookup here.
//
// Directory strings leave this package as plain values; the DN, RDN and LDAP-filter primitives build
// every security-relevant string downstream.
package objects
