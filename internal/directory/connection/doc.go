// Package connection is the connection registry (ADR-0003 F1, blueprint §5.2): it owns DM-10
// Connection, the one directory activeDIQ manages (an AD forest or an Entra tenant), and is the only
// package that names public.connections in SQL. The `connections` module writes through it inside its
// Actions; `client`, `sync` and `inventory` read it.
//
// This package holds the persistence and the lifecycle state machine. The transition table
// (transitions.go) is the single declaration of which state changes are legal; the store refuses any
// other, and the database refuses to change an identity once set (I1) or to leave a terminal state.
// The verification run, the activation gate (I9), bindings (DM-13) and the credential port are other
// tickets and plug in here: they call Transition and SetDirectoryIdentity.
//
// Secret material never enters this package. A connection names its credential by CredentialID, the
// ID of a DM-11 row that the credential port seals elsewhere.
package connection
