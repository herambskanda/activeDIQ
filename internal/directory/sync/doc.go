// Package sync is the directory sync ingester (blueprint §5.2, §14 flow 1): its pure core turns one
// connector ScopedSearch entry into the inventory.Observation that Populate stores, owns the
// CLOSED list of attributes a sync asks the connector for, and its engine reads whole domains.
//
// The mapping (Mapper, Attributes) is pure: no I/O, a function of the entry and the Mapper's configuration,
// exercised with entries captured from the lab and with hostile ones. The rest of the package does I/O only
// through ports: the lease-fenced cursor store (Store, DM-19) and the full-read Engine, which pages one AD
// connection's managed domain NCs through the connector's ScopedSearch into inventory.Ingester, and whose
// Reconcile marks the objects gone from the directory deleted (a forest-wide objectGUID diff that never runs on
// an incomplete listing and is refused above the mass-delete share). The job that
// schedules the engine, acquires its leases and supplies the managed set belongs to a later brick of T-1188.
//
// The rules the mapping holds to:
//
//   - Only the closed list (Attributes) is ever read from an entry. An attribute that is not in the
//     effective request is not examined, copied or named, so a secret the directory returned anyway
//     leaves no trace in the Observation or in an error.
//   - "Not read" is not a value. An attribute the entry does not carry leaves its field nil or zero
//     with the InputsRead bit clear. An attribute the entry carries with no values is read, and
//     empty. Nothing is invented to fill a gap.
//   - A malformed value refuses its entry with an *Error that names the attribute and a fixed
//     reason code and never echoes the value, so a caller counts the refusal and keeps the batch.
//   - Identity is the objectGUID. The DN, the sAMAccountName and the UPN are display data.
package sync
