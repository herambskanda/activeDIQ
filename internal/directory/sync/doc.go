// Package sync is the directory sync ingester (blueprint §5.2, §14 flow 1): its pure core turns one
// connector ScopedSearch entry into the inventory.Observation that Populate stores, owns the
// CLOSED list of attributes a sync asks the connector for, and its engine reads whole domains.
//
// The mapping (Mapper, Attributes) is pure: no I/O, a function of the entry and the Mapper's configuration,
// exercised with entries captured from the lab and with hostile ones. The rest of the package does I/O only
// through ports: the lease-fenced cursor store (Store, DM-19) and the full-read Engine, which pages one AD
// connection's managed domain NCs through the connector's ScopedSearch into inventory.Ingester, and whose
// Reconcile marks the objects gone from the directory deleted (a forest-wide objectGUID diff that never runs on
// an incomplete listing or one without its domain head, and is refused above the mass-delete share of the forest or of any one domain). The job that
// schedules the engine, acquires its leases and supplies the managed set belongs to a later brick of T-1188.
//
// The change-feed side (ChangeMapper, Applier) applies a DirSync ObjectChange as a patch of the stored row
// (contract §6.4): only the attributes the change names are written, VALUES_ADDED and VALUES_REMOVED are
// incremental member edges, DELETED and RECYCLED set the object state, and the result does not depend on the
// order of the changes. An object the inventory has never seen is created when the change carries a creation set
// and is otherwise reported in ApplyReport.NeedsRead, never stored half. Member edges are an authorization input,
// so a change that cannot be applied in full fails closed: a removal (or a whole set) naming a member without a
// GUID, and any change the mapper refuses whose object GUID parsed, put that object in NeedsRead and end a stored
// group's active member edges until the engine's read names them again. The write itself is the inventory
// writer's patch mode (inventory.Ingester.ApplyPatches).
//
// Engine.IncrementalCycle runs the feed per naming context: the first cycle (or any resync) primes the feed, reads the
// NC in full, reconciles on a resync and stores the prime cookie with the SyncCursor in one transaction; later
// cycles resume from the stored cookie, one transaction per batch (lease claim, Applier.Apply, cursor advance), and
// record the pass when the feed reports cycle_complete. A stale cookie (client.ResyncRequired), a cookie the
// connector rejects or cannot decode, or a batch with ApplyReport.NeedsRead sets resync_required and re-establishes
// from a full read. An unreachable or throttled DC or an incomplete feed is a *RetryableError that leaves the cursor
// and cookie alone; a suspended connection pauses the NC and resumes as a resync.
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
