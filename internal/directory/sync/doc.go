// Package sync is the directory sync ingester's pure core (blueprint §5.2, §14 flow 1): it turns one
// connector ScopedSearch entry into the inventory.Observation that Populate stores, and owns the
// CLOSED list of attributes a sync asks the connector for.
//
// This package does no I/O. The caller (the cycle driver, a later brick of T-1188) owns the search,
// the page loop, the lease and the transaction; everything here is a function of the entry and the
// Mapper's configuration, so it is exercised with entries captured from the lab and with hostile ones.
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
