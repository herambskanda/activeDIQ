// Package read is the connector's Read RPC (contract: one object by GUID, ranged multi-valued
// attributes streamed to the end) and the Tier-0 verdict that rides on its header (T-0433).
//
// A Read names the DC it must be served by (DcSelection.pinned_dsa_guid, ADR-0005 rule 5). The
// connector is bound to one DC through one session; a pin that is not that DC fails the call, and
// the DC is checked again after the read and after the classification, so a header never mixes
// answers from two DCs. The verdict is the classifier of internal/connector/write run over the same
// session: if it cannot decide, the call fails (true or error, never a default false).
package read
