// Package dial is the component side of the fleet transport, linked by cmd/connector and cmd/agent:
// the enrollment client, the persisted installation-CA bundle and the dial-out that verifies the
// server only against that CA (TM-TB6-T2, TM-TB12-T2, TM-D24 rules D1 and D3).
//
// It has no store and no SQL (blueprint §2 rule 7) and imports no generated proto: the Enroll RPC
// itself is a caller-supplied Exchange, which the role package in internal/compose binds to
// fleetv1. Three rules hold everywhere in the package:
//
//   - The roots are always the pinned CA certificates. RootCAs is never nil (nil means the host
//     root set), and there is no InsecureSkipVerify and no verify callback.
//   - A failed pin or verification is final for that attempt: nothing here retries, falls back to a
//     weaker mode or dials another address. Retry policy belongs to the caller, which must re-dial
//     with the same pin.
//   - The private key is generated on the host, held in memory until enrollment is verified, written
//     with owner-only permissions, and is never part of any message, error or log line.
package dial
