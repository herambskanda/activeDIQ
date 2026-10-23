// Package fleetsql is the server-only SQL of DM-12 Component and EnrollmentToken (blueprint §2
// rules 6 and 7). Nothing a satellite binary links may import it; fitness-modules checks that
// cmd/connector and cmd/agent do not reach it.
//
// It issues and redeems enrollment tokens (threat model TM-TB6-T1): single-use, expiring, stored
// hashed and rate-limited, issued only to a permission holder who has just completed step-up. It is
// not the Enroll RPC handler, the CA or the listener.
package fleetsql
