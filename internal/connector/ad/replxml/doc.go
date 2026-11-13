// Package replxml is the one decoder for the XML text a domain controller constructs for the
// msDS-Repl* attributes (connector-contract §5.7, rules X1 to X8; threat-model TM-D31):
// msDS-ReplAllInboundNeighbors, msDS-ReplPendingOps, msDS-ReplConnectionFailures,
// msDS-ReplLinkFailures, msDS-ReplAttributeMetaData and msDS-ReplValueMetaData.
//
// The bytes come from a DC, and a DC can be compromised, malfunctioning, a man in the middle of a
// misconfigured channel, or Samba. So the decoder drives encoding/xml token by token and refuses
// what it does not need: a DOCTYPE or any other directive, every processing instruction except the
// leading XML declaration, any declared encoding but UTF-8, an unbounded input, a deep or wide
// document, and any text that is not clean UTF-8. Entities are never resolved. Element names are
// an allowlist per structure; an unknown element is skipped under the same limits and counted,
// never exposed. Metadata output is names, versions, times, DSA GUIDs and USNs, never a value (X7).
//
// Each Decode function takes ONE attribute value and returns a typed struct or a *DecodeError
// whose Code is fixed text; on an error nothing is populated and nothing derived from the input is
// copied into the error. A missing field is unset, never zero. The package is pure (X6): it imports
// no package that can do I/O and logs nothing.
//
// Element names and value formats follow the DS_REPL_* structures of MS-DRSR
// (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/0597aff6-0177-4d52-99f2-14a5441bc3c1)
// and are [UNVERIFIED] [LAB: Windows] until the fixtures of CC-REPLXML-01 are captured; the
// fixtures in testdata/ are synthetic.
//
// Caution: the functions return *DecodeError, not error. Assigning the result to an error variable
// without a nil check yields a non-nil interface holding a nil pointer.
package replxml
