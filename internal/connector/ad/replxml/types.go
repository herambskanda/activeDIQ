package replxml

import "time"

// Guid is a 128-bit identity in RFC 4122 order, the byte order of the canonical dashed text
// (connector-contract §2 rule 9). The XML carries the canonical text, so the bytes are the text read
// left to right; the LDAP mixed-endian wire order of objectGUID never appears here. The zero Guid is
// "unset" (the DC omitted the field), never an identity.
type Guid struct {
	b   [16]byte
	set bool
}

// IsSet reports whether the DC returned the field.
func (g Guid) IsSet() bool { return g.set }

// Bytes returns the 16 bytes in RFC 4122 order, or nil when unset.
func (g Guid) Bytes() []byte {
	if !g.set {
		return nil
	}
	out := make([]byte, 16)
	copy(out, g.b[:])
	return out
}

const lowerHex = "0123456789abcdef"

// String is the canonical lower-case dashed form, or "" when unset.
func (g Guid) String() string {
	if !g.set {
		return ""
	}
	var out [36]byte
	o := 0
	for i, c := range g.b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[o] = '-'
			o++
		}
		out[o] = lowerHex[c>>4]
		out[o+1] = lowerHex[c&0x0f]
		o += 2
	}
	return string(out[:])
}

// TimeKind says what a Time holds.
type TimeKind uint8

const (
	// TimeUnset: the DC did not return the field.
	TimeUnset TimeKind = iota
	// TimeZero: the DC returned FILETIME 0 (1601-01-01T00:00:00Z), "never".
	TimeZero
	// TimeAt: a real UTC timestamp in At.
	TimeAt
)

// Time is a parsed XML time. Unset is distinct from Zero, and neither is ever "now".
type Time struct {
	Kind TimeKind
	At   time.Time // meaningful only when Kind is TimeAt
}

// U32 is an optional unsigned 32-bit count, flag set or Win32 result.
type U32 struct {
	V   uint32
	Set bool
}

// U64 is an optional unsigned 64-bit value (a USN).
type U64 struct {
	V   uint64
	Set bool
}

// Neighbor is one DS_REPL_NEIGHBOR (msDS-ReplAllInboundNeighbors value).
type Neighbor struct {
	Partition           Guid   // uuidNamingContextObjGuid
	PartitionDisplayDN  string // pszNamingContext; display only, every output encoder escapes it (FF-SP4)
	SourceDSA           Guid   // uuidSourceDsaObjGuid
	SourceDNSHost       string // pszSourceDsaAddress; display only
	LastAttempt         Time   // ftimeLastSyncAttempt
	LastSuccess         Time   // ftimeLastSyncSuccess
	ConsecutiveFailures U32    // cNumConsecutiveSyncFailures
	LastResultWin32     U32    // dwLastSyncResult
	Flags               U32    // dwReplicaFlags (DS_REPL_NBR_*), decoded by the report
	UnknownElements     int    // elements outside the allowlist that were skipped (X4)
}

// PendingOp is one DS_REPL_OP (msDS-ReplPendingOps value).
type PendingOp struct {
	Enqueued           Time   // ftimeEnqueued
	SerialNumber       U32    // ulSerialNumber
	Priority           U32    // ulPriority
	OpType             U32    // OpType
	Options            U32    // ulOptions
	Partition          Guid   // uuidNamingContextObjGuid
	PartitionDisplayDN string // pszNamingContext; display only
	DSA                Guid   // uuidDsaObjGuid
	DSADNSHost         string // pszDsaAddress; display only
	UnknownElements    int
}

// Failure is one DS_REPL_KCC_DSA_FAILURE (msDS-ReplConnectionFailures and msDS-ReplLinkFailures value).
type Failure struct {
	DSA             Guid // uuidDsaObjGuid
	FirstFailure    Time // ftimeFirstFailure
	Count           U32  // cNumFailures
	LastResultWin32 U32  // dwLastResult
	UnknownElements int
}

// AttrMeta is one DS_REPL_ATTR_META_DATA (msDS-ReplAttributeMetaData value): the name of an
// attribute that changed and when and where, never its value (X7).
type AttrMeta struct {
	AttributeName   string // pszAttributeName
	Version         U32    // dwVersion
	OriginTime      Time   // ftimeLastOriginatingChange
	OriginatingDSA  Guid   // uuidLastOriginatingDsaInvocationID
	OriginatingUSN  U64    // usnOriginatingChange
	LocalUSN        U64    // usnLocalChange
	UnknownElements int
}

// ValueMeta is one DS_REPL_VALUE_META_DATA (msDS-ReplValueMetaData value): a link value's change
// record. The value (the linked object's DN, the value bytes) is dropped; at most the linked
// object's GUID is kept (X7).
type ValueMeta struct {
	AttributeName   string // pszAttributeName
	TargetGUID      Guid   // uuidObjectGuid [UNVERIFIED name]: only where the DC supplies it
	Created         Time   // ftimeCreated
	Deleted         Time   // ftimeDeleted
	Version         U32    // dwVersion
	OriginTime      Time   // ftimeLastOriginatingChange
	OriginatingDSA  Guid   // uuidLastOriginatingDsaInvocationID
	OriginatingUSN  U64    // usnOriginatingChange
	LocalUSN        U64    // usnLocalChange
	UnknownElements int
}
