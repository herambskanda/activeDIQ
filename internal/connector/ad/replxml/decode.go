package replxml

var neighborSpec = &spec{root: "DS_REPL_NEIGHBOR", fields: map[string]kind{
	"pszNamingContext":            kText,
	"pszSourceDsaAddress":         kText,
	"uuidNamingContextObjGuid":    kGUID,
	"uuidSourceDsaObjGuid":        kGUID,
	"ftimeLastSyncAttempt":        kTime,
	"ftimeLastSyncSuccess":        kTime,
	"cNumConsecutiveSyncFailures": kU32,
	"dwLastSyncResult":            kU32,
	"dwReplicaFlags":              kU32,
	// recognised and dropped (not needed; DNs of directory objects stay out, X7)
	"pszSourceDsaDN":               kDrop,
	"uuidSourceDsaInvocationID":    kDrop,
	"usnLastObjChangeSynced":       kDrop,
	"usnAttributeFilter":           kDrop,
	"pszAsyncIntersiteTransportDN": kDrop,
}}

var pendingOpSpec = &spec{root: "DS_REPL_OP", fields: map[string]kind{
	"ftimeEnqueued":            kTime,
	"ulSerialNumber":           kU32,
	"ulPriority":               kU32,
	"OpType":                   kU32,
	"ulOptions":                kU32,
	"pszNamingContext":         kText,
	"pszDsaAddress":            kText,
	"uuidNamingContextObjGuid": kGUID,
	"uuidDsaObjGuid":           kGUID,
	"pszDsaDN":                 kDrop,
}}

var failureSpec = &spec{root: "DS_REPL_KCC_DSA_FAILURE", fields: map[string]kind{
	"uuidDsaObjGuid":    kGUID,
	"ftimeFirstFailure": kTime,
	"cNumFailures":      kU32,
	"dwLastResult":      kU32,
	"pszDsaDN":          kDrop,
}}

var attrMetaSpec = &spec{root: "DS_REPL_ATTR_META_DATA", fields: map[string]kind{
	"pszAttributeName":                   kText,
	"dwVersion":                          kU32,
	"ftimeLastOriginatingChange":         kTime,
	"uuidLastOriginatingDsaInvocationID": kGUID,
	"usnOriginatingChange":               kU64,
	"usnLocalChange":                     kU64,
	"pszLastOriginatingDsaDN":            kDrop,
}}

var valueMetaSpec = &spec{root: "DS_REPL_VALUE_META_DATA", fields: map[string]kind{
	"pszAttributeName":                   kText,
	"uuidObjectGuid":                     kGUID, // [UNVERIFIED] name of the linked object's GUID
	"ftimeCreated":                       kTime,
	"ftimeDeleted":                       kTime,
	"dwVersion":                          kU32,
	"ftimeLastOriginatingChange":         kTime,
	"uuidLastOriginatingDsaInvocationID": kGUID,
	"usnOriginatingChange":               kU64,
	"usnLocalChange":                     kU64,
	// the value itself: validated, never copied (X7)
	"pszObjectDn":             kDrop,
	"cbData":                  kDrop,
	"pbData":                  kDropBig,
	"pszLastOriginatingDsaDN": kDrop,
}}

// DecodeNeighbors decodes one msDS-ReplAllInboundNeighbors value.
func DecodeNeighbors(b []byte) (Neighbor, *DecodeError) {
	p, e := parse(b, neighborSpec, defaultLimits)
	if e != nil {
		return Neighbor{}, e
	}
	return neighborFrom(p)
}

func neighborFrom(p *parsed) (Neighbor, *DecodeError) {
	r := &reader{p: p}
	n := Neighbor{
		Partition:           r.guid("uuidNamingContextObjGuid"),
		PartitionDisplayDN:  r.text("pszNamingContext"),
		SourceDSA:           r.guid("uuidSourceDsaObjGuid"),
		SourceDNSHost:       r.text("pszSourceDsaAddress"),
		LastAttempt:         r.time("ftimeLastSyncAttempt"),
		LastSuccess:         r.time("ftimeLastSyncSuccess"),
		ConsecutiveFailures: r.u32("cNumConsecutiveSyncFailures"),
		LastResultWin32:     r.u32("dwLastSyncResult"),
		Flags:               r.u32("dwReplicaFlags"),
		UnknownElements:     p.unknown,
	}
	if r.err != nil {
		return Neighbor{}, r.err
	}
	return n, nil
}

// DecodePendingOps decodes one msDS-ReplPendingOps value.
func DecodePendingOps(b []byte) (PendingOp, *DecodeError) {
	p, e := parse(b, pendingOpSpec, defaultLimits)
	if e != nil {
		return PendingOp{}, e
	}
	return pendingOpFrom(p)
}

func pendingOpFrom(p *parsed) (PendingOp, *DecodeError) {
	r := &reader{p: p}
	o := PendingOp{
		Enqueued:           r.time("ftimeEnqueued"),
		SerialNumber:       r.u32("ulSerialNumber"),
		Priority:           r.u32("ulPriority"),
		OpType:             r.u32("OpType"),
		Options:            r.u32("ulOptions"),
		Partition:          r.guid("uuidNamingContextObjGuid"),
		PartitionDisplayDN: r.text("pszNamingContext"),
		DSA:                r.guid("uuidDsaObjGuid"),
		DSADNSHost:         r.text("pszDsaAddress"),
		UnknownElements:    p.unknown,
	}
	if r.err != nil {
		return PendingOp{}, r.err
	}
	return o, nil
}

// DecodeFailures decodes one msDS-ReplConnectionFailures or msDS-ReplLinkFailures value.
func DecodeFailures(b []byte) (Failure, *DecodeError) {
	p, e := parse(b, failureSpec, defaultLimits)
	if e != nil {
		return Failure{}, e
	}
	return failureFrom(p)
}

func failureFrom(p *parsed) (Failure, *DecodeError) {
	r := &reader{p: p}
	f := Failure{
		DSA:             r.guid("uuidDsaObjGuid"),
		FirstFailure:    r.time("ftimeFirstFailure"),
		Count:           r.u32("cNumFailures"),
		LastResultWin32: r.u32("dwLastResult"),
		UnknownElements: p.unknown,
	}
	if r.err != nil {
		return Failure{}, r.err
	}
	return f, nil
}

// DecodeAttrMetaData decodes one msDS-ReplAttributeMetaData value. The attribute name is required.
func DecodeAttrMetaData(b []byte) (AttrMeta, *DecodeError) {
	p, e := parse(b, attrMetaSpec, defaultLimits)
	if e != nil {
		return AttrMeta{}, e
	}
	return attrMetaFrom(p)
}

func attrMetaFrom(p *parsed) (AttrMeta, *DecodeError) {
	r := &reader{p: p}
	m := AttrMeta{
		AttributeName:   r.text("pszAttributeName"),
		Version:         r.u32("dwVersion"),
		OriginTime:      r.time("ftimeLastOriginatingChange"),
		OriginatingDSA:  r.guid("uuidLastOriginatingDsaInvocationID"),
		OriginatingUSN:  r.u64("usnOriginatingChange"),
		LocalUSN:        r.u64("usnLocalChange"),
		UnknownElements: p.unknown,
	}
	if r.err == nil && m.AttributeName == "" {
		r.err = fail(CodeMissingField)
	}
	if r.err != nil {
		return AttrMeta{}, r.err
	}
	return m, nil
}

// DecodeValueMetaData decodes one msDS-ReplValueMetaData value. The attribute name is required.
func DecodeValueMetaData(b []byte) (ValueMeta, *DecodeError) {
	p, e := parse(b, valueMetaSpec, defaultLimits)
	if e != nil {
		return ValueMeta{}, e
	}
	return valueMetaFrom(p)
}

func valueMetaFrom(p *parsed) (ValueMeta, *DecodeError) {
	r := &reader{p: p}
	m := ValueMeta{
		AttributeName:   r.text("pszAttributeName"),
		TargetGUID:      r.guid("uuidObjectGuid"),
		Created:         r.time("ftimeCreated"),
		Deleted:         r.time("ftimeDeleted"),
		Version:         r.u32("dwVersion"),
		OriginTime:      r.time("ftimeLastOriginatingChange"),
		OriginatingDSA:  r.guid("uuidLastOriginatingDsaInvocationID"),
		OriginatingUSN:  r.u64("usnOriginatingChange"),
		LocalUSN:        r.u64("usnLocalChange"),
		UnknownElements: p.unknown,
	}
	if r.err == nil && m.AttributeName == "" {
		r.err = fail(CodeMissingField)
	}
	if r.err != nil {
		return ValueMeta{}, r.err
	}
	return m, nil
}

// Budget enforces the per-DC, per-call cap of X2: callers Take the length of each value before
// decoding it. The decoder cannot know how many values one call has fed it, so the caller owns
// the counter; a value over MaxValueBytes is refused by the Decode functions themselves.
type Budget struct{ used int }

// Take charges n bytes and reports too_large once the call total would pass MaxCallBytes.
func (b *Budget) Take(n int) *DecodeError {
	if n < 0 || n > MaxCallBytes-b.used {
		return fail(CodeTooLarge)
	}
	b.used += n
	return nil
}
