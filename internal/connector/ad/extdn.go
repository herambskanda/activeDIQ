package ad

// extendedDN is LDAP_SERVER_EXTENDED_DN_OID (MS-ADTS 3.1.1.3.4.1.5) sent without a value, which
// asks for the hex form: every DN-syntax value comes back as "<GUID=hex>;<SID=S-1-…>;dn" (the SID
// part only for security principals, and only when the DC knows the SID). It is non-critical on
// purpose: a DC that ignores it returns plain DNs, and the consumer then leaves guid and sid
// empty rather than guessing them. The entry's own DN stays plain.
//
// The control is opt-in per operation (ReadOptions.ExtendedDN, SearchRequest.ExtendedDN,
// ScopedRequest.ExtendedDN) because it changes the bytes of every DN-valued attribute, and the
// classifier, rights and parent code compare those as plain DNs.
type extendedDN struct{}

func (extendedDN) GetControlType() string { return oidExtendedDN }
func (extendedDN) Encode() *berPacket     { return encodeValuelessControl(oidExtendedDN) }
func (extendedDN) String() string         { return "Extended DN control" }
