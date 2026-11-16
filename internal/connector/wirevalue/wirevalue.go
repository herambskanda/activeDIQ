// Package wirevalue builds a connectorv1.AttributeValue from the raw bytes a directory returned
// (connector-contract §5.9.1). It is the one place that switches on the schema syntax: read and
// write both call Of, so a value has the same typed form wherever it leaves the connector.
//
// It is a leaf: it imports neither internal/connector/read nor internal/connector/write.
package wirevalue

import (
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/filetime"
	"github.com/skenzeriq/activediq/internal/directory/attr/gentime"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// GUIDToWire converts an attr/guid value to the v1.Guid wire form (RFC 4122 byte order).
func GUIDToWire(g guid.GUID) *connectorv1.Guid {
	s := g.String()
	b, err := hex.DecodeString(s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:])
	if err != nil { // String is canonical by construction
		return &connectorv1.Guid{}
	}
	return &connectorv1.Guid{Value: b}
}

// Of decodes one raw value of attribute name by its schema syntax. An unknown syntax (or SynOctet)
// stays octets. A value that does not parse as its syntax is an error: callers decide whether to
// refuse or to fall back to octets.
func Of(name string, syn ldapfilter.Syntax, raw []byte) (*connectorv1.AttributeValue, error) {
	switch syn {
	case ldapfilter.SynString:
		return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Text{Text: string(raw)}}, nil
	case ldapfilter.SynDN:
		lv, err := dn.ParseLinkValue(string(raw))
		if err != nil {
			return nil, err
		}
		v := &connectorv1.DnValue{DisplayDn: lv.DN}
		if lv.HasGUID { // only what the DC sent: a plain DN stays without identity
			v.Guid = GUIDToWire(lv.GUID)
		}
		if lv.HasSID {
			v.Sid = &connectorv1.Sid{Value: lv.SID.Bytes()}
		}
		return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Dn{Dn: v}}, nil
	case ldapfilter.SynBool:
		return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Boolean{Boolean: string(raw) == "TRUE"}}, nil
	case ldapfilter.SynInt32:
		n, err := codec.ParseInteger(string(raw), 32)
		if err != nil {
			return nil, err
		}
		return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int32Value{Int32Value: int32(n)}}, nil
	case ldapfilter.SynInt64:
		n, err := codec.ParseInteger(string(raw), 64)
		if err != nil {
			return nil, err
		}
		if _, ferr := filetime.FieldFor(name); ferr == nil {
			return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Time{Time: timeOf(n)}}, nil
		}
		return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int64Value{Int64Value: n}}, nil
	case ldapfilter.SynGenTime:
		t, err := gentime.Parse(string(raw))
		if err != nil {
			return nil, err
		}
		return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Time{Time: &connectorv1.TimeValue{
			Kind: &connectorv1.TimeValue_At{At: timestamppb.New(t)}}}}, nil
	case ldapfilter.SynSID:
		if _, err := sid.FromBytes(raw); err != nil {
			return nil, err
		}
		return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Sid{Sid: &connectorv1.Sid{Value: append([]byte(nil), raw...)}}}, nil
	case ldapfilter.SynGUID:
		g, err := guid.FromBytes(raw)
		if err != nil {
			return nil, err
		}
		return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Guid{Guid: GUIDToWire(g)}}, nil
	}
	return Octets(raw), nil
}

// Octets wraps raw bytes (copied) as an octet value.
func Octets(raw []byte) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Octets{Octets: append([]byte(nil), raw...)}}
}

// timeOf maps the Integer8 form of a FILETIME attribute: 0 and max stay the two "never" sentinels,
// a beyond-range value keeps its ticks.
func timeOf(n int64) *connectorv1.TimeValue {
	switch {
	case n == 0:
		return &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_Sentinel{Sentinel: connectorv1.TimeSentinel_TIME_SENTINEL_ZERO}}
	case n == 1<<63-1:
		return &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_Sentinel{Sentinel: connectorv1.TimeSentinel_TIME_SENTINEL_MAX}}
	case n < 0 || n > filetime.MaxInstantTicks:
		return &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_FiletimeTicksOutOfRange{FiletimeTicksOutOfRange: n}}
	}
	const unixEpoch = 116_444_736_000_000_000
	ticks := n - unixEpoch
	return &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_At{At: timestamppb.New(time.Unix(ticks/10_000_000, (ticks%10_000_000)*100).UTC())}}
}
