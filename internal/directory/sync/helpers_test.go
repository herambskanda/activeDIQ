package sync_test

import (
	"encoding/binary"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// gid is a connector Guid whose canonical text is "00000000-0000-4000-8000-" + 12 hex digits of n:
// the RFC 4122 byte order the contract carries.
func gid(n uint64) *connectorv1.Guid {
	b := []byte{0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0}
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], n)
	copy(b[10:], t[2:])
	return &connectorv1.Guid{Value: b}
}

func gtext(n uint64) string {
	const h = "0123456789abcdef"
	s := []byte("00000000-0000-4000-8000-000000000000")
	for i := 0; i < 12; i++ {
		s[35-i] = h[(n>>(4*uint(i)))&0xf]
	}
	return string(s)
}

// domSID is S-1-5-21-1-2-3-<rid>, binary.
func domSID(rid uint32) *connectorv1.Sid {
	b := make([]byte, 8+4*5)
	b[0], b[1], b[7] = 1, 5, 5
	for i, v := range []uint32{21, 1, 2, 3, rid} {
		binary.LittleEndian.PutUint32(b[8+4*i:], v)
	}
	return &connectorv1.Sid{Value: b}
}

func sidBytes(rid uint32) []byte { return domSID(rid).Value }

type attrs []*connectorv1.Attribute

func (a attrs) with(name string, vs ...*connectorv1.AttributeValue) attrs {
	return append(a, &connectorv1.Attribute{Name: name, Values: vs, Complete: true})
}

func txt(s string) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Text{Text: s}}
}

func i32(n int32) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int32Value{Int32Value: n}}
}

func boolean(b bool) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Boolean{Boolean: b}}
}

func sidv(s *connectorv1.Sid) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Sid{Sid: s}}
}

func dnv(display string, g *connectorv1.Guid) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Dn{Dn: &connectorv1.DnValue{DisplayDn: display, Guid: g}}}
}

func at(t time.Time) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Time{Time: &connectorv1.TimeValue{
		Kind: &connectorv1.TimeValue_At{At: timestamppb.New(t)}}}}
}

func sentinel(s connectorv1.TimeSentinel) *connectorv1.AttributeValue {
	return &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Time{Time: &connectorv1.TimeValue{
		Kind: &connectorv1.TimeValue_Sentinel{Sentinel: s}}}}
}

func (a attrs) classes(cs ...string) attrs {
	at := &connectorv1.Attribute{Name: "objectClass", Complete: true}
	for _, c := range cs {
		at.Values = append(at.Values, txt(c))
	}
	return append(a, at)
}

func (a attrs) gentime(name string, t time.Time) attrs { return a.with(name, at(t)) }

const (
	domainNC = 1
	ouGUID   = 2
)

func entry(obj uint64, dn string, parent *connectorv1.Guid, as attrs) *connectorv1.DirectoryEntry {
	return &connectorv1.DirectoryEntry{ObjectGuid: gid(obj), Dn: &connectorv1.DnValue{DisplayDn: dn}, ParentGuid: parent, Attributes: as}
}

func mapper(cfg dirsync.Config) *dirsync.Mapper {
	if cfg.NC == "" {
		cfg.NC = inventory.GUID(gtext(domainNC))
	}
	m, err := dirsync.NewMapper(cfg)
	if err != nil {
		panic(err)
	}
	return m
}

// domainSID is S-1-5-21-1-2-3, the domain object's own SID (four sub-authorities).
func domainSID() *connectorv1.Sid {
	b := make([]byte, 8+4*4)
	b[0], b[1], b[7] = 1, 4, 5
	for i, v := range []uint32{21, 1, 2, 3} {
		binary.LittleEndian.PutUint32(b[8+4*i:], v)
	}
	return &connectorv1.Sid{Value: b}
}
