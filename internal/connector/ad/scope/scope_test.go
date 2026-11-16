package scope

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// roundTrip serialises a control as the wire does and parses it back.
func roundTrip(t *testing.T, c ldap.Control) *ber.Packet {
	t.Helper()
	p, err := ber.DecodePacketErr(c.Encode().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDirSyncControlWire(t *testing.T) {
	cookie := []byte{0xde, 0xad, 0xbe, 0xef}
	c := DirSync(cookie)
	if c.GetControlType() != "1.2.840.113556.1.4.841" {
		t.Fatalf("oid %s", c.GetControlType())
	}
	p := roundTrip(t, c)
	if len(p.Children) != 3 {
		t.Fatalf("children %d", len(p.Children))
	}
	if crit, _ := p.Children[1].Value.(bool); !crit {
		t.Error("DirSync control is not critical")
	}
	val, err := ber.DecodePacketErr(p.Children[2].Data.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	seq := val.Children
	if len(seq) != 3 {
		t.Fatalf("value children %d", len(seq))
	}
	// AD reads the flags as a four-byte unsigned integer: object security | incremental values.
	if want := []byte{0x80, 0x00, 0x00, 0x01}; !bytes.Equal(seq[0].Data.Bytes(), want) {
		t.Errorf("flags bytes % x, want % x", seq[0].Data.Bytes(), want)
	}
	if DirSyncFlags != 0x80000001 {
		t.Errorf("DirSyncFlags %#x", uint32(DirSyncFlags))
	}
	if !bytes.Equal(seq[2].Data.Bytes(), cookie) {
		t.Errorf("cookie % x", seq[2].Data.Bytes())
	}
	// No cookie on the first request: an empty octet string, not an absent one.
	first := roundTrip(t, DirSync(nil))
	v, _ := ber.DecodePacketErr(first.Children[2].Data.Bytes())
	if len(v.Children) != 3 || v.Children[2].Data.Len() != 0 {
		t.Errorf("first-request cookie not empty: %d children", len(v.Children))
	}
}

func TestShowDeletedControlWire(t *testing.T) {
	c := ShowDeleted()
	if c.GetControlType() != "1.2.840.113556.1.4.417" {
		t.Fatalf("oid %s", c.GetControlType())
	}
	p := roundTrip(t, c)
	if crit, _ := p.Children[1].Value.(bool); !crit || len(p.Children) != 2 {
		t.Errorf("show-deleted: critical=%v children=%d", crit, len(p.Children))
	}
}

func TestDirSyncResponse(t *testing.T) {
	r, ok := DirSyncResponse([]ldap.Control{&ldap.ControlDirSync{Flags: 1, Cookie: []byte{1, 2}}})
	if !ok || !r.MoreResults || !bytes.Equal(r.Cookie, []byte{1, 2}) {
		t.Errorf("%+v %v", r, ok)
	}
	r, ok = DirSyncResponse([]ldap.Control{&ldap.ControlDirSync{Flags: 0, Cookie: []byte{3}}})
	if !ok || r.MoreResults {
		t.Errorf("%+v %v", r, ok)
	}
	if _, ok := DirSyncResponse(nil); ok {
		t.Error("no control must be ok=false")
	}
}
