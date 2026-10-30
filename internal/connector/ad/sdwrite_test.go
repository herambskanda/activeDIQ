package ad

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/attr/codec"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// An invalid (zero) DACLWrite is refused before the session is touched: nothing is read or sent.
func TestWriteDACLRefusesZeroWrite(t *testing.T) {
	var s Session
	d, err := dn.Parse("CN=x,DC=lab,DC=test", dn.Strict)
	if err != nil {
		t.Fatal(err)
	}
	err = s.WriteDACL(context.Background(), dn.DNRef(d), sd.DACLWrite{}, nil)
	if CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("zero DACLWrite: %v", err)
	}
}

// fakeSD builds a self-relative SD with a DACL of one allow ACE (full control for trustee) and a SYSTEM owner.
func fakeSD(t *testing.T, trustee string, mask uint32) []byte {
	t.Helper()
	tr, err := sid.Parse(trustee)
	if err != nil {
		t.Fatal(err)
	}
	sys, _ := sid.Parse("S-1-5-18")
	tb := tr.Bytes()
	ace := make([]byte, 8, 8+len(tb))
	ace[2] = byte(8 + len(tb))
	binary.LittleEndian.PutUint32(ace[4:], mask)
	ace = append(ace, tb...)
	acl := make([]byte, 8, 8+len(ace))
	acl[0] = 2
	binary.LittleEndian.PutUint16(acl[2:], uint16(8+len(ace)))
	binary.LittleEndian.PutUint16(acl[4:], 1)
	acl = append(acl, ace...)
	hdr := make([]byte, 20)
	hdr[0] = 1
	binary.LittleEndian.PutUint16(hdr[2:], 0x8004)
	binary.LittleEndian.PutUint32(hdr[16:], 20)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(20+len(acl)))
	return append(append(hdr, acl...), sys.Bytes()...)
}

// A stale base sends nothing (T-0743 nit): the directory holds a different DACL than the plan's base,
// so VerifyBase fails on the fresh read and no Modify reaches the wire. The matching base sends one,
// and ReadDACL returns the stored SD from the same session.
func TestWriteDACLStaleBaseSendsNothing(t *testing.T) {
	obj := guid.GUID{0xC0, 15: 1}
	conn, _ := sid.Parse("S-1-5-21-1-2-3-1105")
	everyone, _ := sid.Parse("S-1-1-0")
	baseRaw := fakeSD(t, conn.String(), 0xF01FF)
	base, err := sd.Decode(sd.Raw(baseRaw))
	if err != nil {
		t.Fatal(err)
	}
	w, _, err := sd.PlanDACL(base, sd.ACEDiff{Add: []sd.NewACE{{Trustee: everyone, Mask: sd.MaskReadProp}}}, nil,
		sd.ObjectCtx{ObjectGUID: obj, Connector: sd.PrincipalFromToken(conn, []sid.SID{everyone})}, sd.PlanOpts{})
	if err != nil {
		t.Fatal(err)
	}
	sent := 0
	send := func(m Modifier, _ string, _ []byte, ctrls []ldap.Control) error {
		sent++
		req := ldap.NewModifyRequest("CN=x,DC=lab,DC=test", ctrls)
		req.Replace("nTSecurityDescriptor", []string{"x"})
		return m.Modify(req)
	}
	run := func(serving []byte) (*fakeUpstream, error) {
		up := startFakeUpstream(t, 0)
		up.sdAttrs = map[string][][]byte{"objectGUID": {obj.Bytes()}, "nTSecurityDescriptor": {serving}}
		s, _ := faultSession(t, up.dial, injectPlan{skip: 1 << 30})
		return up, s.WriteDACL(context.Background(), dn.GUIDRef(obj), w, send)
	}

	up, err := run(fakeSD(t, conn.String(), 0x1)) // someone changed the DACL since the plan
	if codec.Code(err) != sd.ErrStaleBase || sent != 0 || up.modifyCount() != 0 {
		t.Fatalf("stale base: err=%v sent=%d modifies=%d", err, sent, up.modifyCount())
	}
	up, err = run(baseRaw)
	if err != nil || sent != 1 || up.modifyCount() != 1 {
		t.Fatalf("matching base: err=%v sent=%d modifies=%d", err, sent, up.modifyCount())
	}
}
