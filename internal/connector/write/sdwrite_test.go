package write

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// fakeSDSession counts what reaches the directory: ApplyDACL's refusals must leave both at zero.
type fakeSDSession struct {
	id         ad.DCIdentity
	idCalls    int
	writeCalls int
}

func (f *fakeSDSession) DCIdentity(context.Context) (ad.DCIdentity, error) {
	f.idCalls++
	return f.id, nil
}

func (f *fakeSDSession) WriteDACL(context.Context, dn.ObjectRef, sd.DACLWrite, ad.ReplaceSDFunc) error {
	f.writeCalls++
	return nil
}

func testGUID(t *testing.T, s string) guid.GUID {
	t.Helper()
	g, err := guid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// testDACLWrite plans a valid DACLWrite for object g over a hand-built base DACL.
func testDACLWrite(t *testing.T, g guid.GUID) sd.DACLWrite {
	t.Helper()
	conn, err := sid.Parse("S-1-5-21-1-2-3-1105")
	if err != nil {
		t.Fatal(err)
	}
	everyone, _ := sid.Parse("S-1-1-0")
	sys, _ := sid.Parse("S-1-5-18")
	cb := conn.Bytes()
	ace := make([]byte, 8, 8+len(cb)) // ACCESS_ALLOWED, full control for the connector
	ace[2] = byte(8 + len(cb))
	binary.LittleEndian.PutUint32(ace[4:], 0xF01FF)
	ace = append(ace, cb...)
	acl := make([]byte, 8, 8+len(ace))
	acl[0] = 2
	binary.LittleEndian.PutUint16(acl[2:], uint16(8+len(ace)))
	binary.LittleEndian.PutUint16(acl[4:], 1)
	acl = append(acl, ace...)
	hdr := make([]byte, 20)
	hdr[0] = 1
	binary.LittleEndian.PutUint16(hdr[2:], 0x8004) // self-relative, DACL present
	binary.LittleEndian.PutUint32(hdr[16:], 20)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(20+len(acl)))
	raw := append(append(hdr, acl...), sys.Bytes()...)
	base, err := sd.Decode(sd.Raw(raw))
	if err != nil {
		t.Fatal(err)
	}
	w, _, err := sd.PlanDACL(base, sd.ACEDiff{Add: []sd.NewACE{{Trustee: everyone, Mask: sd.MaskReadProp}}}, nil,
		sd.ObjectCtx{ObjectGUID: g, Connector: sd.PrincipalFromToken(conn, []sid.SID{everyone})}, sd.PlanOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestApplyDACLRefusals(t *testing.T) {
	a := testGUID(t, "11111111-0000-0000-0000-00000000000a")
	b := testGUID(t, "22222222-0000-0000-0000-00000000000b")
	dc1 := testGUID(t, "33333333-0000-0000-0000-000000000001")
	dc2 := testGUID(t, "33333333-0000-0000-0000-000000000002")
	tok := func(target, dc guid.GUID) Authorised {
		return Authorised{p: &pass{evaluated: []guid.GUID{target}, dc: dc}}
	}
	ref := dn.GUIDRef(b)

	cases := []struct {
		name string
		tok  Authorised
		w    sd.DACLWrite
		sess *fakeSDSession
		want string
	}{
		{"zero token", Authorised{}, testDACLWrite(t, b), &fakeSDSession{}, "not authorised"},
		{"zero write", tok(b, dc1), sd.DACLWrite{}, &fakeSDSession{}, "not from a planner"},
		{"token for another object", tok(a, dc1), testDACLWrite(t, b), &fakeSDSession{id: ad.DCIdentity{DSAGUID: dc1}}, "did not evaluate"},
		{"token not bound to a DC", tok(b, guid.GUID{}), testDACLWrite(t, b), &fakeSDSession{}, "not bound to a DC"},
		{"session bound to another DC", tok(b, dc1), testDACLWrite(t, b), &fakeSDSession{id: ad.DCIdentity{DSAGUID: dc2}}, "not bound to the DC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ApplyDACL(context.Background(), c.tok, c.sess, ref, c.w)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if c.sess.writeCalls != 0 {
				t.Fatal("a refused write reached the session")
			}
			if c.name != "session bound to another DC" && c.sess.idCalls != 0 {
				t.Fatal("session touched before the token checks passed")
			}
		})
	}

	ok := &fakeSDSession{id: ad.DCIdentity{DSAGUID: dc1}}
	if err := ApplyDACL(context.Background(), tok(b, dc1), ok, ref, testDACLWrite(t, b)); err != nil || ok.writeCalls != 1 {
		t.Fatalf("matching token, object and DC: err=%v writes=%d", err, ok.writeCalls)
	}
}
