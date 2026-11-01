//go:build lab && windowslab

package tier0

// Windows-lab proof of TM-D26 (T-0346): what Samba cannot show. The classifier reads the live
// nTSecurityDescriptor of the domain head from a real Windows Server DC and must classify
//
//	C17 DACL      an allow ACE with WRITE_DAC                         -> tier0
//	C17 owner     ownership of the domain head                        -> tier0 (rule 3)
//	C17 callback  allow callback ACEs 0x09 / 0x0B                     -> tier0 (rule 4); deny callback 0x0A -> not
//	C18           cross-domain sIDHistory                             -> tier0 or fails closed (rule 6b/8)
//
// Every positive case has a negative twin. Run: `make lab-test-connector-windows` style env
// (WIN_LAB_MODE=external WIN_LAB_DC_ADDR=… WIN_LAB_TLS_NAME=…), then
//
//	go test -tags 'lab windowslab' -run TestWinLabTM26 -v ./internal/connector/tier0
//
// The admin bind (Administrator, from the gitignored lab env file) is used only to plant and remove
// test state; the classifier runs as the delegated service account. The domain head's DACL and owner
// are restored in t.Cleanup from the bytes read before the first change; if the lab is left dirty,
// revert it to the `clean` snapshot (runbook windows-lab.md §10).

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

const (
	winOU       = "OU=Managed," + winDom
	winSDFlags  = "1.2.840.113556.1.4.801"
	sdfOwner    = 1
	sdfDACL     = 4
	aceAllowCB  = 0x09
	aceDenyCB   = 0x0A
	aceAllowCBO = 0x0B
)

// sdFlagsControl is the LDAP_SERVER_SD_FLAGS_OID control (MS-ADTS 3.1.1.3.4.1.11).
type sdFlagsControl int

func (sdFlagsControl) GetControlType() string { return winSDFlags }
func (c sdFlagsControl) Encode() *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, winSDFlags, "Control Type"))
	p.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	v := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control Value")
	v.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c), "Flags"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v.Bytes()), "Control Value"))
	return p
}
func (c sdFlagsControl) String() string { return fmt.Sprintf("SD_FLAGS(%d)", int(c)) }

// newUser creates a disabled user in OU=Managed and returns its DN and SID text.
func (l *winLab) newUser(tag string) (string, string) {
	l.t.Helper()
	name := fmt.Sprintf("t0346-%s-%d", tag, time.Now().UnixNano()%1_000_000)
	d := "CN=" + name + "," + winOU
	add := ldap.NewAddRequest(d, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{name})
	if err := l.admin.Add(add); err != nil {
		l.t.Fatalf("create %s: %v", d, err)
	}
	l.t.Cleanup(func() { _ = l.admin.Del(ldap.NewDelRequest(d, nil)) })
	e := l.read(d, nil, "objectSid")
	s, err := sid.FromBytes([]byte(e.GetRawAttributeValue("objectSid")))
	if err != nil {
		l.t.Fatal(err)
	}
	return d, s.String()
}

// sdParts splits a self-relative descriptor into its owner SID bytes and DACL bytes.
func sdParts(raw []byte) (owner, dacl []byte) {
	if len(raw) < 20 {
		return nil, nil
	}
	oOff := binary.LittleEndian.Uint32(raw[4:])
	dOff := binary.LittleEndian.Uint32(raw[16:])
	if oOff != 0 {
		n := 8 + 4*int(raw[oOff+1])
		owner = raw[oOff : int(oOff)+n]
	}
	if dOff != 0 {
		size := int(binary.LittleEndian.Uint16(raw[dOff+2:]))
		dacl = raw[dOff : int(dOff)+size]
	}
	return owner, dacl
}

func sdWithDACL(acl []byte) []byte {
	b := []byte{1, 0}
	b = binary.LittleEndian.AppendUint16(b, 0x8004)
	for _, off := range []uint32{0, 0, 0, 20} {
		b = binary.LittleEndian.AppendUint32(b, off)
	}
	return append(b, acl...)
}

func sdWithOwner(owner []byte) []byte {
	b := []byte{1, 0}
	b = binary.LittleEndian.AppendUint16(b, 0x8000)
	for _, off := range []uint32{20, 0, 0, 0} {
		b = binary.LittleEndian.AppendUint32(b, off)
	}
	return append(b, owner...)
}

// aceBytes encodes one ACE: type, mask, trustee; the callback types carry 4 bytes of (opaque)
// application data, as the fake in adfake_test.go does. The 0x0B form has no object GUIDs.
func aceBytes(typ byte, mask uint32, trustee string) []byte {
	s, err := sid.Parse(trustee)
	if err != nil {
		panic(err)
	}
	var hdr []byte
	if typ == aceAllowCBO || typ == 0x0C {
		hdr = make([]byte, 4)
	}
	sb := s.Bytes()
	var tail []byte
	if typ >= aceAllowCB && typ <= 0x0C {
		tail = make([]byte, 4)
	}
	a := []byte{typ, 0}
	a = binary.LittleEndian.AppendUint16(a, uint16(8+len(hdr)+len(sb)+len(tail)))
	a = binary.LittleEndian.AppendUint32(a, mask)
	a = append(a, hdr...)
	a = append(a, sb...)
	return append(a, tail...)
}

func appendACE(acl, ace []byte) []byte {
	out := append(append([]byte{}, acl...), ace...)
	binary.LittleEndian.PutUint16(out[2:], uint16(len(out)))
	binary.LittleEndian.PutUint16(out[4:], binary.LittleEndian.Uint16(acl[4:])+1)
	return out
}

func (l *winLab) writeSD(d string, flags int, sd []byte) error {
	m := ldap.NewModifyRequest(d, []ldap.Control{sdFlagsControl(flags)})
	m.Replace("nTSecurityDescriptor", []string{string(sd)})
	return l.admin.Modify(m)
}

// snapshotHead reads the owner and DACL of the domain head and registers their restoration.
func (l *winLab) snapshotHead() (owner, dacl []byte) {
	l.t.Helper()
	e := l.read(l.head, sdFlagsControl(sdfOwner|sdfDACL), "nTSecurityDescriptor")
	owner, dacl = sdParts([]byte(e.GetRawAttributeValue("nTSecurityDescriptor")))
	if owner == nil || dacl == nil {
		l.t.Fatalf("domain head SD unreadable: %d bytes", len(e.GetRawAttributeValue("nTSecurityDescriptor")))
	}
	l.t.Cleanup(func() {
		if err := l.writeSD(l.head, sdfDACL, sdWithDACL(dacl)); err != nil {
			l.t.Errorf("LAB DIRTY: restoring domain head DACL failed (%v); revert VM to snapshot clean", err)
		}
		if err := l.writeSD(l.head, sdfOwner, sdWithOwner(owner)); err != nil {
			l.t.Errorf("LAB DIRTY: restoring domain head owner failed (%v); revert VM to snapshot clean", err)
		}
	})
	return owner, dacl
}

func (l *winLab) classify(userDN string) ADResult {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	ref, err := dn.ParseObjectRef(userDN)
	if err != nil {
		l.t.Fatal(err)
	}
	r, err := l.cls.Classify(ctx, ref, ADInput{CorrelationKnown: true})
	if err != nil {
		l.t.Fatalf("classify %s: %v", userDN, err)
	}
	return r
}

func (l *winLab) wantC17(userDN string, want bool, why string) {
	l.t.Helper()
	r := l.classify(userDN)
	if has(r, C17) != want {
		l.t.Errorf("%s: C17 = %v, want %v (bases %v)", why, has(r, C17), want, r.Bases)
	}
}

// AC1 (DACL): WRITE_DAC on the live domain head makes the holder tier0; a read-only ACE does not.
func TestWinLabTM26DACL(t *testing.T) { // T0-C17-DACL on Windows
	l := newWinLab(t)
	_, dacl := l.snapshotHead()
	holder, holderSID := l.newUser("wdacl")
	reader, readerSID := l.newUser("rdonly")
	l.wantC17(holder, false, "holder before the ACE")
	acl := appendACE(dacl, aceBytes(0x00, 0x40000, holderSID)) // ACCESS_ALLOWED, WRITE_DAC
	acl = appendACE(acl, aceBytes(0x00, 0x10, readerSID))      // ADS_RIGHT_DS_READ_PROP
	if err := l.writeSD(l.head, sdfDACL, sdWithDACL(acl)); err != nil {
		t.Fatalf("plant DACL: %v", err)
	}
	l.wantC17(holder, true, "WRITE_DAC on the domain head")
	l.wantC17(reader, false, "read-only twin")
}

// AC1 (owner): ownership of the domain head is tier0 whatever the DACL says (rule 3).
func TestWinLabTM26Owner(t *testing.T) { // T0-C17-OWNER on Windows
	l := newWinLab(t)
	l.snapshotHead()
	owner, ownerSID := l.newUser("owner")
	twin, _ := l.newUser("nown")
	l.wantC17(owner, false, "future owner before the change")
	s, err := sid.Parse(ownerSID)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.writeSD(l.head, sdfOwner, sdWithOwner(s.Bytes())); err != nil {
		t.Fatalf("set owner of the domain head to a plain user over LDAP: %v", err)
	}
	l.wantC17(owner, true, "owner of the domain head")
	l.wantC17(twin, false, "non-owner twin")
}

// AC1 (callback ACEs): allow callbacks count as unconditional allows; a deny callback grants nothing.
// If Windows refuses to store a callback ACE in a directory DACL, the refusal is the finding: the
// test fails naming the status instead of passing silently (spec divergence -> M2 follow-up).
func TestWinLabTM26CallbackACEs(t *testing.T) { // T0-CB-CALLBACK on Windows
	l := newWinLab(t)
	_, dacl := l.snapshotHead()
	for _, tc := range []struct {
		name string
		typ  byte
		want bool
	}{{"allow-callback-0x09", aceAllowCB, true}, {"allow-callback-object-0x0B", aceAllowCBO, true}, {"deny-callback-0x0A", aceDenyCB, false}} {
		t.Run(tc.name, func(t *testing.T) {
			l.t = t
			u, us := l.newUser("cb")
			l.wantC17(u, false, "before the ACE")
			acl := appendACE(dacl, aceBytes(tc.typ, 0x40000, us))
			if err := l.writeSD(l.head, sdfDACL, sdWithDACL(acl)); err != nil {
				t.Fatalf("Windows refused to store ACE type %#x in the domain head DACL: %v", tc.typ, err)
			}
			t.Cleanup(func() { _ = l.writeSD(l.head, sdfDACL, sdWithDACL(dacl)) })
			l.wantC17(u, tc.want, tc.name)
		})
	}
}

// AC2 (sIDHistory): a SID from another domain cannot be written over LDAP on Windows (only
// DsAddSidHistory across a trust can), so a single-domain lab cannot plant one. This test pins
// what a Windows DC does offer: it refuses the write (so a lab user cannot be made privileged
// through LDAP), the GC answers a lookup of a foreign-prefix SID with "not found" rather than an
// error, and an account with no sIDHistory is not C18. The cross-domain Tier-0 case itself needs a
// second domain with a trust: follow-up filed (see the ticket note).
func TestWinLabTM26SIDHistoryCrossDomain(t *testing.T) { // T0-C18-FOREIGN on Windows
	l := newWinLab(t)
	u, _ := l.newUser("sidh")
	if r := l.classify(u); has(r, C18) {
		t.Errorf("no sIDHistory but C18 set: %v", r.Bases)
	}
	// A foreign domain's Domain Admins SID (RID 512). Windows must refuse the write.
	m := ldap.NewModifyRequest(u, nil)
	m.Replace("sIDHistory", []string{string(mustSIDBytes(t, "S-1-5-21-111111111-222222222-333333333-512"))})
	err := l.admin.Modify(m)
	if err == nil {
		t.Fatal("Windows accepted an LDAP write of sIDHistory: spec assumption (only DsAddSidHistory) is wrong; classify it and revise the lab note")
	}
	t.Logf("LDAP write of sIDHistory refused as expected: %v", err)
	if r := l.classify(u); has(r, C18) {
		t.Errorf("refused write must leave the account non-C18: %v", r.Bases)
	}
}

// AC2 (GC half): the classifier resolves a foreign-domain sIDHistory value through the Global
// Catalog (rule 6b). On Windows the GC must open and answer by SID. KNOWN BUG T-0619: OpenGC fails
// on a real GC, so every foreign-domain value fails closed. Deliberately red until T-0619 is fixed;
// not skipped, so the failure stays visible in every Windows-lab run.
func TestWinLabTM26GCOpens(t *testing.T) { // T0-C18-GC on Windows
	l := newWinLab(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	gc, err := ad.OpenGC(ctx, ad.Config{Servers: []string{l.host + ":3269"}, ServerName: winTLSName(), RootCAs: l.pool, PageSize: 500, Credential: l.svc})
	if err != nil {
		t.Fatalf("KNOWN BUG T-0619: OpenGC against the Windows GC: %v", err)
	}
	defer gc.Close()
	adm, _ := sid.Parse(l.prefix + "-500")
	if e, found, err := gc.LookupSID(ctx, adm, []string{"sAMAccountName"}); err != nil || !found || e == nil {
		t.Errorf("GC lookup of %s: found=%v err=%v", adm, found, err)
	}
	foreign, _ := sid.Parse("S-1-5-21-111111111-222222222-333333333-512")
	if _, found, err := gc.LookupSID(ctx, foreign, []string{"sAMAccountName"}); err != nil || found {
		t.Errorf("GC lookup of a foreign SID: found=%v err=%v", found, err)
	}
	doms, err := gc.DomainSIDs(ctx)
	if err != nil || len(doms) == 0 {
		t.Fatalf("forest domains from the GC: %v %v", doms, err)
	}
	// With a GC the classifier answers: an account with no sIDHistory stays non-C18.
	u, _ := l.newUser("gcsidh")
	cls := NewAD(SessionDirectory{S: l.sess, GC: gc})
	ref, _ := dn.ParseObjectRef(u)
	if r, err := cls.Classify(ctx, ref, ADInput{CorrelationKnown: true}); err != nil || has(r, C18) {
		t.Errorf("classify with GC: %v %v", r.Bases, err)
	}
}

func mustSIDBytes(t *testing.T, s string) []byte {
	t.Helper()
	v, err := sid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return v.Bytes()
}
