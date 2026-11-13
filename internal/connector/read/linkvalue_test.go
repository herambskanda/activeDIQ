package read_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/write"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1202: DN-syntax values read with the extended-DN control become DnValue{display_dn, guid, sid};
// a part the DC did not send stays empty.
func TestDnValuesCarryIdentityWhenSupplied(t *testing.T) {
	memberGUID := g("bbbbbbbb-0000-0000-0000-000000000001")
	foreign := g("bbbbbbbb-0000-0000-0000-000000000002")
	s1, err := sid.Parse("S-1-5-21-1-2-3-1105")
	if err != nil {
		t.Fatal(err)
	}
	ext := func(id [16]byte, rest string) []byte {
		return []byte("<GUID=" + hex.EncodeToString(id[:]) + ">;" + rest)
	}
	mg, fg := memberGUID.Bytes(), foreign.Bytes()
	vals := [][]byte{
		ext([16]byte(mg), "<SID=S-1-5-21-1-2-3-1105>;CN=Smith\\, Ann,OU=Ü,DC=lab,DC=test"),                   // principal
		ext([16]byte(fg), "CN=Group,DC=lab,DC=test"),                                                         // no SID: not a principal
		[]byte("<SID=S-1-5-21-9-9-9-500>;CN=S-1-5-21-9-9-9-500,CN=ForeignSecurityPrincipals,DC=lab,DC=test"), // no GUID
		[]byte("CN=Plain,DC=lab,DC=test"),                                                                    // DC ignored the control
	}
	s := &ssrc{src: &src{dsa: dsaA}, entries: []*ad.Entry{ad.NewEntry("CN=grp,DC=lab", map[string][][]byte{
		"objectGUID": {g(objGUID).Bytes()}, "member": vals})}}
	r := sreq()
	r.Attributes = []string{"member"}
	ms, err := searchAll(start(t, s), r)
	if err != nil {
		t.Fatal(err)
	}
	got := ms[0].GetBatch().GetEntries()[0].GetAttributes()[0].GetValues()
	if len(got) != 4 {
		t.Fatalf("values %d", len(got))
	}
	d := func(i int) *connectorv1.DnValue { return got[i].GetDn() }
	if d(0).GetDisplayDn() != "CN=Smith\\, Ann,OU=Ü,DC=lab,DC=test" ||
		!bytes.Equal(d(0).GetGuid().GetValue(), write.GUIDToWire(memberGUID).GetValue()) ||
		!bytes.Equal(d(0).GetSid().GetValue(), s1.Bytes()) {
		t.Errorf("principal: %v", d(0))
	}
	if !bytes.Equal(d(1).GetGuid().GetValue(), write.GUIDToWire(foreign).GetValue()) || d(1).GetSid() != nil || d(1).GetDisplayDn() != "CN=Group,DC=lab,DC=test" {
		t.Errorf("no-SID: %v", d(1))
	}
	if d(2).GetGuid() != nil || d(2).GetSid() == nil || d(2).GetDisplayDn() == "" {
		t.Errorf("no-GUID: %v", d(2))
	}
	if d(3).GetGuid() != nil || d(3).GetSid() != nil || d(3).GetDisplayDn() != "CN=Plain,DC=lab,DC=test" {
		t.Errorf("plain: %v", d(3))
	}
}

func TestMalformedExtendedDnIsProviderFailure(t *testing.T) {
	s := &ssrc{src: &src{dsa: dsaA}, entries: []*ad.Entry{ad.NewEntry("CN=grp,DC=lab", map[string][][]byte{
		"objectGUID": {g(objGUID).Bytes()}, "member": {[]byte("<GUID=zz>;CN=x,DC=lab")}})}}
	r := sreq()
	r.Attributes = []string{"member"}
	if _, err := searchAll(start(t, s), r); code(err) != connectorv1.ErrorCode_ERROR_CODE_PROVIDER_FAILURE {
		t.Fatalf("got %v", err)
	}
}
