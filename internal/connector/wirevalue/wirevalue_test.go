package wirevalue_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/skenzeriq/activediq/internal/connector/wirevalue"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

var guidRaw = []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
var sidRaw = []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}

// TestOfEverySyntax covers every ldapfilter.Syntax plus the unknown one.
func TestOfEverySyntax(t *testing.T) {
	cases := []struct {
		name string
		attr string
		syn  ldapfilter.Syntax
		raw  []byte
		want *connectorv1.AttributeValue
	}{
		{"string", "cn", ldapfilter.SynString, []byte("Ünï, x"), &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Text{Text: "Ünï, x"}}},
		{"octet", "thumbnailPhoto", ldapfilter.SynOctet, []byte{0, 1, 2}, &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Octets{Octets: []byte{0, 1, 2}}}},
		{"unknown", "x", 0, []byte("abc"), &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Octets{Octets: []byte("abc")}}},
		{"bool true", "isDeleted", ldapfilter.SynBool, []byte("TRUE"), &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Boolean{Boolean: true}}},
		{"bool false", "isDeleted", ldapfilter.SynBool, []byte("FALSE"), &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Boolean{}}},
		{"int32", "userAccountControl", ldapfilter.SynInt32, []byte("512"), &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int32Value{Int32Value: 512}}},
		{"int64", "uSNChanged", ldapfilter.SynInt64, []byte("12345678901"), &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Int64Value{Int64Value: 12345678901}}},
		{"filetime never", "accountExpires", ldapfilter.SynInt64, []byte("0"), &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Time{Time: &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_Sentinel{Sentinel: connectorv1.TimeSentinel_TIME_SENTINEL_ZERO}}}}},
		{"filetime max", "accountExpires", ldapfilter.SynInt64, []byte("9223372036854775807"), &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Time{Time: &connectorv1.TimeValue{Kind: &connectorv1.TimeValue_Sentinel{Sentinel: connectorv1.TimeSentinel_TIME_SENTINEL_MAX}}}}},
		{"sid", "objectSid", ldapfilter.SynSID, sidRaw, &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Sid{Sid: &connectorv1.Sid{Value: sidRaw}}}},
		{"plain dn", "manager", ldapfilter.SynDN, []byte(`CN=Doe\, Jan,OU=Ü,DC=x,DC=y`), &connectorv1.AttributeValue{Value: &connectorv1.AttributeValue_Dn{Dn: &connectorv1.DnValue{DisplayDn: `CN=Doe\, Jan,OU=Ü,DC=x,DC=y`}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := wirevalue.Of(c.attr, c.syn, c.raw)
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(got, c.want) {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
	t.Run("guid", func(t *testing.T) {
		got, err := wirevalue.Of("objectGUID", ldapfilter.SynGUID, guidRaw)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
		if string(got.GetGuid().GetValue()) != string(want) {
			t.Fatalf("guid wire %x", got.GetGuid().GetValue())
		}
	})
	t.Run("generalized time", func(t *testing.T) {
		got, err := wirevalue.Of("whenCreated", ldapfilter.SynGenTime, []byte("20240102030405.0Z"))
		if err != nil || got.GetTime().GetAt().AsTime().Year() != 2024 {
			t.Fatalf("%v %v", got, err)
		}
	})
}

func TestOfBadInputErrors(t *testing.T) {
	for name, c := range map[string]struct {
		syn ldapfilter.Syntax
		raw string
	}{
		"int32": {ldapfilter.SynInt32, "abc"}, "int64": {ldapfilter.SynInt64, "1x"},
		"gentime": {ldapfilter.SynGenTime, "nope"}, "sid": {ldapfilter.SynSID, "\x01"}, "guid": {ldapfilter.SynGUID, "short"},
	} {
		if _, err := wirevalue.Of("a", c.syn, []byte(c.raw)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestOctetsCopies(t *testing.T) {
	raw := []byte{1}
	v, _ := wirevalue.Of("a", ldapfilter.SynOctet, raw)
	raw[0] = 9
	if v.GetOctets()[0] != 1 {
		t.Fatal("aliased")
	}
}
