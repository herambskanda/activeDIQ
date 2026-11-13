package writechange

import (
	"testing"

	"github.com/skenzeriq/activediq/internal/platform/operation/step"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

func TestBuildersRoundTripThroughDecode(t *testing.T) {
	ca, err := CreateAttrs(CreateSpec{RDN: "Smith, Ann Ü", Enabled: true, HasSecret: true,
		Set: []Edit{{Op: "set", Attribute: "sAMAccountName", Values: []string{"asmith"}}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := Decode(KeyObjectCreate, ca)
	if err != nil {
		t.Fatal(err)
	}
	if oc := c.GetObjectCreate(); oc.GetRdnValue() != "Smith, Ann Ü" || !oc.GetAccountEnabled() || !oc.GetHasSecretInput() || len(oc.GetInitial()) != 1 {
		t.Fatalf("create %v", oc)
	}
	ua, err := UpdateAttrs([]Edit{{Op: "set", Attribute: "title", Values: []string{"Dev"}}, {Op: "clear", Attribute: "info"}})
	if err != nil {
		t.Fatal(err)
	}
	k, back, err := Encode(mustDecode(t, KeyObjectUpdate, ua))
	if err != nil || k != KeyObjectUpdate || len(back) != len(ua) || back[0].Name != ua[0].Name {
		t.Fatalf("update round trip %v %v", back, err)
	}
	if _, err := UpdateAttrs([]Edit{{Op: "bogus", Attribute: "x"}}); err == nil {
		t.Fatal("unknown op accepted")
	}
}

func mustDecode(t *testing.T, key string, a []step.Attr) *connectorv1.WriteChange {
	t.Helper()
	c, err := Decode(key, a)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
