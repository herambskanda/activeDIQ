package read_test

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/read"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// csrc adds the child-count half to the Read fake.
type csrc struct {
	*src
	n      int
	capped bool
	limit  int
}

func (c *csrc) CountChildren(_ context.Context, _ guid.GUID, limit int) (int, bool, error) {
	c.limit = limit
	return c.n, c.capped, nil
}

func ccEntry(classes ...string) *ad.Entry {
	var oc [][]byte
	for _, c := range classes {
		oc = append(oc, []byte(c))
	}
	return entry(map[string][][]byte{"cn": {[]byte("Dept")}, "objectClass": oc})
}

func ccReq() *connectorv1.ReadRequest {
	r := req("", false)
	r.IncludeChildCount = true
	return r
}

func TestChildCountOnContainers(t *testing.T) {
	for name, tc := range map[string]struct {
		n      int
		capped bool
	}{"empty": {0, false}, "three": {3, false}, "capped": {1000, true}} {
		t.Run(name, func(t *testing.T) {
			c := &csrc{src: &src{dsa: dsaA, entry: ccEntry("top", "organizationalUnit")}, n: tc.n, capped: tc.capped}
			ms, err := collect(t, start(t, c), ccReq())
			if err != nil {
				t.Fatal(err)
			}
			cc := ms[0].GetHeader().GetChildCount()
			if cc == nil || int(cc.GetCount()) != tc.n || cc.GetCapped() != tc.capped {
				t.Fatalf("child_count %v", cc)
			}
			if c.limit != read.ChildCountCap {
				t.Fatalf("limit %d", c.limit)
			}
		})
	}
}

func TestChildCountAbsentUnlessAsked(t *testing.T) {
	c := &csrc{src: &src{dsa: dsaA, entry: ccEntry("top", "organizationalUnit")}, n: 5}
	ms, err := collect(t, start(t, c), req("", false))
	if err != nil || ms[0].GetHeader().GetChildCount() != nil {
		t.Fatalf("%v %v", err, ms[0].GetHeader().GetChildCount())
	}
}

func TestChildCountRefusesNonContainerAndMissingCapability(t *testing.T) {
	c := &csrc{src: &src{dsa: dsaA, entry: ccEntry("top", "person", "organizationalPerson", "user")}}
	_, err := collect(t, start(t, c), ccReq())
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
		t.Fatalf("user: %v", err)
	}
	plain := &src{dsa: dsaA, entry: ccEntry("top", "organizationalUnit")}
	_, err = collect(t, start(t, plain), ccReq())
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("no capability: %v", err)
	}
}
