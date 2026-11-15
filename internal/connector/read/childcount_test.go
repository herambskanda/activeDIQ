package read_test

import (
	"context"
	"errors"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
	"github.com/skenzeriq/activediq/internal/directory/client"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// counting is a Source that also counts children, as ADSource does.
type counting struct {
	*src
	n      uint32
	capped bool
	err    error
	asked  uint32
}

func (c *counting) CountChildren(_ context.Context, _ guid.GUID, limit uint32) (uint32, bool, error) {
	c.asked = limit
	c.calls = append(c.calls, "count")
	return c.n, c.capped, c.err
}

func countReq() *connectorv1.ReadRequest {
	r := req("", false)
	r.IncludeChildCount = true
	return r
}

func ouEntry(class string) *ad.Entry {
	return entry(map[string][][]byte{"cn": {[]byte("x")}, "objectClass": {[]byte("top"), []byte(class)}})
}

func TestChildCountForContainers(t *testing.T) {
	for _, class := range []string{"organizationalUnit", "container"} {
		for _, tc := range []struct {
			n      uint32
			capped bool
		}{{0, false}, {3, false}, {1000, true}} {
			c := &counting{src: &src{dsa: dsaA, entry: ouEntry(class)}, n: tc.n, capped: tc.capped}
			ms, err := collect(t, start(t, c), countReq())
			if err != nil {
				t.Fatal(err)
			}
			cc := ms[0].GetHeader().GetChildCount()
			if cc == nil || cc.GetCount() != tc.n || cc.GetCapped() != tc.capped || c.asked != 1000 {
				t.Fatalf("%s %+v: %v asked %d", class, tc, cc, c.asked)
			}
			for _, a := range ms[0].GetHeader().GetEntry().GetAttributes() {
				if a.GetName() == "objectclass" {
					t.Fatal("objectClass was not asked for and leaked")
				}
			}
		}
	}
}

func TestChildCountNotRequestedIsAbsent(t *testing.T) {
	c := &counting{src: &src{dsa: dsaA, entry: ouEntry("organizationalUnit")}, n: 5}
	ms, err := collect(t, start(t, c), req("", false))
	if err != nil || ms[0].GetHeader().GetChildCount() != nil || c.asked != 0 {
		t.Fatalf("%v %v", err, ms[0].GetHeader().GetChildCount())
	}
}

func TestChildCountRefusesOtherClassesBeforeCounting(t *testing.T) {
	for _, class := range []string{"user", "group", "computer"} {
		c := &counting{src: &src{dsa: dsaA, entry: ouEntry(class)}, n: 5}
		ms, err := collect(t, start(t, c), countReq())
		if code(err) != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT || len(ms) != 0 || c.asked != 0 {
			t.Fatalf("%s: code %v msgs %d asked %d", class, code(err), len(ms), c.asked)
		}
		var re *client.RemoteError
		if !errors.As(client.FromStatus(err), &re) || re.Err.GetRejectedInput().GetRuleId() != "ClassNotAllowed" {
			t.Fatalf("%s: rule %v", class, err)
		}
	}
}

func TestChildCountWithoutObjectClassIsRefused(t *testing.T) {
	c := &counting{src: &src{dsa: dsaA, entry: entry(map[string][][]byte{"cn": {[]byte("x")}})}}
	if _, err := collect(t, start(t, c), countReq()); code(err) != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT {
		t.Fatalf("code %v", code(err))
	}
}

func TestChildCountErrorIsAnErrorNeverZero(t *testing.T) {
	c := &counting{src: &src{dsa: dsaA, entry: ouEntry("organizationalUnit")}, err: ad.NewError(ad.CodeInsufficientRights)}
	ms, err := collect(t, start(t, c), countReq())
	if code(err) != connectorv1.ErrorCode_ERROR_CODE_INSUFFICIENT_RIGHTS || len(ms) != 0 {
		t.Fatalf("code %v msgs %d", code(err), len(ms))
	}
}

func TestChildCountUnsupportedSource(t *testing.T) {
	s := &src{dsa: dsaA, entry: ouEntry("organizationalUnit")}
	if _, err := collect(t, start(t, s), countReq()); code(err) != connectorv1.ErrorCode_ERROR_CODE_CAPABILITY_UNSUPPORTED {
		t.Fatalf("code %v", code(err))
	}
}
