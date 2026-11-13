//go:build lab

package read_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/client"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1914 / CC-READ-10 on Samba AD: Read include_child_count through read.Handler over a real session.
// `make lab-up && go test -tags lab ./internal/connector/read -run TestLabChildCount`.
// Samba proves the counting, the cap and the class gate. It does not prove what a Windows DC returns
// for an unreadable child or the NotLeaf answer of a delete (Windows-lab ticket, see the advance note).

func (l *searchLab) countReq(g *connectorv1.Guid) *connectorv1.ReadRequest {
	return &connectorv1.ReadRequest{Connection: &connectorv1.ConnectionRef{ConnectionId: "c1", DirectoryIdentity: l.ident},
		Guid: g, Attributes: []string{"cn"}, IncludeChildCount: true}
}

func TestLabChildCount(t *testing.T) {
	l := newSearchLab(t)
	root := "OU=t1914" + l.stamp + "," + labDom
	t.Cleanup(func() { l.delTree(root) })
	ou := map[string][]string{"objectClass": {"top", "organizationalUnit"}}
	l.add(t, root, ou)
	empty, three, big := "OU=empty,"+root, "OU=three\\, Ünï,"+root, "OU=big,"+root
	for _, d := range []string{empty, three, big} {
		l.add(t, d, ou)
	}
	// Grandchildren must not count: only direct children block a delete.
	for i := 0; i < 3; i++ {
		l.add(t, fmt.Sprintf("CN=c%d,%s", i, three), map[string][]string{"objectClass": {"top", "container"}})
	}
	l.add(t, "CN=nested,CN=c0,"+three, map[string][]string{"objectClass": {"top", "container"}}) // a grandchild: not counted
	for i := 0; i < 1200; i++ {
		l.add(t, fmt.Sprintf("CN=c%04d,%s", i, big), map[string][]string{"objectClass": {"top", "container"}})
	}
	for _, tc := range []struct {
		dn     string
		n      uint32
		capped bool
	}{{empty, 0, false}, {three, 3, false}, {big, 1000, true}} {
		ms, err := collect(t, l.client, l.countReq(l.guid(t, tc.dn)))
		if err != nil {
			t.Fatalf("%s: %v", tc.dn, err)
		}
		cc := ms[0].GetHeader().GetChildCount()
		if cc.GetCount() != tc.n || cc.GetCapped() != tc.capped {
			t.Errorf("%s: got %v want %d capped=%v", tc.dn, cc, tc.n, tc.capped)
		}
	}
	// A non-container is refused with ClassNotAllowed, not counted as zero.
	l.add(t, "CN=u1914,"+empty, map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "user"},
		"sAMAccountName": {"t1914u" + l.stamp}})
	_, err := collect(t, l.client, l.countReq(l.guid(t, "CN=u1914,"+empty)))
	var re *client.RemoteError
	if !errors.As(client.FromStatus(err), &re) || re.Err.GetCode() != connectorv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT ||
		re.Err.GetRejectedInput().GetRuleId() != "ClassNotAllowed" {
		t.Fatalf("user: %v", err)
	}
	// The empty OU now has one child.
	ms, err := collect(t, l.client, l.countReq(l.guid(t, empty)))
	if err != nil || ms[0].GetHeader().GetChildCount().GetCount() != 1 {
		t.Fatalf("after add: %v %v", ms, err)
	}
}
