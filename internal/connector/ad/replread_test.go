package ad

// ReadReplication over the wire (T-1723; CC-REPL-02, -09; contract §5.6 rules 3, 5, 6).
// FAILURE INJECTION: the directory is the in-process stand-in behind the test-only proxy; Samba's
// own answers are the lab test in connector/replstatus. Nothing here proves a Windows behaviour.

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func replSession(t *testing.T, up *fakeUpstream) *Session {
	t.Helper()
	s, _ := faultSession(t, up.dial, injectPlan{skip: 1 << 30})
	return s
}

// replSearches are the searches after Open that name an msDS-Repl* attribute.
func replSearches(up *fakeUpstream) []searchRec {
	var out []searchRec
	for _, r := range up.searchLog() {
		for _, a := range r.attrs {
			if strings.HasPrefix(strings.ToLower(a), "msds-repl") {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// CC-REPL-09 / RX6: the names on the wire are exactly the four, never ";binary", never the
// repsFrom or repsTo family, and the request carries no LDAP control (rule 6).
func TestReadReplication_wireRequestsAreTheFourNamesAndNoControl(t *testing.T) {
	up := startFakeUpstream(t, 0)
	up.repl = map[string][][]byte{
		"msds-replallinboundneighbors": {[]byte("<a/>")}, "msds-replpendingops": {[]byte("<b/>")},
		"msds-replconnectionfailures": {[]byte("<c/>")}, "msds-repllinkfailures": {[]byte("<d/>")},
	}
	s := replSession(t, up)
	got, err := s.ReadReplication(context.Background(), AllReplAttrs)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range AllReplAttrs {
		if !got[a].Present || len(got[a].Values) != 1 {
			t.Errorf("%s: %+v", a.LDAPName(), got[a])
		}
	}
	allowed := map[string]bool{}
	for _, a := range AllReplAttrs {
		allowed[strings.ToLower(a.LDAPName())] = true
	}
	rs := replSearches(up)
	if len(rs) != 4 {
		t.Fatalf("want one search per attribute, got %d", len(rs))
	}
	for _, r := range rs {
		if r.base != "" || len(r.attrs) != 1 {
			t.Errorf("search %+v: want a rootDSE read of one attribute", r)
		}
		for _, a := range r.attrs {
			l := strings.ToLower(a)
			if strings.Contains(l, "binary") || strings.Contains(l, "repsfrom") || strings.Contains(l, "repsto") || !allowed[l] {
				t.Errorf("attribute %q on the wire", a)
			}
		}
		if len(r.controls) != 0 {
			t.Errorf("controls %v on a replication read", r.controls)
		}
	}
}

// RX6: the closed set maps to exactly the four names.
func TestReadReplicationStatus_no_repsFrom(t *testing.T) {
	want := []string{"msDS-ReplAllInboundNeighbors", "msDS-ReplPendingOps", "msDS-ReplConnectionFailures", "msDS-ReplLinkFailures"}
	if len(AllReplAttrs) != len(want) || len(replAttrNames) != len(want) {
		t.Fatalf("closed set has %d/%d names", len(AllReplAttrs), len(replAttrNames))
	}
	for i, a := range AllReplAttrs {
		if a.LDAPName() != want[i] {
			t.Errorf("attr %d = %q, want %q", i, a.LDAPName(), want[i])
		}
	}
}

// CC-REPL-02: an attribute the DC does not return is not Present, with no values, and no search
// beyond one per attribute (no fallback to another name).
func TestReadReplication_notReturned(t *testing.T) {
	up := startFakeUpstream(t, 0)
	s := replSession(t, up)
	got, err := s.ReadReplication(context.Background(), AllReplAttrs)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range AllReplAttrs {
		if v := got[a]; v.Present || len(v.Values) != 0 || v.Denied || v.RangeIncomplete {
			t.Errorf("%s: %+v", a.LDAPName(), v)
		}
	}
	if n := len(replSearches(up)); n != 4 {
		t.Errorf("searches = %d, want 4", n)
	}
}

// Rule 5: ranges are followed to the terminal range.
func TestReadReplication_rangesFollowedToTheEnd(t *testing.T) {
	up := startFakeUpstream(t, 0)
	var vals [][]byte
	for i := 0; i < 3200; i++ {
		vals = append(vals, []byte(fmt.Sprintf("<v%d/>", i)))
	}
	up.repl = map[string][][]byte{"msds-replallinboundneighbors": vals}
	up.rangeSize = 1500
	s := replSession(t, up)
	got, err := s.ReadReplication(context.Background(), []ReplAttr{ReplInboundNeighbors})
	if err != nil {
		t.Fatal(err)
	}
	v := got[ReplInboundNeighbors]
	if !v.Present || v.RangeIncomplete || len(v.Values) != 3200 || string(v.Values[3199]) != "<v3199/>" {
		t.Fatalf("present=%v incomplete=%v n=%d", v.Present, v.RangeIncomplete, len(v.Values))
	}
}

// A range that never reaches "*" is RangeIncomplete, not a short list.
func TestReadReplication_rangeNeverCompletes(t *testing.T) {
	up := startFakeUpstream(t, 0)
	var vals [][]byte
	for i := 0; i < 10; i++ {
		vals = append(vals, []byte("<v/>"))
	}
	up.repl = map[string][][]byte{"msds-replallinboundneighbors": vals}
	up.rangeSize, up.rangeNoEnd = 3, true
	s := replSession(t, up)
	got, err := s.ReadReplication(context.Background(), []ReplAttr{ReplInboundNeighbors})
	if err != nil {
		t.Fatal(err)
	}
	if v := got[ReplInboundNeighbors]; !v.Present || !v.RangeIncomplete {
		t.Fatalf("%+v", v)
	}
}

// Rule 6: a refusal is per attribute; the others are still read.
func TestReadReplication_deniedIsPerAttribute(t *testing.T) {
	up := startFakeUpstream(t, 0)
	up.repl = map[string][][]byte{"msds-replpendingops": {[]byte("<b/>")}}
	up.replDenied = map[string]bool{"msds-replallinboundneighbors": true}
	s := replSession(t, up)
	got, err := s.ReadReplication(context.Background(), []ReplAttr{ReplInboundNeighbors, ReplPendingOps})
	if err != nil {
		t.Fatal(err)
	}
	if !got[ReplInboundNeighbors].Denied || got[ReplInboundNeighbors].Present {
		t.Errorf("neighbors: %+v", got[ReplInboundNeighbors])
	}
	if v := got[ReplPendingOps]; !v.Present || v.Denied || len(v.Values) != 1 {
		t.Errorf("pending: %+v", v)
	}
}

// An unknown attribute value is refused before any request.
func TestReadReplication_unknownAttributeSendsNothing(t *testing.T) {
	up := startFakeUpstream(t, 0)
	s := replSession(t, up)
	before := len(up.searchLog())
	for _, bad := range [][]ReplAttr{nil, {0}, {99}, {ReplPendingOps, 0}} {
		if _, err := s.ReadReplication(context.Background(), bad); CodeOf(err) != CodeInvalidArgument {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if n := len(up.searchLog()); n != before {
		t.Errorf("%d searches sent", n-before)
	}
}
