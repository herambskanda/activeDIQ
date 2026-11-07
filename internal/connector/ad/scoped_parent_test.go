package ad

import (
	"bytes"
	"context"
	"strconv"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/attr/guid"
)

// T-0694 AC1/AC2 against a protocol fake: 600 entries over 7 distinct parents cost exactly 7 parent
// reads (one per distinct parent DN, never per entry), every entry carries its own parent's GUID, and
// the reads happen with the session lock free (the call would deadlock otherwise).
func TestScopedSearchResolvesParentsOncePerDistinctParent(t *testing.T) {
	const entries, parents = 600, 7
	up := startFakeUpstream(t, entries)
	up.parents = parents
	s, _ := faultSession(t, up.dial, injectPlan{skip: 1 << 30})
	req := scopedReq(t, s, guid.GUID{1})
	req.ResolveParents = true
	got := 0
	_, err := s.ScopedSearch(context.Background(), req, func(e *Entry) error {
		pg, has, resolved := e.Parent()
		if !resolved || !has {
			t.Fatalf("%s: resolved=%v has=%v", e.DN, resolved, has)
		}
		var k int
		for i := 0; i < parents; i++ {
			if bytes.Contains([]byte(e.DN), []byte(",OU=p"+strconv.Itoa(i)+",")) {
				k = i
			}
		}
		if !bytes.Equal(pg.Bytes(), parentGUID(k)) {
			t.Fatalf("%s: parent %x, want %x", e.DN, pg.Bytes(), parentGUID(k))
		}
		got++
		return nil
	})
	if err != nil || got != entries {
		t.Fatalf("err=%v got=%d", err, got)
	}
	reads := up.parentReads()
	total := 0
	for dn, n := range reads {
		if n != 1 {
			t.Errorf("parent %s read %d times", dn, n)
		}
		total += n
	}
	if total != parents {
		t.Fatalf("%d parent reads for %d distinct parents: %v", total, parents, reads)
	}
}

// Without ResolveParents nothing extra is read and Parent reports unresolved.
func TestScopedSearchWithoutResolveParentsReadsNothingExtra(t *testing.T) {
	up := startFakeUpstream(t, 5)
	up.parents = 2
	s, _ := faultSession(t, up.dial, injectPlan{skip: 1 << 30})
	_, err := s.ScopedSearch(context.Background(), scopedReq(t, s, guid.GUID{1}), func(e *Entry) error {
		if _, _, resolved := e.Parent(); resolved {
			t.Error("parent resolved without being asked")
		}
		return nil
	})
	if err != nil || len(up.parentReads()) != 0 {
		t.Fatalf("err=%v reads=%v", err, up.parentReads())
	}
}

func countScoped(t *testing.T, s *Session, req ScopedRequest) (ScopedResult, int, error) {
	t.Helper()
	got := 0
	res, err := s.ScopedSearch(context.Background(), req, func(*Entry) error { got++; return nil })
	return res, got, err
}

// An entry listed without objectGUID is withheld and counted, not a failure of the whole search, and
// the entries around it are still delivered (Samba lists some system objects partially).
func TestScopedSearchWithholdsEntryWithoutObjectGUID(t *testing.T) {
	up := startFakeUpstream(t, 10)
	up.parents = 2
	up.noGUID = 3
	s, _ := faultSession(t, up.dial, injectPlan{skip: 1 << 30})
	req := scopedReq(t, s, guid.GUID{1})
	req.ResolveParents = true
	res, got, err := countScoped(t, s, req)
	if err != nil || got != 7 || res.Returned != 7 || res.Unreadable != 3 {
		t.Fatalf("err=%v got=%d res=%+v", err, got, res)
	}
}

// An entry whose parent cannot be read is withheld and counted; its siblings under a readable parent
// are delivered. 10 entries over 2 parents: the 5 under the missing parent are the withheld ones.
func TestScopedSearchWithholdsEntryWithUnreadableParent(t *testing.T) {
	up := startFakeUpstream(t, 10)
	up.parents = 2
	up.missingParent = map[int]bool{1: true}
	s, _ := faultSession(t, up.dial, injectPlan{skip: 1 << 30})
	req := scopedReq(t, s, guid.GUID{1})
	req.ResolveParents = true
	res, got, err := countScoped(t, s, req)
	if err != nil || got != 5 || res.Returned != 5 || res.Unreadable != 5 {
		t.Fatalf("err=%v got=%d res=%+v", err, got, res)
	}
}

// A session failure while resolving a parent is not "unplaceable": the search fails, never a silent
// withhold.
func TestScopedSearchSessionFailureOnParentStillFails(t *testing.T) {
	up := startFakeUpstream(t, 10)
	up.parents = 2
	up.dropOnParent = map[int]bool{0: true}
	s, _ := faultSession(t, up.dial, injectPlan{skip: 1 << 30})
	req := scopedReq(t, s, guid.GUID{1})
	req.ResolveParents = true
	res, _, err := countScoped(t, s, req)
	if err == nil {
		t.Fatalf("a dropped session was swallowed: %+v", res)
	}
}
