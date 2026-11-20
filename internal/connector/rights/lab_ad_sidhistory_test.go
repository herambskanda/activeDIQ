//go:build lab

package rights

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/attr/sid"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// T-1762. sIDHistory values are foreign-domain SIDs, fixed so the run is deterministic.
const (
	histUserSID  = "S-1-5-21-1111111111-2222222222-3333333333-1234"
	histGroupSID = "S-1-5-21-1111111111-2222222222-3333333333-5678"
)

// setSIDHistory adds a sIDHistory value with ldbmodify --relax (samba-tool has no verb for it; the
// attribute is system-only for LDAP clients). The value disappears with the object at cleanup.
func (l *lab) setSIDHistory(objDN, value string) {
	l.t.Helper()
	ldif := "dn: " + objDN + "\nchangetype: modify\nadd: sIDHistory\nsIDHistory: " + value + "\n"
	cmd := exec.Command("docker", "exec", "-i", l.ctr, "ldbmodify", "-H", "/var/lib/samba/private/sam.ldb", "--relax", "/dev/stdin")
	cmd.Stdin = strings.NewReader(ldif)
	if out, err := cmd.CombinedOutput(); err != nil {
		l.t.Fatalf("ldbmodify sIDHistory on %s: %v\n%s", objDN, err, out)
	}
}

func (l *lab) group(member string) (dnText, sidText string) {
	l.t.Helper()
	labSeq++
	name := "t1762g" + itoa(labSeq)
	l.tool("samba-tool", "group", "add", name)
	l.t.Cleanup(func() { l.try("samba-tool", "group", "delete", name) })
	l.tool("samba-tool", "group", "addmembers", name, member)
	for _, ln := range strings.Split(l.tool("samba-tool", "group", "show", name, "--attributes=objectSid,distinguishedName"), "\n") {
		if v, ok := strings.CutPrefix(ln, "objectSid: "); ok {
			sidText = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(ln, "dn: "); ok {
			dnText = strings.TrimSpace(v)
		}
	}
	if dnText == "" || sidText == "" {
		l.t.Fatal("group fixture")
	}
	return
}

func itoa(n int64) string {
	const d = "0123456789"
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{d[n%10]}, b...)
	}
	return string(b)
}

func mustSID(t *testing.T, s string) sid.SID {
	t.Helper()
	v, err := sid.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// AC1 (CC §5.9.4): a live sIDHistory value on the identity is in the exported TokenSet, and the set is
// Complete. Also pins, per the T-1741 security review, what the real tokenGroups holds when a group the
// user belongs to carries its own sIDHistory.
func TestLabADTokenSetSIDHistory(t *testing.T) {
	l := newLab(t)
	ctx := labCtx(t)
	name, userDN, userSID := l.user()
	groupDN, groupSID := l.group(name)
	l.setSIDHistory(userDN, histUserSID)
	l.setSIDHistory(groupDN, histGroupSID)

	r := l.verify(ctx, name, userDN, ADInput{})
	ts := r.res.Tokens
	if !ts.Complete {
		t.Fatalf("TokenSet incomplete: %v", ts.SIDs)
	}
	if !ts.Has(mustSID(t, histUserSID)) {
		t.Errorf("TokenSet lacks the identity's sIDHistory %s: %v", histUserSID, ts.SIDs)
	}
	if !ts.Has(mustSID(t, userSID)) || !ts.Has(mustSID(t, groupSID)) {
		t.Errorf("TokenSet lacks objectSid or the group SID: %v", ts.SIDs)
	}

	// The directory's own tokenGroups of the same identity, read live.
	tg := tokenGroupsOf(t, ctx, r.sess, userDN)
	hasGroup, hasGroupHist := false, false
	for _, g := range tg {
		hasGroup = hasGroup || g.String() == groupSID
		hasGroupHist = hasGroupHist || g.String() == histGroupSID
	}
	if !hasGroup {
		t.Fatalf("fixture: tokenGroups lacks the member group %s: %v", groupSID, tg)
	}
	// Recorded result (Samba 4, T-1762): tokenGroups does NOT expand the sIDHistory of a group the user
	// belongs to. Windows is recorded in the Windows lab run (T-1762 AC2 follow-up). If this flips, the
	// contract §5.9.4 text and T-1763 item 2 need revisiting.
	if hasGroupHist {
		t.Errorf("Samba tokenGroups now contains the group's sIDHistory %s; update contract §5.9.4", histGroupSID)
	}
	// And the exported set does not hold it either: it adds only the identity's own sIDHistory.
	if ts.Has(mustSID(t, histGroupSID)) {
		t.Errorf("TokenSet holds the group's sIDHistory %s though tokenGroups does not", histGroupSID)
	}
	t.Logf("RECORDED samba tokenGroups=%v groupSIDHistoryInTokenGroups=%v tokenSet=%v", tg, hasGroupHist, ts.SIDs)
}

func tokenGroupsOf(t *testing.T, ctx context.Context, s *ad.Session, userDN string) []sid.SID {
	t.Helper()
	ref, err := dn.ParseObjectRef(userDN)
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Read(ctx, ref, []string{"tokenGroups"}, ad.ReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	g, err := e.SIDs("tokenGroups")
	if err != nil {
		t.Fatal(err)
	}
	return g
}
