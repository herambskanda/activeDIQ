//go:build lab && windowslab

package tier0

// Windows lab tests (T-0404): tier0 fails closed when the connector cannot READ a protected group
// or a member of one (deny-read ACE, LCRPLO). Samba only exercises the entry-without-objectGUID
// path; here we see what a real Windows DC returns for a denied Read and pin the fail-closed cause.
// Run: make windows-lab-up && go test -tags 'lab windowslab' ./internal/connector/tier0 -run TestWindowsLab -v
// Credentials: lab/windows/.win-lab.env (WIN_LAB_ADMIN_PASSWORD, WIN_LAB_SVC_PASSWORD). The lab
// is never skipped when missing: the run fails loudly. Each test restores the DACL it changed.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// daclOnly is the SD_FLAGS control (OID 1.2.840.113556.1.4.801) asking for the DACL part only.
func daclOnly() ldap.Control {
	return &ldap.ControlString{ControlType: "1.2.840.113556.1.4.801", Criticality: true, ControlValue: "\x30\x03\x02\x01\x04"}
}

// denyReadACE is ACCESS_DENIED_ACE (LC 0x4 | RP 0x10 | LO 0x80) for the connector SID.
func denyReadACE(sid []byte) []byte {
	ace := make([]byte, 8, 8+len(sid))
	ace[0] = 0x01 // ACCESS_DENIED_ACE_TYPE
	binary.LittleEndian.PutUint16(ace[2:], uint16(8+len(sid)))
	binary.LittleEndian.PutUint32(ace[4:], 0x4|0x10|0x80)
	return append(ace, sid...)
}

// withDeny prepends the deny ACE to the DACL of a DACL-only self-relative SD (deny first = canonical).
func withDeny(sd, ace []byte) ([]byte, error) {
	if len(sd) < 28 || binary.LittleEndian.Uint32(sd[16:]) != 20 {
		return nil, errors.New("unexpected SD layout")
	}
	acl := sd[20:]
	size := binary.LittleEndian.Uint16(acl[2:])
	count := binary.LittleEndian.Uint16(acl[4:])
	out := append([]byte{}, sd[:20]...)
	hdr := append([]byte{}, acl[:8]...)
	binary.LittleEndian.PutUint16(hdr[2:], size+uint16(len(ace)))
	binary.LittleEndian.PutUint16(hdr[4:], count+1)
	out = append(out, hdr...)
	out = append(out, ace...)
	return append(out, acl[8:size]...), nil
}

// denyRead sets the deny-read ACE on dnText and restores the original DACL on cleanup.
func (w *winLab) denyRead(t *testing.T, dnText string) {
	t.Helper()
	r, err := w.admin.Search(ldap.NewSearchRequest(dnText, ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)",
		[]string{"nTSecurityDescriptor"}, []ldap.Control{daclOnly()}))
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("read DACL of %s: %v", dnText, err)
	}
	orig := r.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	bad, err := withDeny(orig, denyReadACE(w.svcSID))
	if err != nil {
		t.Fatal(err)
	}
	set := func(v []byte) error {
		m := ldap.NewModifyRequest(dnText, []ldap.Control{daclOnly()})
		m.Replace("nTSecurityDescriptor", []string{string(v)})
		return w.admin.Modify(m)
	}
	if err := set(bad); err != nil {
		t.Fatalf("set deny-read on %s: %v", dnText, err)
	}
	t.Cleanup(func() {
		if err := set(orig); err != nil {
			t.Errorf("RESTORE DACL of %s FAILED (run make windows-lab-reset): %v", dnText, err)
		}
	})
}

func (w *winLab) mustAdd(t *testing.T, req *ldap.AddRequest) {
	t.Helper()
	if err := w.admin.Add(req); err != nil {
		t.Fatalf("add %s: %v", req.DN, err)
	}
	t.Cleanup(func() { _ = w.admin.Del(ldap.NewDelRequest(req.DN, nil)) })
}

// observe records what a denied Read returns on this DC (AC3): the result code, or the entry's
// attribute names. The line is copied into the threat model's tier0 section.
func (w *winLab) observe(t *testing.T, dnText string) {
	t.Helper()
	ref, err := dn.ParseObjectRef(dnText)
	if err != nil {
		t.Fatal(err)
	}
	e, err := w.sess.Read(context.Background(), ref, []string{"objectGUID", "objectSid", "objectClass"}, ad.ReadOptions{})
	if err != nil {
		t.Logf("OBSERVED denied Read of %s: error code=%v (%v)", dnText, ad.CodeOf(err), err)
		return
	}
	t.Logf("OBSERVED denied Read of %s: entry returned, attributes=%v", dnText, e.Names())
}

func (w *winLab) classifier() (*ADClassifier, dn.ObjectRef) {
	c := NewAD(SessionDirectory{S: w.sess})
	target, _ := dn.ParseObjectRef("CN=Administrator,CN=Users," + winDom)
	return c, target
}

// AC1: a deny-read ACE on a group nested in Domain Admins: Classify is Unknown with an error that
// names the cause (a member the connector cannot read, listed by Domain Admins), not any read error.
func TestWindowsLabTier0DenyReadNestedGroupFailsClosed(t *testing.T) {
	w := newWinLab(t)
	name := fmt.Sprintf("t0404-nest-%d", time.Now().UnixNano()%1_000_000)
	nested := "CN=" + name + ",CN=Users," + winDom
	add := ldap.NewAddRequest(nested, nil)
	add.Attribute("objectClass", []string{"top", "group"})
	add.Attribute("sAMAccountName", []string{name})
	add.Attribute("groupType", []string{"-2147483646"}) // global security
	w.mustAdd(t, add)
	da := "CN=Domain Admins,CN=Users," + winDom
	m := ldap.NewModifyRequest(da, nil)
	m.Add("member", []string{nested})
	if err := w.admin.Modify(m); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m := ldap.NewModifyRequest(da, nil)
		m.Delete("member", []string{nested})
		_ = w.admin.Modify(m)
	})

	c, target := w.classifier()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if r, err := c.Classify(ctx, target, ADInput{CorrelationKnown: true}); err != nil || r.Unknown {
		t.Fatalf("control run (no deny): %+v %v", r, err) // proves the failure below is the ACE
	}
	w.denyRead(t, nested)
	w.observe(t, nested)
	r, err := c.Classify(ctx, target, ADInput{CorrelationKnown: true})
	if err == nil || !r.Unknown || !r.Tier0 {
		t.Fatalf("deny-read nested group: result %+v err %v, want Tier0+Unknown and an error", r, err)
	}
	// The cause, pinned. Windows answers a denied Read with an entry that has no attributes
	// (observed, T-0404), so the walk fails in builder.mark. Any other error (timeout, bind,
	// protocol) is not this cause and must fail the test.
	if !strings.Contains(err.Error(), "without objectGUID") {
		t.Fatalf("fail-closed for the wrong cause: %v", err)
	}
	if !strings.Contains(err.Error(), nested) {
		t.Fatalf("error does not name the unreadable group %s: %v", nested, err)
	}
}

// AC2: deny-read on CN=Backup Operators,CN=Builtin: the snapshot fails closed naming S-1-5-32-551.
func TestWindowsLabTier0DenyReadBackupOperatorsFailsClosed(t *testing.T) {
	w := newWinLab(t)
	bo := "CN=Backup Operators,CN=Builtin," + winDom
	c, _ := w.classifier()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if _, err := c.Snapshot(ctx); err != nil {
		t.Fatalf("control snapshot (no deny): %v", err)
	}
	w.denyRead(t, bo)
	w.observe(t, bo)
	_, err := c.Snapshot(ctx)
	if err == nil || !strings.Contains(err.Error(), "without objectGUID") {
		t.Fatalf("deny-read Backup Operators: err = %v, want a fail-closed entry-without-objectGUID refusal", err)
	}
	if !strings.Contains(err.Error(), "S-1-5-32-551") {
		t.Fatalf("refusal does not name S-1-5-32-551: %v", err)
	}
}

// AC4 evidence: report the domain functional level, forest level and whether Key Admins /
// Enterprise Key Admins exist, so a run on a pre-2016 domain with 2016+ DCs can be read off the log.
// This lab is a fresh WS2025 forest, so it cannot by itself show the pre-2016 case (see ticket notes).
func TestWindowsLabKeyAdminsPresenceVsFunctionalLevel(t *testing.T) {
	w := newWinLab(t)
	r, err := w.admin.Search(ldap.NewSearchRequest(winDom, ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)",
		[]string{"msDS-Behavior-Version", "objectSid"}, nil))
	if err != nil || len(r.Entries) != 1 {
		t.Fatal(err)
	}
	lvlText := r.Entries[0].GetAttributeValue("msDS-Behavior-Version")
	lvl, err := strconv.Atoi(lvlText)
	if err != nil {
		t.Fatalf("functional level %q: %v", lvlText, err)
	}
	for _, n := range []string{"Key Admins", "Enterprise Key Admins"} {
		g, err := w.admin.Search(ldap.NewSearchRequest(winDom, ldap.ScopeWholeSubtree, 0, 0, 0, false,
			"(&(objectClass=group)(sAMAccountName="+ldap.EscapeFilter(n)+"))", []string{"objectSid"}, nil))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("OBSERVED domain level %d: %q present=%v", lvl, n, len(g.Entries) == 1)
		if lvl >= levelWin2016 && len(g.Entries) != 1 && n == "Key Admins" {
			t.Errorf("level %d but Key Admins is absent: the classifier would accept a hidden group only below 7", lvl)
		}
	}
}
