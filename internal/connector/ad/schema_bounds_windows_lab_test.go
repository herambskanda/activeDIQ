//go:build lab && windowslab

package ad

// T-1880 (evidence for T-1250 / T-1713) against the Windows lab DC dc1, over LDAPS. Run:
//   lab/windows/bin/with-dc1-lock -- make lab-test-sync-windows       (needs WIN_LAB_DC_ADDR, windows-lab.md section 10)
// AC1: Windows' schema rangeUpper for every attribute the sync mapper bounds, compared to the documented value
//      (knowledge/development/domain/sync-refusal-bounds.md). That the mapper accepts a value of exactly
//      that many characters is pinned offline in internal/directory/sync (bounds_windows_evidence_test.go).
// AC2: can a MachineAccountQuota creator (a plain domain user) store an unpaired UTF-16 surrogate in
//      description/displayName of the computer it created, over SAMR (WinNT provider), ADSI/LDAP SetInfo and
//      raw LDAP? The bytes read back are logged (T1880-RESULT); that the mapper refuses those bytes with
//      CodeBadText is pinned offline in the same sync test. This package may not import the mapper (blueprint 2.3).

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

const (
	t1880Domain  = "win.activediq.test"
	t1880Creator = "t1880creator"
	t1880CreDN   = "CN=t1880creator,CN=Users," + winBase
	t1880Comp    = "T1880PC"
	t1880CompDN  = "CN=T1880PC,CN=Computers," + winBase
)

// t1880BoundsAttrs are the attributes whose mapper bound is compared with the schema's rangeUpper.
var t1880BoundsAttrs = []string{"sAMAccountName", "userPrincipalName", "displayName", "mail", "company", "description",
	"dNSHostName", "operatingSystem", "operatingSystemVersion"}

// t1880Documented is the rangeUpper claimed in sync-refusal-bounds.md (MS-ADSC) before this ticket.
var t1880Documented = map[string]int{"sAMAccountName": 256, "userPrincipalName": 1024, "displayName": 256, "mail": 256,
	"company": 64, "description": 1024, "dNSHostName": 2048, "operatingSystem": 128, "operatingSystemVersion": 24} // the last two: disproved on dc1

// t1880NoUpper are the attributes dc1's schema carries no rangeUpper for (T-1880 measurement).
var t1880NoUpper = map[string]bool{"operatingSystem": true, "operatingSystemVersion": true}

// t1880Attr returns the first raw value of attr on e.
func t1880Attr(e *ldap.Entry, attr string) string {
	if v := e.GetRawAttributeValues(attr); len(v) > 0 {
		return string(v[0])
	}
	return ""
}

func Test_windowslab_mapper_bounds_vs_schema_range_upper(t *testing.T) {
	c := winDial(t, winAdminBind, winEnv(t)["WIN_LAB_ADMIN_PASSWORD"])
	hits := 0
	for _, a := range t1880BoundsAttrs {
		r, err := c.Search(ldap.NewSearchRequest("CN=Schema,CN=Configuration,"+winBase, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
			"(lDAPDisplayName="+ldap.EscapeFilter(a)+")", []string{"rangeUpper", "isSingleValued"}, nil))
		if err != nil || len(r.Entries) != 1 {
			t.Fatalf("schema lookup %s: %v", a, err)
		}
		raw := t1880Attr(r.Entries[0], "rangeUpper")
		if raw == "" {
			t.Logf("T1880-RANGEUPPER %s windows=absent documented=%d", a, t1880Documented[a])
			if !t1880NoUpper[a] {
				t.Errorf("%s: no rangeUpper in Windows' schema", a)
			}
			continue
		}
		upper, err := strconv.Atoi(raw)
		if err != nil {
			t.Errorf("%s: unparsable rangeUpper %q: %v", a, raw, err)
			continue
		}
		hits++
		t.Logf("T1880-RANGEUPPER %s windows=%d documented=%d single_valued=%s", a, upper, t1880Documented[a], t1880Attr(r.Entries[0], "isSingleValued"))
		if upper != t1880Documented[a] {
			t.Errorf("%s: Windows rangeUpper %d differs from the documented %d: fix sync-refusal-bounds.md and the sync test", a, upper, t1880Documented[a])
		}
	}
	if want := len(t1880BoundsAttrs) - len(t1880NoUpper); hits != want {
		t.Fatalf("%d attributes had a rangeUpper, want %d: the schema lookup is not checking everything", hits, want)
	}
}

func t1880PW(t *testing.T) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "T1880-" + hex.EncodeToString(b) + "-aA1!"
}

func t1880PwdBytes(pw string) string {
	u := utf16.Encode([]rune(`"` + pw + `"`))
	b := make([]byte, 0, 2*len(u))
	for _, x := range u {
		b = append(b, byte(x), byte(x>>8))
	}
	return string(b)
}

type surrogateVariant struct {
	name  string
	units []uint16 // UTF-16 code units as AD stores them
	raw   string   // the bytes a raw LDAP client sends (UTF-8, or CESU-8 for a lone surrogate)
	lone  bool
}

var surrogateVariants = []surrogateVariant{
	{"lone_high_D800", []uint16{0xD800}, "\xed\xa0\x80", true},
	{"lone_low_DC00", []uint16{0xDC00}, "\xed\xb0\x80", true},
	{"valid_pair_D83D_DE00", []uint16{0xD83D, 0xDE00}, "\U0001F600", false}, // control: must store and read back valid
}

func t1880Replace(c *ldap.Conn, dn, attr string, vals []string) error {
	m := ldap.NewModifyRequest(dn, nil)
	m.Replace(attr, vals)
	return c.Modify(m)
}

func t1880Cleanup(t *testing.T, admin *ldap.Conn) {
	for _, dn := range []string{t1880CompDN, t1880CreDN} {
		if err := admin.Del(ldap.NewDelRequest(dn, nil)); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			t.Errorf("removing %s: %v (REMOVE IT BY HAND)", dn, err)
		}
	}
}

func Test_windowslab_unpaired_surrogate_hiding_path(t *testing.T) {
	admin := winDial(t, winAdminBind, winEnv(t)["WIN_LAB_ADMIN_PASSWORD"])
	t1880Cleanup(t, admin) // a leftover from an aborted run
	defer t1880Cleanup(t, admin)

	r, err := admin.Search(ldap.NewSearchRequest(winBase, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"ms-DS-MachineAccountQuota"}, nil))
	if err != nil || len(r.Entries) != 1 {
		t.Fatalf("read MachineAccountQuota: %v", err)
	}
	t.Logf("T1880-MAQ ms-DS-MachineAccountQuota=%s", t1880Attr(r.Entries[0], "ms-DS-MachineAccountQuota"))

	pw := t1880PW(t)
	add := ldap.NewAddRequest(t1880CreDN, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{t1880Creator})
	add.Attribute("userAccountControl", []string{"546"})
	if err := admin.Add(add); err != nil {
		t.Fatalf("create the creator account: %v", err)
	}
	if err := t1880Replace(admin, t1880CreDN, "unicodePwd", []string{t1880PwdBytes(pw)}); err != nil {
		t.Fatalf("set the creator's password: %v", err)
	}
	if err := t1880Replace(admin, t1880CreDN, "userAccountControl", []string{"512"}); err != nil {
		t.Fatalf("enable the creator: %v", err)
	}

	creator := winDial(t, t1880Creator+"@"+t1880Domain, pw)
	// Measured on dc1: the creator's add is refused (unwillingToPerform) unless it also carries SPNs matching its dNSHostName.
	comp := ldap.NewAddRequest(t1880CompDN, nil)
	comp.Attribute("objectClass", []string{"computer"})
	comp.Attribute("sAMAccountName", []string{t1880Comp + "$"})
	comp.Attribute("dNSHostName", []string{t1880Comp + "." + t1880Domain})
	comp.Attribute("servicePrincipalName", []string{"HOST/" + t1880Comp, "HOST/" + t1880Comp + "." + t1880Domain})
	comp.Attribute("userAccountControl", []string{"4096"})
	comp.Attribute("unicodePwd", []string{t1880PwdBytes(t1880PW(t))}) // a workstation trust needs a password at creation
	if err := creator.Add(comp); err != nil {
		t.Fatalf("the non-admin creator could not create a computer under MachineAccountQuota: %v", err)
	}
	t.Logf("T1880-CREATOR %s created %s under MachineAccountQuota", t1880Creator, t1880CompDN)

	judge := func(path string, v surrogateVariant, attr, writeErr string) {
		rr, err := admin.Search(ldap.NewSearchRequest(t1880CompDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{attr}, nil))
		if err != nil || len(rr.Entries) != 1 {
			t.Fatalf("read back %s: %v", attr, err)
		}
		got := rr.Entries[0].GetRawAttributeValues(attr)
		var b []byte
		if len(got) > 0 {
			b = got[0]
		}
		t.Logf("T1880-RESULT path=%s variant=%s attr=%s write_err=%q stored=%v readback_hex=%x valid_utf8=%v",
			path, v.name, attr, writeErr, b != nil, b, utf8.Valid(b))
		if !v.lone && b != nil && !utf8.Valid(b) {
			t.Errorf("%s %s %s: a valid surrogate pair read back as invalid UTF-8 %x", path, v.name, attr, b)
		}
		_ = t1880Replace(admin, t1880CompDN, attr, nil)
	}

	// Raw LDAP, as the creator.
	for _, v := range surrogateVariants {
		for _, attr := range []string{"description", "displayName"} {
			werr := ""
			if err := t1880Replace(creator, t1880CompDN, attr, []string{v.raw}); err != nil {
				werr = err.Error()
			}
			judge("ldap-raw", v, attr, werr)
		}
	}

	// SAMR (WinNT provider) and ADSI LDAP-provider SetInfo, as the creator, driven over WinRM.
	for _, path := range []string{"samr", "adsi-ldap"} {
		for _, v := range surrogateVariants {
			var units []string
			for _, u := range v.units {
				units = append(units, fmt.Sprintf("%04x", u))
			}
			cmd := exec.Command("python3", labFile("", "bin/t1880-surrogate-write"), path, t1880Comp, t1880Creator, strings.Join(units, ","))
			cmd.Stdin = strings.NewReader(pw) // the password never goes on argv or into the environment
			out, err := cmd.CombinedOutput()
			t.Logf("T1880-WRITER path=%s variant=%s err=%v out=%s", path, v.name, err, strings.TrimSpace(strings.ReplaceAll(string(out), pw, "***")))
			if err != nil {
				t.Errorf("writer %s/%s failed to run: %v", path, v.name, err)
				continue
			}
			for _, attr := range []string{"description", "displayName"} {
				judge(path, v, attr, "see T1880-WRITER")
			}
		}
	}
}
