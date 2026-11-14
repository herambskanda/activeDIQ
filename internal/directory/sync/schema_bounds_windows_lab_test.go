//go:build lab && windowslab

package sync_test

// T-1880 (evidence for T-1250 / T-1713) against the Windows lab DC dc1, over LDAPS. Run:
//   lab/windows/bin/with-dc1-lock -- make lab-test-sync-windows       (needs WIN_LAB_DC_ADDR, section 10 of windows-lab.md)
// AC1: Windows' schema rangeUpper for every attribute the mapper bounds, compared to the documented value
//      and to the mapper bound (knowledge/development/domain/sync-refusal-bounds.md).
// AC2: can a MachineAccountQuota creator (a plain domain user) store an unpaired UTF-16 surrogate in
//      description/displayName of the computer it created, over SAMR (WinNT provider), ADSI/LDAP SetInfo
//      and raw LDAP, and does the mapper then refuse the entry with CodeBadText?

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
)

const (
	winBase    = "DC=win,DC=activediq,DC=test"
	winDomain  = "win.activediq.test"
	winTLSHost = "dc1.win.activediq.test"
	creatorSAM = "t1880creator"
	creatorDN  = "CN=t1880creator,CN=Users," + winBase
	compSAM    = "T1880PC"
	compDN     = "CN=T1880PC,CN=Computers," + winBase
)

// documentedUpper is the AD rangeUpper claimed in sync-refusal-bounds.md (MS-ADSC) before this ticket.
var documentedUpper = map[string]int{"sAMAccountName": 256, "userPrincipalName": 1024, "displayName": 256, "mail": 256,
	"company": 64, "description": 1024, "dNSHostName": 2048, "operatingSystem": 128, "operatingSystemVersion": 24} // the last two: disproved on dc1

// noUpperOnWindows are the attributes dc1's schema carries no rangeUpper for (T-1880 measurement).
var noUpperOnWindows = map[string]bool{"operatingSystem": true, "operatingSystemVersion": true}

func winDial(t *testing.T, env map[string]string, user, pw string) *ldap.Conn {
	t.Helper()
	host := os.Getenv("WIN_LAB_DC_ADDR") // process environment wins over the lab env file, as in the drivers
	if host == "" {
		host = env["WIN_LAB_DC_ADDR"]
	}
	if host == "" {
		t.Fatal("WIN_LAB_DC_ADDR is not set (windows-lab.md section 10)")
	}
	caPath := os.Getenv("WIN_LAB_CA")
	if caPath == "" {
		caPath = labDir("windows", ".win-lab-ca.pem")
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	c, err := ldap.DialURL("ldaps://"+host+":636", ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: winTLSHost}))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Bind(user+"@"+winDomain, pw); err != nil {
		c.Close()
		t.Fatalf("bind %s: %v", user, err)
	}
	return c
}

func winEnvFile(t *testing.T) map[string]string {
	p := os.Getenv("WIN_LAB_ENV")
	if p == "" {
		p = labDir("windows", ".win-lab.env")
	}
	return readEnvFile(t, p)
}

func Test_windowslab_mapper_bounds_vs_schema_range_upper(t *testing.T) {
	env := winEnvFile(t)
	c := winDial(t, env, "Administrator", env["WIN_LAB_ADMIN_PASSWORD"])
	defer c.Close()
	hits := 0
	for _, a := range boundsAttrs {
		r, err := c.Search(ldap.NewSearchRequest("CN=Schema,CN=Configuration,"+winBase, ldap.ScopeSingleLevel,
			ldap.NeverDerefAliases, 0, 0, false, schemaFilter(t, a), []string{"rangeUpper", "rangeLower", "isSingleValued"}, nil))
		if err != nil || len(r.Entries) != 1 {
			t.Fatalf("schema lookup %s: %v (%d entries)", a, err, func() int {
				if r == nil {
					return 0
				}
				return len(r.Entries)
			}())
		}
		e := r.Entries[0]
		raw := e.GetAttributeValue("rangeUpper")
		if raw == "" {
			// Measured on dc1 (T-1880): Windows' schema has no rangeUpper for these two either; the
			// documented 128 / 24 were wrong. Absence is pinned so a schema change shows up here.
			t.Logf("T1880-RANGEUPPER %s windows=absent documented=%d", a, documentedUpper[a])
			if !noUpperOnWindows[a] {
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
		t.Logf("T1880-RANGEUPPER %s windows=%d documented=%d single_valued=%s", a, upper, documentedUpper[a], e.GetAttributeValue("isSingleValued"))
		if upper != documentedUpper[a] {
			t.Errorf("%s: Windows rangeUpper %d differs from the documented %d: fix sync-refusal-bounds.md", a, upper, documentedUpper[a])
		}
		if err := mapsAtRangeUpper(a, upper); err != nil {
			t.Errorf("%s: a value of Windows' rangeUpper (%d chars) is refused by the mapper: %v", a, upper, err)
		}
	}
	if want := len(boundsAttrs) - len(noUpperOnWindows); hits != want {
		t.Fatalf("%d attributes had a rangeUpper, want %d: the schema lookup is not checking everything", hits, want)
	}
}

func randPW(t *testing.T) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "T1880-" + hex.EncodeToString(b) + "-aA1!"
}

func pwdBytes(pw string) string {
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

var variants = []surrogateVariant{
	{"lone_high_D800", []uint16{0xD800}, "\xed\xa0\x80", true},
	{"lone_low_DC00", []uint16{0xDC00}, "\xed\xb0\x80", true},
	{"valid_pair_D83D_DE00", []uint16{0xD83D, 0xDE00}, "\U0001F600", false}, // control: must store and map
}

// mapRead runs what the connector does with a stored value (read/handler.go: Text = string(raw)) and the mapper.
func mapRead(raw []byte, attr string) (dirsync.Code, error) {
	e := entry(91, "CN=T1880PC,CN=Computers,DC=win,DC=activediq,DC=test", gid(ouGUID),
		attrs(nil).classes("top", "computer").with(attr, txt(string(raw))))
	_, err := mapper(dirsync.Config{}).Map(e)
	var me *dirsync.Error
	if errors.As(err, &me) {
		return me.Code, err
	}
	return "", err
}

func Test_windowslab_unpaired_surrogate_hiding_path(t *testing.T) {
	env := winEnvFile(t)
	admin := winDial(t, env, "Administrator", env["WIN_LAB_ADMIN_PASSWORD"])
	defer admin.Close()
	cleanup := func() {
		for _, dn := range []string{compDN, creatorDN} {
			if err := admin.Del(ldap.NewDelRequest(dn, nil)); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				t.Errorf("removing %s: %v (REMOVE IT BY HAND)", dn, err)
			}
		}
	}
	cleanup() // a leftover from an aborted run
	defer cleanup()

	r, err := admin.Search(ldap.NewSearchRequest(winBase, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"ms-DS-MachineAccountQuota"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("T1880-MAQ ms-DS-MachineAccountQuota=%s", r.Entries[0].GetAttributeValue("ms-DS-MachineAccountQuota"))

	pw := randPW(t)
	add := ldap.NewAddRequest(creatorDN, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{creatorSAM})
	add.Attribute("userAccountControl", []string{"546"})
	if err := admin.Add(add); err != nil {
		t.Fatalf("create the creator account: %v", err)
	}
	m := ldap.NewModifyRequest(creatorDN, nil)
	m.Replace("unicodePwd", []string{pwdBytes(pw)})
	if err := admin.Modify(m); err != nil {
		t.Fatalf("set the creator's password: %v", err)
	}
	m = ldap.NewModifyRequest(creatorDN, nil)
	m.Replace("userAccountControl", []string{"512"})
	if err := admin.Modify(m); err != nil {
		t.Fatalf("enable the creator: %v", err)
	}

	creator := winDial(t, env, creatorSAM, pw)
	defer creator.Close()
	ca := ldap.NewAddRequest(compDN, nil)
	ca.Attribute("objectClass", []string{"computer"})
	ca.Attribute("sAMAccountName", []string{compSAM + "$"})
	ca.Attribute("dNSHostName", []string{compSAM + "." + winDomain})
	// Measured on dc1: the creator's add is refused (unwillingToPerform) unless it also carries SPNs matching its dNSHostName.
	ca.Attribute("servicePrincipalName", []string{"HOST/" + compSAM, "HOST/" + compSAM + "." + winDomain})
	ca.Attribute("userAccountControl", []string{"4096"})
	ca.Attribute("unicodePwd", []string{pwdBytes(randPW(t))}) // a workstation trust needs a password at creation
	if err := creator.Add(ca); err != nil {
		t.Fatalf("the non-admin creator could not create a computer under MachineAccountQuota: %v", err)
	}
	t.Logf("T1880-CREATOR %s created %s under MachineAccountQuota", creatorSAM, compDN)

	readBack := func(attr string) []byte {
		t.Helper()
		rr, err := admin.Search(ldap.NewSearchRequest(compDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)", []string{attr}, nil))
		if err != nil || len(rr.Entries) != 1 {
			t.Fatalf("read back %s: %v", attr, err)
		}
		v := rr.Entries[0].GetRawAttributeValues(attr)
		if len(v) == 0 {
			return nil
		}
		return v[0]
	}
	clear := func(attr string) {
		m := ldap.NewModifyRequest(compDN, nil)
		m.Replace(attr, nil)
		_ = admin.Modify(m)
	}
	judge := func(path string, v surrogateVariant, attr, writeErr string) {
		got := readBack(attr)
		stored := got != nil
		code, merr := mapRead(got, attr)
		t.Logf("T1880-RESULT path=%s variant=%s attr=%s write_err=%q stored=%v readback_hex=%x valid_utf8=%v mapper_code=%q",
			path, v.name, attr, writeErr, stored, got, utf8.Valid(got), code)
		switch {
		case !stored:
		case v.lone && !utf8.Valid(got) && code != dirsync.CodeBadText:
			t.Errorf("%s %s %s: stored invalid UTF-8 %x but the mapper did not refuse it with bad_text: %v", path, v.name, attr, got, merr)
		case !v.lone && merr != nil:
			t.Errorf("%s %s %s: a valid surrogate pair was refused: %v", path, v.name, attr, merr)
		}
		clear(attr)
	}

	// Raw LDAP, as the creator.
	for _, v := range variants {
		for _, attr := range []string{"description", "displayName"} {
			m := ldap.NewModifyRequest(compDN, nil)
			m.Replace(attr, []string{v.raw})
			werr := ""
			if err := creator.Modify(m); err != nil {
				werr = err.Error()
			}
			judge("ldap-raw", v, attr, werr)
		}
	}

	// SAMR (WinNT provider) and ADSI LDAP-provider SetInfo, as the creator, driven over WinRM.
	for _, path := range []string{"samr", "adsi-ldap"} {
		for _, v := range variants {
			cmd := exec.Command("python3", labDir("windows", "bin", "t1880-surrogate-write"), path, compSAM, creatorSAM,
				strings.Join(func() (s []string) {
					for _, u := range v.units {
						s = append(s, fmt.Sprintf("%04x", u))
					}
					return
				}(), ","))
			cmd.Env = append(os.Environ(), "T1880_CREATOR_PW="+pw)
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
