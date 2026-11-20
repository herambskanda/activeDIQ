//go:build lab

package server

// T-1112 (spec reports-2a AC-23 pattern): the batch-6 user-attribute reports USR-07, USR-08 and USR-11 are
// proven against a direct LDAP query of the Samba lab, not against the seeded store. The test seeds one
// case per preset on existing lab users (restored when the test ends), syncs with the real sync.full job,
// runs every preset through the real reports router and compares the GUIDs of the rows with an LDAP
// search that never touches inventory or the engine's SQL.
//
// Not seedable on the lab, named here and in the ticket note: USR-09 (Skype/Lync) reads msRTCSIP-UserEnabled,
// an attribute the Samba schema does not define, so it cannot be set or read; its presets are not compared.

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/connector/ad"
	"github.com/skenzeriq/activediq/internal/connector/labadmin"
	"github.com/skenzeriq/activediq/internal/directory/ldapfilter"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

const uacSmartcardRequired = 0x40000

func TestLabUserAttributeReportsMatchLDAPGroundTruth(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		r := newReportsRig(t, s)
		le := r.le
		admin := labadmin.Dial(t, le.Port, le.Pool, "Administrator@"+labUPNSuffix, le.Values["LAB_ADMIN_PASSWORD"])
		cs := openCountSession(t, r.ctx, le, "")
		g := gtLDAP{t: t, sess: cs.s, base: cs.base}

		notDisabled := ldapfilter.Not(ldapfilter.BitAnd(attr(t, "userAccountControl"), uacAccountDisable))
		acc := g.accounts(notDisabled)
		if len(acc) < 6 {
			t.Fatalf("the lab seed has %d enabled users, need 6", len(acc))
		}
		dnOf := func(i int) string { return admin.DNOf(acc[i].sam) }
		restricted := bytes.Repeat([]byte{0xFF}, 21)
		restricted[20] = 0x7F // the last hour of the week is not allowed
		open := bytes.Repeat([]byte{0xFF}, 21)
		jpeg := string([]byte{0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, 'J', 'F', 'I', 'F', 0})

		// One case per preset, set BEFORE the sync so the sync job carries it into inventory.
		admin.ReplaceValues(dnOf(0), "thumbnailPhoto", jpeg)
		admin.ReplaceValues(dnOf(0), "scriptPath", "logon.bat")
		admin.ReplaceValues(dnOf(0), "msNPAllowDialin", "TRUE")
		admin.ReplaceValues(dnOf(0), "logonHours", string(restricted))
		admin.ReplaceValues(dnOf(0), "mail", "gt0@lab.activediq.test")
		admin.ReplaceValues(dnOf(1), "jpegPhoto", jpeg)
		admin.ReplaceValues(dnOf(1), "msNPAllowDialin", "FALSE")
		admin.ReplaceValues(dnOf(1), "logonHours", string(open))
		admin.ReplaceValues(dnOf(1), "userAccountControl", strconv.Itoa(512|uacSmartcardRequired))
		admin.ReplaceValues(dnOf(2), "scriptPath", "other.bat")
		admin.ReplaceValues(dnOf(2), "department", "Gt")
		admin.ReplaceValues(dnOf(2), "manager", dnOf(0))

		r.activateAndSync()

		present := func(a string) ldapfilter.Filter { return ldapfilter.Present(attr(t, a)) }
		absent := func(a string) ldapfilter.Filter { return ldapfilter.Not(present(a)) }
		truths := map[string]func() map[string]struct{}{
			"usr-08/photo_with": func() map[string]struct{} {
				return g.users(ldapfilter.Or(present("thumbnailPhoto"), present("jpegPhoto")), nil, nil)
			},
			"usr-08/photo_without": func() map[string]struct{} {
				return g.users(ldapfilter.And(absent("thumbnailPhoto"), absent("jpegPhoto")), nil, nil)
			},
			"usr-08/script_with":    func() map[string]struct{} { return g.users(present("scriptPath"), nil, nil) },
			"usr-08/script_without": func() map[string]struct{} { return g.users(absent("scriptPath"), nil, nil) },
			"usr-07/dialin_allow": func() map[string]struct{} {
				return g.users(ldapfilter.Eq(attr(t, "msNPAllowDialin"), ldapfilter.Bool(true)), nil, nil)
			},
			// Deny lists only an explicit FALSE; users with no value are NPS-controlled and only counted in the header.
			"usr-07/dialin_deny": func() map[string]struct{} {
				return g.users(ldapfilter.Eq(attr(t, "msNPAllowDialin"), ldapfilter.Bool(false)), nil, nil)
			},
			"usr-07/smartcard": func() map[string]struct{} {
				return g.users(ldapfilter.BitAnd(attr(t, "userAccountControl"), uacSmartcardRequired), nil, nil)
			},
			// A schedule restricts a user when it has at least one denied hour (a zero bit in the 21 octets).
			"usr-07/logon_hours": func() map[string]struct{} {
				return g.users(present("logonHours"), []string{"logonHours"}, func(e *ad.Entry) bool {
					for _, v := range e.Raw("logonHours") {
						for _, b := range v {
							if b != 0xFF {
								return true
							}
						}
					}
					return false
				})
			},
		}
		for id, a := range map[string]string{"mail": "mail", "employee_id": "employeeID", "department": "department", "title": "title",
			"company": "company", "telephone_number": "telephoneNumber", "mobile": "mobile", "description": "description", "manager": "manager"} {
			a := a
			truths["usr-11/empty_"+id] = func() map[string]struct{} { return g.users(absent(a), nil, nil) }
		}
		nonEmpty := map[string]bool{"usr-08/photo_with": true, "usr-08/photo_without": true, "usr-08/script_with": true, "usr-08/script_without": true,
			"usr-07/dialin_allow": true, "usr-07/dialin_deny": true, "usr-07/smartcard": true, "usr-07/logon_hours": true, "usr-11/empty_mail": true,
			"usr-11/empty_department": true, "usr-11/empty_manager": true}

		for _, key := range sortedKeys2(truths) {
			t.Run(strings.ReplaceAll(key, "/", "_"), func(t *testing.T) {
				def, preset, _ := strings.Cut(key, "/")
				got := r.runRowGUIDs(r.report(def, preset))
				want := truths[key]()
				var problems []string
				if msg, ok := guidSetDiff(want, inter(got, want)); !ok {
					problems = append(problems, "rows missing from the report: "+msg)
				}
				if msg, ok := guidSetDiff(inter(got, want), got); !ok {
					problems = append(problems, "rows with no LDAP match: "+msg)
				}
				for _, p := range problems {
					t.Errorf("%s: %s", key, p)
				}
				if nonEmpty[key] && len(want) == 0 {
					t.Errorf("%s: the LDAP ground truth is empty, the comparison proves nothing", key)
				}
				t.Logf("%s: %d rows, LDAP ground truth %d", key, len(got), len(want))
			})
		}
	})
}
