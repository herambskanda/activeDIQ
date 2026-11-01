package inventory_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/directory/attr/filetime"
	"github.com/skenzeriq/activediq/internal/directory/inventory"
	"github.com/skenzeriq/activediq/internal/platform/report"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/store/reportsql"
	"github.com/skenzeriq/activediq/internal/platform/store/storetest"
)

// RP8 (reports contract §4.8, spec reports-2a §6.4): the derived columns the compiled query computes
// must equal a reference implementation written from the spec, for every input combination. The
// reference below (derive) is test code only; the run path never calls anything like it.

// secs is a stored interval in seconds: nil is "not read", 0 is forever.
type secs = *int64

func sec(n int64) secs { return &n }

type domPol struct {
	max, lock secs
	psosRead  bool
}

type psoM struct {
	guid, name string
	prec       *int64
	max, lock  secs
	stored     bool // false: the PSO row was never read (an applies edge without a PSO)
	applies    []string
	removed    []string // edges marked removed
}

type grpM struct {
	guid, name string
	rid        uint32
	members    []string
}

// world8 is the whole model of one scenario.
type world8 struct {
	dom    domPol
	psos   []psoM
	groups []grpM
	users  []hUser
}

func wireBytes(g string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(g, "-", ""))
	if err != nil || len(b) != 16 {
		panic("bad guid " + g)
	}
	// the text order of the first three groups is little-endian on the wire
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	b[4], b[5] = b[5], b[4]
	b[6], b[7] = b[7], b[6]
	return b
}

// derived is the reference result for one user.
type derived struct {
	locked, pwd, acct, source string
	lockWhy, pwdWhy, acctWhy  string
	lockEnds, pwdAt           *time.Time
	days                      *int64
}

// resolve returns the effective max age and lockout duration, the policy source name, and, when the
// policy is unresolved, the cause (otherwise "").
func (w world8) resolve(u hUser) (maxAge, lock secs, source, why string) {
	const unresolved = "Unknown (policy not resolved)"
	if !w.dom.psosRead {
		return nil, nil, unresolved, "pso_set_not_read"
	}
	if u.uac == nil {
		return nil, nil, unresolved, "account_inputs_not_read"
	}
	eligible := *u.uac&512 == 512 && u.rid != 502 && !strings.HasPrefix(strings.ToLower(u.sam), "krbtgt_")
	if !eligible {
		return w.dom.max, w.dom.lock, "Domain policy", ""
	}
	// the groups the user is in: direct and primary, then transitively through group members
	in := map[string]bool{}
	if u.primary != "" {
		in[u.primary] = true
	}
	for _, g := range w.groups {
		for _, m := range g.members {
			if m == u.guid {
				in[g.guid] = true
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, g := range w.groups {
			for _, m := range g.members {
				if in[m] && !in[g.guid] {
					in[g.guid], changed = true, true
				}
			}
		}
	}
	var direct, viaGroup []psoM
	for _, p := range w.psos {
		for _, t := range p.applies {
			if t == u.guid {
				direct = append(direct, p)
			} else if in[t] {
				viaGroup = append(viaGroup, p)
			}
		}
	}
	cands := direct
	if len(cands) == 0 {
		cands = viaGroup
	}
	if len(cands) == 0 {
		return w.dom.max, w.dom.lock, "Domain policy", ""
	}
	best := cands[0]
	for _, p := range cands[1:] {
		switch {
		case p.prec == nil && best.prec != nil:
			best = p
		case p.prec != nil && best.prec != nil && *p.prec < *best.prec:
			best = p
		case (p.prec == nil) == (best.prec == nil) && (p.prec == nil || *p.prec == *best.prec) &&
			bytes.Compare(wireBytes(p.guid), wireBytes(best.guid)) < 0:
			best = p
		}
	}
	if !best.stored {
		return nil, nil, unresolved, "pso_not_read"
	}
	if best.prec == nil {
		return nil, nil, unresolved, "pso_precedence_not_read"
	}
	return best.max, best.lock, best.name, ""
}

func (w world8) derive(u hUser, now time.Time) derived {
	var d derived
	const unk = report.UnknownInputMissing
	maxAge, lock, src, why := w.resolve(u)
	d.source = src
	// the cause of an interval that is not read: the unresolved cause, else the source that holds it
	intervalWhy := func() string {
		switch {
		case why != "":
			return why
		case src == "Domain policy":
			return "domain_policy_not_read"
		}
		return "pso_interval_not_read"
	}
	d.lockWhy, d.pwdWhy, d.acctWhy = "none", "none", "none"
	trust := u.uac != nil && *u.uac&14336 != 0
	switch {
	case u.uac == nil:
		d.locked, d.lockWhy = unk, "uac_not_read"
	case trust:
		d.locked = "not_applicable"
	case u.read&inventory.ReadLockoutTime == 0:
		d.locked, d.lockWhy = unk, "lockout_time_not_read"
	case u.lockout.IsZero():
		d.locked = "not_locked"
	case lock == nil:
		d.locked, d.lockWhy = unk, intervalWhy()
	case *lock == 0:
		d.locked = "locked"
	default:
		end := u.lockout.Add(time.Duration(*lock) * time.Second)
		d.locked = "not_locked"
		if !now.After(end) {
			d.locked = "locked"
			d.lockEnds = &end
		}
	}
	switch {
	case u.uac == nil:
		d.pwd, d.pwdWhy = unk, "uac_not_read"
	case trust:
		d.pwd = "not_applicable"
	case *u.uac&65536 != 0:
		d.pwd = "never_account_flag"
	case *u.uac&262144 != 0:
		d.pwd = "not_applicable_smartcard"
	case u.read&inventory.ReadPwdLastSet == 0:
		d.pwd, d.pwdWhy = unk, "pwd_last_set_not_read"
	case u.pwdLastSet.IsZero():
		d.pwd = "must_change"
	case maxAge == nil:
		d.pwd, d.pwdWhy = unk, intervalWhy()
	case *maxAge == 0:
		d.pwd = "never_policy"
	default:
		end := u.pwdLastSet.Add(time.Duration(*maxAge) * time.Second)
		d.pwd = "expires"
		if now.After(end) {
			d.pwd = "expired"
		}
		d.pwdAt = &end
		days := int64(math.Floor(end.Sub(now).Seconds() / 86400))
		d.days = &days
	}
	switch {
	case u.read&inventory.ReadAccountExpires == 0:
		d.acct, d.acctWhy = unk, "account_expires_not_read"
	case u.expires.IsZero():
		d.acct = "never"
	case now.After(u.expires):
		d.acct = "expired"
	default:
		d.acct = "not_expired"
	}
	return d
}

func enumOrUnknown(s string) report.Cell {
	if s == report.UnknownInputMissing {
		return report.Unknown()
	}
	return report.EnumCell(s)
}

func timeOrAbsent(t *time.Time) report.Cell {
	if t == nil {
		return report.Absent()
	}
	return report.TimeCell(*t)
}

// cells is the reference row, in the order of rp8Cols.
func (d derived) cells() map[report.ColumnID]report.Cell {
	m := map[report.ColumnID]report.Cell{
		"locked_out":              enumOrUnknown(d.locked),
		"password_state":          enumOrUnknown(d.pwd),
		"account_expired":         enumOrUnknown(d.acct),
		"policy_source":           report.TextCell(d.source),
		"locked_out_reason":       report.EnumCell(d.lockWhy),
		"password_state_reason":   report.EnumCell(d.pwdWhy),
		"account_expired_reason":  report.EnumCell(d.acctWhy),
		"lockout_ends_at":         timeOrAbsent(d.lockEnds),
		"password_expires_at":     timeOrAbsent(d.pwdAt),
		"days_to_password_expiry": report.Absent(),
	}
	if d.days != nil {
		m["days_to_password_expiry"] = report.IntCell(*d.days)
	}
	if d.locked == report.UnknownInputMissing {
		m["lockout_ends_at"] = report.Unknown()
	}
	if d.pwd == report.UnknownInputMissing {
		m["password_expires_at"], m["days_to_password_expiry"] = report.Unknown(), report.Unknown()
	}
	return m
}

var rp8Cols = []report.ColumnID{"sam_account_name", "locked_out", "lockout_ends_at", "password_state", "password_expires_at",
	"days_to_password_expiry", "account_expired", "policy_source", "locked_out_reason", "password_state_reason", "account_expired_reason"}

// seed writes the world: structure, users, groups, PSOs and the domain policy. observed rises with
// each call so a re-seed replaces what the previous scenario wrote.
func (e *env) seed8(t *testing.T, c inventory.ConnectionID, w world8, at time.Time) {
	t.Helper()
	var obs []inventory.Observation
	for _, u := range w.users {
		obs = append(obs, u.obs())
	}
	for _, g := range w.groups {
		obs = append(obs, hGroup(g.guid, g.name, g.rid, g.members...))
	}
	for _, p := range w.psos {
		obs = append(obs, hPSOObj(p.guid, p.name))
	}
	if _, err := e.populate(t, c, at, obs...); err != nil {
		t.Fatalf("seed: %v", err)
	}
	e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
		dp := inventory.DomainPolicy{MaxPwdAge: ivl(w.dom.max), LockoutDuration: ivl(w.dom.lock)}
		if w.dom.psosRead {
			dp.PSOsReadAt = at
		}
		if err := pw.SetDomainPolicy(ctx, tx, c, inventory.GUID(hDom), dp, at); err != nil {
			return err
		}
		for _, p := range w.psos {
			if p.stored {
				err := pw.SetPSO(ctx, tx, c, inventory.GUID(p.guid), inventory.GUID(hDom), inventory.PSO{Precedence: p.prec, MaxPwdAge: ivl(p.max), LockoutDuration: ivl(p.lock)}, at)
				if err != nil {
					return err
				}
			}
			for _, a := range p.applies {
				if err := pw.SetPSOApplies(ctx, tx, c, inventory.GUID(p.guid), inventory.GUID(a), at); err != nil {
					return err
				}
			}
			for _, a := range p.removed {
				if err := pw.SetPSOApplies(ctx, tx, c, inventory.GUID(p.guid), inventory.GUID(a), at); err != nil {
					return err
				}
				if err := pw.RemovePSOApplies(ctx, tx, c, inventory.GUID(p.guid), inventory.GUID(a), at.Add(time.Second)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ivl turns stored seconds back into the codec's interval.
func ivl(s secs) *filetime.Interval {
	switch {
	case s == nil:
		return nil
	case *s == 0:
		return forever()
	}
	return &filetime.Interval{Ticks: *s * 10_000_000}
}

// compare runs the users dataset and checks every row against the reference.
func (e *env) compare8(t *testing.T, reg *reportsql.Registry, c inventory.ConnectionID, w world8, now time.Time, label string) {
	t.Helper()
	res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: rp8Cols, scope: e.scopeNC(c), now: now,
		sort: []report.SortKey{{Column: "sam_account_name", Dir: report.Asc}}})
	byGUID := map[string]hUser{}
	for _, u := range w.users {
		byGUID[strings.ToLower(u.guid)] = u
	}
	if len(res.rows) != len(w.users) {
		t.Fatalf("%s: %d rows, want %d", label, len(res.rows), len(w.users))
	}
	for g, row := range res.rows {
		u := byGUID[g]
		want := w.derive(u, now).cells()
		for _, col := range rp8Cols[1:] {
			if cellKey(row[col]) != cellKey(want[col]) {
				t.Errorf("%s: %s %s = %s, reference %s", label, u.sam, col, cellKey(row[col]), cellKey(want[col]))
			}
		}
	}
}

func (e *env) setDom8(t *testing.T, c inventory.ConnectionID, d domPol, at time.Time) {
	t.Helper()
	e.policyTx(t, func(ctx context.Context, tx store.Tx, pw inventory.PolicyWriter) error {
		dp := inventory.DomainPolicy{MaxPwdAge: ivl(d.max), LockoutDuration: ivl(d.lock)}
		if d.psosRead {
			dp.PSOsReadAt = at
		}
		return pw.SetDomainPolicy(ctx, tx, c, inventory.GUID(hDom), dp, at)
	})
}

const (
	gTie1   = "d1742912-0000-4000-8000-000000000001" // wire bytes 12 29 74 d1 …
	gTie2   = "7b41e54e-0000-4000-8000-000000000002" // wire bytes 4e e5 41 7b … (text order puts it first)
	uacDont = uacNormal | 65536
	uacCard = uacNormal | 262144
	uacWks  = 4096 // WORKSTATION_TRUST_ACCOUNT
)

// worldA is the baseline: domain maximum age 42 days, lockout duration 30 minutes. Every user is
// named for the rule it exercises.
func worldA(now time.Time) world8 {
	n := func(k int) string { return hGUID(1, k) }
	g := func(k int) string { return hGUID(2, k) }
	p := func(k int) string { return hGUID(3, k) }
	read := inventory.InputsRead(15)
	u := func(k int, sam string, uac int64, mod func(*hUser)) hUser {
		h := hUser{guid: n(k), sam: sam, rid: uint32(1100 + k), uac: i64(uac), read: read, pwdLastSet: now.Add(-10 * 24 * time.Hour)}
		if mod != nil {
			mod(&h)
		}
		return h
	}
	w := world8{dom: domPol{max: sec(42 * 86400), lock: sec(30 * 60), psosRead: true}}
	w.users = []hUser{
		u(1, "trust", uacNormal|uacWks, func(h *hUser) { h.lockout = now.Add(-time.Minute) }),
		u(2, "dont-expire", uacDont, func(h *hUser) { h.pwdLastSet = time.Time{} }),
		u(3, "smartcard", uacCard, nil),
		u(4, "must-change", uacNormal, func(h *hUser) { h.pwdLastSet = time.Time{} }),
		u(5, "expired", uacNormal, func(h *hUser) { h.pwdLastSet = now.Add(-50 * 24 * time.Hour) }),
		u(6, "expires", uacNormal, nil),
		u(7, "age-edge", uacNormal, func(h *hUser) { h.pwdLastSet = now.Add(-42 * 24 * time.Hour) }),
		u(8, "age-edge-plus", uacNormal, func(h *hUser) { h.pwdLastSet = now.Add(-42*24*time.Hour - time.Second) }),
		u(9, "locked-inside", uacNormal, func(h *hUser) { h.lockout = now.Add(-10 * time.Minute) }),
		u(10, "lock-elapsed", uacNormal, func(h *hUser) { h.lockout = now.Add(-2 * time.Hour) }),
		u(11, "lock-edge", uacNormal, func(h *hUser) { h.lockout = now.Add(-30 * time.Minute) }),
		u(12, "never-locked", uacNormal, nil),
		u(13, "lock-unread", uacNormal, func(h *hUser) { h.read &^= inventory.ReadLockoutTime }),
		u(14, "acct-expired", uacNormal, func(h *hUser) { h.expires = now.Add(-24 * time.Hour) }),
		u(15, "acct-future", uacNormal, func(h *hUser) { h.expires = now.Add(24 * time.Hour) }),
		u(16, "acct-unread", uacNormal, func(h *hUser) { h.read &^= inventory.ReadAccountExpires }),
		u(17, "pwd-unread", uacNormal, func(h *hUser) { h.read &^= inventory.ReadPwdLastSet; h.pwdLastSet = time.Time{} }),
		u(18, "no-uac", 0, func(h *hUser) { h.uac = nil }),
		// PSOs
		u(20, "pso-short", uacNormal, func(h *hUser) { h.pwdLastSet = now.Add(-20 * 24 * time.Hour); h.lockout = now.Add(-10 * time.Minute) }),
		u(21, "group-pso", uacNormal, func(h *hUser) { h.pwdLastSet = now.Add(-20 * 24 * time.Hour) }),
		u(22, "tie", uacNormal, nil),
		u(23, "direct-wins", uacNormal, func(h *hUser) { h.pwdLastSet = now.Add(-20 * 24 * time.Hour) }),
		u(24, "nested", uacNormal, func(h *hUser) { h.pwdLastSet = now.Add(-20 * 24 * time.Hour) }),
		u(25, "primary", uacNormal, func(h *hUser) { h.pwdLastSet = now.Add(-20 * 24 * time.Hour); h.primary = g(4) }),
		u(26, "krbtgt", uacNormal|2, func(h *hUser) { h.rid = 502; h.pwdLastSet = now.Add(-20 * 24 * time.Hour) }),
		u(27, "no-precedence", uacNormal, nil),
		u(28, "pso-unread", uacNormal, nil),
		u(29, "edge-removed", uacNormal, func(h *hUser) { h.pwdLastSet = now.Add(-20 * 24 * time.Hour) }),
		u(30, "pso-forever", uacNormal, func(h *hUser) { h.pwdLastSet = now.Add(-400 * 24 * time.Hour); h.lockout = now.Add(-24 * time.Hour) }),
		u(31, "krbtgt-rodc", uacNormal, func(h *hUser) { h.sam = "krbtgt_1234"; h.pwdLastSet = now.Add(-20 * 24 * time.Hour) }),
	}
	w.groups = []grpM{
		{guid: g(1), name: "GroupPSO", rid: 2001, members: []string{n(21)}},
		{guid: g(2), name: "Inner", rid: 2002, members: []string{n(24)}},
		{guid: g(3), name: "Outer", rid: 2003, members: []string{g(2)}},
		{guid: g(4), name: "Primary", rid: 2004},
		{guid: g(5), name: "DirectLoses", rid: 2005, members: []string{n(23)}},
	}
	w.psos = []psoM{
		{guid: p(1), name: "PSO-short", prec: i64(1), max: sec(10 * 86400), lock: sec(5 * 60), stored: true, applies: []string{n(20)}},
		{guid: p(2), name: "PSO-group", prec: i64(5), max: sec(15 * 86400), lock: sec(60), stored: true, applies: []string{g(1)}},
		{guid: gTie1, name: "PSO-tie-d174", prec: i64(3), max: sec(5 * 86400), lock: sec(60), stored: true, applies: []string{n(22)}},
		{guid: gTie2, name: "PSO-tie-7b41", prec: i64(3), max: sec(30 * 86400), lock: sec(60), stored: true, applies: []string{n(22)}},
		{guid: p(3), name: "PSO-direct", prec: i64(10), max: sec(5 * 86400), lock: sec(60), stored: true, applies: []string{n(23)}},
		{guid: p(4), name: "PSO-low-prec", prec: i64(1), max: sec(90 * 86400), lock: sec(60), stored: true, applies: []string{g(5)}},
		{guid: p(5), name: "PSO-outer", prec: i64(2), max: sec(10 * 86400), lock: sec(60), stored: true, applies: []string{g(3)}},
		{guid: p(6), name: "PSO-primary", prec: i64(2), max: sec(10 * 86400), lock: sec(60), stored: true, applies: []string{g(4)}},
		{guid: p(7), name: "PSO-krbtgt", prec: i64(1), max: sec(1 * 86400), lock: sec(60), stored: true, applies: []string{n(26), n(31)}},
		{guid: p(8), name: "PSO-no-prec", prec: nil, max: sec(1 * 86400), lock: sec(60), stored: true, applies: []string{n(27)}},
		{guid: p(9), name: "PSO-unread", prec: i64(1), stored: false, applies: []string{n(28)}},
		{guid: p(10), name: "PSO-removed", prec: i64(1), max: sec(5 * 86400), lock: sec(60), stored: true, removed: []string{n(29)}},
		{guid: p(11), name: "PSO-forever", prec: i64(1), max: sec(0), lock: sec(0), stored: true, applies: []string{n(30)}},
	}
	return w
}

// want is one explicit expectation of the baseline world.
type want8 struct {
	user                   string
	locked, pwd, acct, src string
	lockEnds, pwdAt        string // RFC 3339, "" absent
	days                   string // decimal, "" absent
	// why: the reasons of the three states, locked_out / password_state / account_expired; "" is "none"
	why [3]string
}

func Test_derived_columns_match_reference(t *testing.T) {
	storetest.EachVersion(t, func(t *testing.T, s *storetest.Server) {
		e := setup(t, s)
		reg := e.registry(t)
		e.hStructure(t, e.adA)
		now := hBase.Add(100 * 24 * time.Hour)
		at := now.Add(-time.Hour)
		w := worldA(now)
		e.seed8(t, e.adA, w, at)

		// Spec §6.4 rows 1-7, lockout, PSO resolution: each case states its expected result outright, so
		// the reference above cannot agree with the SQL about a wrong rule.
		const unk = report.UnknownInputMissing
		f := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
		day := 24 * time.Hour
		explicit := []want8{
			{user: "trust", locked: "not_applicable", pwd: "not_applicable", acct: "never", src: "Domain policy"},
			{user: "dont-expire", locked: "not_locked", pwd: "never_account_flag", acct: "never", src: "Domain policy"},
			{user: "smartcard", locked: "not_locked", pwd: "not_applicable_smartcard", acct: "never", src: "Domain policy"},
			{user: "must-change", locked: "not_locked", pwd: "must_change", acct: "never", src: "Domain policy"},
			{user: "expired", locked: "not_locked", pwd: "expired", acct: "never", src: "Domain policy", pwdAt: f(-8 * day), days: "-8"},
			{user: "expires", locked: "not_locked", pwd: "expires", acct: "never", src: "Domain policy", pwdAt: f(32 * day), days: "32"},
			{user: "age-edge", locked: "not_locked", pwd: "expires", acct: "never", src: "Domain policy", pwdAt: f(0), days: "0"},
			{user: "age-edge-plus", locked: "not_locked", pwd: "expired", acct: "never", src: "Domain policy", pwdAt: f(-time.Second), days: "-1"},
			{user: "locked-inside", locked: "locked", pwd: "expires", acct: "never", src: "Domain policy", lockEnds: f(20 * time.Minute), pwdAt: f(32 * day), days: "32"},
			{user: "lock-elapsed", locked: "not_locked", pwd: "expires", acct: "never", src: "Domain policy", pwdAt: f(32 * day), days: "32"},
			{user: "lock-edge", locked: "locked", pwd: "expires", acct: "never", src: "Domain policy", lockEnds: f(0), pwdAt: f(32 * day), days: "32"},
			{user: "never-locked", locked: "not_locked", pwd: "expires", acct: "never", src: "Domain policy", pwdAt: f(32 * day), days: "32"},
			{user: "lock-unread", why: [3]string{"lockout_time_not_read"}, locked: unk, pwd: "expires", acct: "never", src: "Domain policy", pwdAt: f(32 * day), days: "32"},
			{user: "acct-expired", locked: "not_locked", pwd: "expires", acct: "expired", src: "Domain policy", pwdAt: f(32 * day), days: "32"},
			{user: "acct-future", locked: "not_locked", pwd: "expires", acct: "not_expired", src: "Domain policy", pwdAt: f(32 * day), days: "32"},
			{user: "acct-unread", why: [3]string{2: "account_expires_not_read"}, locked: "not_locked", pwd: "expires", acct: unk, src: "Domain policy", pwdAt: f(32 * day), days: "32"},
			{user: "pwd-unread", why: [3]string{1: "pwd_last_set_not_read"}, locked: "not_locked", pwd: unk, acct: "never", src: "Domain policy"},
			{user: "no-uac", why: [3]string{"uac_not_read", "uac_not_read"}, locked: unk, pwd: unk, acct: "never", src: "Unknown (policy not resolved)"},
			// a PSO with a shorter age expires earlier than the domain policy would say
			{user: "pso-short", locked: "not_locked", pwd: "expired", acct: "never", src: "PSO-short", pwdAt: f(-10 * day), days: "-10"},
			{user: "group-pso", locked: "not_locked", pwd: "expired", acct: "never", src: "PSO-group", pwdAt: f(-5 * day), days: "-5"},
			{user: "tie", locked: "not_locked", pwd: "expired", acct: "never", src: "PSO-tie-d174", pwdAt: f(-5 * day), days: "-5"},
			{user: "direct-wins", locked: "not_locked", pwd: "expired", acct: "never", src: "PSO-direct", pwdAt: f(-15 * day), days: "-15"},
			{user: "nested", locked: "not_locked", pwd: "expired", acct: "never", src: "PSO-outer", pwdAt: f(-10 * day), days: "-10"},
			{user: "primary", locked: "not_locked", pwd: "expired", acct: "never", src: "PSO-primary", pwdAt: f(-10 * day), days: "-10"},
			{user: "krbtgt", locked: "not_locked", pwd: "expires", acct: "never", src: "Domain policy", pwdAt: f(22 * day), days: "22"},
			{user: "krbtgt_1234", locked: "not_locked", pwd: "expires", acct: "never", src: "Domain policy", pwdAt: f(22 * day), days: "22"},
			{user: "no-precedence", why: [3]string{1: "pso_precedence_not_read"}, locked: "not_locked", pwd: unk, acct: "never", src: "Unknown (policy not resolved)"},
			{user: "pso-unread", why: [3]string{1: "pso_not_read"}, locked: "not_locked", pwd: unk, acct: "never", src: "Unknown (policy not resolved)"},
			{user: "edge-removed", locked: "not_locked", pwd: "expires", acct: "never", src: "Domain policy", pwdAt: f(22 * day), days: "22"},
			{user: "pso-forever", locked: "locked", pwd: "never_policy", acct: "never", src: "PSO-forever"},
		}
		res := e.run(t, reg, hQuery{dataset: inventory.DatasetUsers, cols: rp8Cols, scope: e.scopeNC(e.adA), now: now})
		bySam := map[string]map[report.ColumnID]report.Cell{}
		for _, r := range res.rows {
			bySam[string(r["sam_account_name"].DigestValue())] = r
		}
		if len(bySam) != len(w.users) {
			t.Fatalf("%d rows for %d users", len(bySam), len(w.users))
		}
		en := func(s string) string { return cellKey(enumOrUnknown(s)) }
		tm := func(s string, unknown bool) string {
			switch {
			case unknown:
				return cellKey(report.Unknown())
			case s == "":
				return cellKey(report.Absent())
			}
			v, _ := time.Parse(time.RFC3339, s)
			return cellKey(report.TimeCell(v))
		}
		reason := func(w string) string {
			if w == "" {
				w = "none"
			}
			return cellKey(report.EnumCell(w))
		}
		for _, x := range explicit {
			r := bySam[x.user]
			if r == nil {
				t.Errorf("%s: no row", x.user)
				continue
			}
			days := cellKey(report.Absent())
			if x.days != "" {
				n, _ := strconv.ParseInt(x.days, 10, 64)
				days = cellKey(report.IntCell(n))
			}
			if x.pwd == unk {
				days = cellKey(report.Unknown())
			}
			checks := []struct {
				col  report.ColumnID
				want string
			}{
				{"locked_out", en(x.locked)}, {"password_state", en(x.pwd)}, {"account_expired", en(x.acct)},
				{"policy_source", cellKey(report.TextCell(x.src))},
				{"locked_out_reason", reason(x.why[0])}, {"password_state_reason", reason(x.why[1])}, {"account_expired_reason", reason(x.why[2])},
				{"lockout_ends_at", tm(x.lockEnds, x.locked == unk)},
				{"password_expires_at", tm(x.pwdAt, x.pwd == unk)}, {"days_to_password_expiry", days},
			}
			for _, c := range checks {
				if got := cellKey(r[c.col]); got != c.want {
					t.Errorf("%s: %s = %s, want %s", x.user, c.col, got, c.want)
				}
			}
		}
		e.compare8(t, reg, e.adA, w, now, "baseline")

		// The reference is also checked at moving clocks, so a boundary rule cannot hide behind one now.
		for _, d := range []time.Duration{-90 * day, -time.Second, 0, time.Millisecond, time.Second, 7 * day, 43 * day, 500 * day} {
			e.compare8(t, reg, e.adA, w, now.Add(d), "now"+d.String())
		}

		// Domain policy variants: forever, unset (not read), PSO set never read.
		step := at
		for _, v := range []struct {
			name string
			d    domPol
		}{
			{"forever", domPol{max: sec(0), lock: sec(0), psosRead: true}},
			{"unset", domPol{psosRead: true}},
			{"psos-unread", domPol{max: sec(42 * 86400), lock: sec(1800)}},
			{"short", domPol{max: sec(86400), lock: sec(1), psosRead: true}},
		} {
			step = step.Add(time.Minute)
			e.setDom8(t, e.adA, v.d, step)
			w.dom = v.d
			e.compare8(t, reg, e.adA, w, now, "domain-"+v.name)
		}
	})
}
