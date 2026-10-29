// Package main is `fitness-built-msi` (T-0697): the other half of ADR-0006 A1. The source scan
// (tools/fitness/agenthost) cannot see WiX that is generated at build time (MSBuild Exec/UsingTask inline
// tasks, a WixExtension or PackageReference that emits a ServiceInstall, a Compile Include outside the
// repo), so after the build this check opens the MSI itself and judges the tables the Windows installer
// will actually execute: ServiceInstall, MsiServiceConfig, CustomAction, Binary, MsiLockPermissionsEx,
// LockPermissions, Registry and RemoveRegistry. The MSI is dumped with `msidump` (msitools, LGPL-2.1+,
// CI tooling only, never shipped); the judge reads the .idt files, so it is tested without an MSI.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	AgentService    = "activeDIQAgent"
	AgentAccount    = `NT SERVICE\activeDIQAgent`
	PinnedPrivilege = "SeChangeNotifyPrivilege"
	sidRestricted   = "3"
	cfgSID          = "3" // SERVICE_CONFIG_SERVICE_SID_INFO
	cfgPrivs        = "4" // SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO
)

// Table is one imported .idt table.
type Table struct {
	Cols []string
	Rows [][]string
	Keys []string // primary key column names
}

// Col returns the value of column name in row r ("" when absent).
func (t *Table) Col(r []string, name string) string {
	for i, c := range t.Cols {
		if strings.EqualFold(c, name) && i < len(r) {
			return r[i]
		}
	}
	return ""
}

// Key renders the primary key of a row for messages.
func (t *Table) Key(r []string) string {
	var ks []string
	for _, k := range t.Keys {
		ks = append(ks, t.Col(r, k))
	}
	return strings.Join(ks, "/")
}

// LoadIDT parses an msidump .idt file: column names, column types, "Table<TAB>pk...", then rows.
func LoadIDT(path string) (string, *Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var lines []string
	for sc.Scan() {
		lines = append(lines, strings.TrimSuffix(sc.Text(), "\r"))
	}
	if err := sc.Err(); err != nil {
		return "", nil, err
	}
	if len(lines) < 3 {
		return "", nil, fmt.Errorf("%s: not an idt file (fewer than 3 header lines)", path)
	}
	lines[0] = strings.TrimPrefix(lines[0], "\ufeff")
	hdr := strings.Split(lines[2], "\t")
	t := &Table{Cols: strings.Split(lines[0], "\t"), Keys: hdr[1:]}
	for _, l := range lines[3:] {
		if l == "" {
			continue
		}
		t.Rows = append(t.Rows, strings.Split(l, "\t"))
	}
	return hdr[0], t, nil
}

// LoadDir reads every .idt in dir.
func LoadDir(dir string) (map[string]*Table, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.idt"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no .idt files (msidump produced nothing)", dir)
	}
	out := map[string]*Table{}
	for _, f := range files {
		name, t, err := LoadIDT(f)
		if err != nil {
			return nil, err
		}
		out[name] = t
	}
	return out, nil
}

// Pinned is one reviewed CustomAction as it appears in the CustomAction table.
type Pinned struct{ Type, Source, Target string }

// ParsePinned reads pinned-actions.txt.
func ParsePinned(s string) map[string]Pinned {
	m := map[string]Pinned{}
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, "\r")
		if strings.HasPrefix(strings.TrimSpace(l), "#") || strings.TrimSpace(l) == "" {
			continue
		}
		f := strings.SplitN(l, "\t", 4)
		if len(f) == 4 {
			m[f[0]] = Pinned{f[1], f[2], f[3]}
		}
	}
	return m
}

// Options configures Judge.
type Options struct {
	Pinned       map[string]Pinned // reviewed CustomActions
	Allow        []string          // installer-allow.txt: reviewed CustomAction Ids and permission parents
	RequireAgent bool              // the MSI must install the agent service exactly once
}

func allowed(allow []string, id string) bool {
	for _, a := range allow {
		if a == id {
			return true
		}
	}
	return false
}

func dynamic(s string) bool { return strings.ContainsAny(s, "[]") || strings.Contains(s, "!(") }

// actionFlags renders a CustomAction Type so a reviewer sees what the number means.
func actionFlags(typ string) string {
	n, err := strconv.Atoi(typ)
	if err != nil {
		return typ
	}
	kinds := map[int]string{1: "dll-from-binary", 2: "exe-from-binary", 5: "jscript-from-binary", 6: "vbscript-from-binary", 17: "dll-from-file", 18: "exe-from-file", 21: "jscript-from-file", 22: "vbscript-from-file", 34: "exe-from-directory", 35: "set-directory", 37: "jscript-text", 38: "vbscript-text", 50: "exe-from-property", 51: "set-property"}
	k, ok := kinds[n&0x3f]
	if !ok {
		k = fmt.Sprintf("kind %d", n&0x3f)
	}
	var f []string
	for _, b := range []struct {
		bit  int
		name string
	}{{64, "continue"}, {128, "async"}, {256, "rollback/first-sequence"}, {512, "commit/once"}, {1024, "in-script"}, {2048, "no-impersonate"}} {
		if n&b.bit != 0 {
			f = append(f, b.name)
		}
	}
	return k + " " + strings.Join(f, "+")
}

// Judge returns one violation string per problem; each names the table and row.
func Judge(t map[string]*Table, o Options) []string {
	var v []string
	fail := func(f string, a ...any) { v = append(v, fmt.Sprintf(f, a...)) }

	si := t["ServiceInstall"]
	services := map[string]bool{} // lower-case literal service names installed by this MSI
	agents := 0
	if si != nil {
		for _, r := range si.Rows {
			key, name, acct := si.Key(r), si.Col(r, "Name"), si.Col(r, "StartName")
			services[strings.ToLower(name)] = true
			if dynamic(name) {
				fail("ServiceInstall row %q: service Name %q is formatted at install time and cannot be judged", key, name)
			}
			if strings.EqualFold(name, AgentService) {
				agents++
				if name != AgentService {
					fail("ServiceInstall row %q: agent service Name is %q, must be exactly %q", key, name, AgentService)
				}
			}
			want := `NT SERVICE\` + name
			if strings.EqualFold(name, AgentService) {
				want = AgentAccount
			}
			switch {
			case acct == "":
				fail("ServiceInstall row %q (service %s): StartName is empty, so the service runs as LocalSystem; it must be %q", key, name, want)
			case !strings.EqualFold(acct, want):
				fail("ServiceInstall row %q (service %s): StartName is %q, not the pinned %q", key, name, acct, want)
			}
			if st, err := strconv.Atoi(si.Col(r, "ServiceType")); err != nil || st != 16 {
				fail("ServiceInstall row %q (service %s): ServiceType is %q, must be 16 (own process); shared-process or interactive services leave the reviewed model", key, name, si.Col(r, "ServiceType"))
			}
			if ec, err := strconv.Atoi(si.Col(r, "ErrorControl")); err != nil || ec&0xff > 1 {
				fail("ServiceInstall row %q (service %s): ErrorControl is %q, must be 0 or 1 (optionally with the 0x8000 vital bit); critical (3) can stop a domain controller booting", key, name, si.Col(r, "ErrorControl"))
			}
			if p := si.Col(r, "Password"); p != "" {
				fail("ServiceInstall row %q (service %s): has a Password; a virtual service account has none", key, name)
			}
		}
	}
	if o.RequireAgent && agents != 1 {
		fail("ServiceInstall: %d rows install service %s, want exactly 1 (the pinned account cannot be judged otherwise)", agents, AgentService)
	}

	// MsiServiceConfig: SID type and privileges, per installed service and for any other service named.
	type cfg struct{ sid, priv []string }
	siComps := map[string]map[string]bool{} // service -> Component_ ids that install it
	if si != nil {
		for _, r := range si.Rows {
			n, c := strings.ToLower(si.Col(r, "Name")), si.Col(r, "Component_")
			if siComps[n] == nil {
				siComps[n] = map[string]bool{}
			}
			siComps[n][c] = true
			if cond := componentCondition(t, c); cond != "" {
				fail("ServiceInstall row %q (service %s): component %q has Condition %q; a conditional install cannot be judged", si.Key(r), si.Col(r, "Name"), c, cond)
			}
		}
	}
	got := map[string]*cfg{}
	if mc := t["MsiServiceConfig"]; mc != nil {
		for _, r := range mc.Rows {
			key, name, typ, arg := mc.Key(r), mc.Col(r, "Name"), mc.Col(r, "ConfigType"), mc.Col(r, "Argument")
			if typ == cfgSID || typ == cfgPrivs {
				if ev, err := strconv.Atoi(mc.Col(r, "Event")); err != nil || ev&1 == 0 {
					fail("MsiServiceConfig row %q (service %s): Event %q does not apply on install (bit 1), so the setting never takes effect", key, name, mc.Col(r, "Event"))
					continue
				}
				if !siComps[strings.ToLower(name)][mc.Col(r, "Component_")] {
					fail("MsiServiceConfig row %q (service %s): Component_ %q is not the component that installs the service, so the setting may never apply", key, name, mc.Col(r, "Component_"))
					continue
				}
			}
			if dynamic(name) {
				fail("MsiServiceConfig row %q: service Name %q is formatted at install time and cannot be judged", key, name)
			}
			ln := strings.ToLower(name)
			if got[ln] == nil {
				got[ln] = &cfg{}
			}
			switch typ {
			case cfgSID:
				got[ln].sid = append(got[ln].sid, arg)
				if arg != sidRestricted {
					fail("MsiServiceConfig row %q (service %s): SID type is %q, must be 3 (restricted)", key, name, arg)
				}
			case cfgPrivs:
				ps := splitPrivs(arg)
				got[ln].priv = append(got[ln].priv, strings.Join(ps, ","))
				if len(ps) != 1 || ps[0] != PinnedPrivilege {
					fail("MsiServiceConfig row %q (service %s): RequiredPrivileges are %q, must be exactly %s", key, name, strings.Join(ps, ","), PinnedPrivilege)
				}
			}
			if dynamic(arg) && (typ == cfgSID || typ == cfgPrivs) && !strings.Contains(arg, "[~]") {
				fail("MsiServiceConfig row %q (service %s): Argument %q is formatted at install time", key, name, arg)
			}
		}
	}
	if si != nil {
		names := make([]string, 0, len(services))
		for n := range services {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			c := got[n]
			if c == nil || len(c.sid) == 0 {
				fail("ServiceInstall service %s: no MsiServiceConfig row of ConfigType 3 sets a restricted SID (the default is an unrestricted service SID)", n)
			}
			if c == nil || len(c.priv) == 0 {
				fail("ServiceInstall service %s: no MsiServiceConfig row of ConfigType 4 pins RequiredPrivileges to %s", n, PinnedPrivilege)
			}
		}
	}
	if t["ServiceConfig"] != nil && len(t["ServiceConfig"].Rows) > 0 {
		fail("ServiceConfig table (util extension) has %d row(s): its custom action applies service settings this check does not model", len(t["ServiceConfig"].Rows))
	}

	if ca := t["CustomAction"]; ca != nil {
		for _, r := range ca.Rows {
			id, typ, src, tgt := ca.Key(r), ca.Col(r, "Type"), ca.Col(r, "Source"), ca.Col(r, "Target")
			p, ok := o.Pinned[id]
			switch {
			case !ok || !allowed(o.Allow, id):
				fail("CustomAction row %q (%s, Source %q, Target %q): not a reviewed action; the installer allows only the pinned set (T-0688 ruling 4)", id, actionFlags(typ), src, tgt)
			case p.Type != typ || p.Source != src || p.Target != tgt:
				fail("CustomAction row %q: Type %s (%s) Source %q Target %q differ from the reviewed Type %s Source %q Target %q", id, typ, actionFlags(typ), src, tgt, p.Type, p.Source, p.Target)
			}
		}
	}
	if b := t["Binary"]; b != nil {
		for _, r := range b.Rows {
			fail("Binary row %q: the installer embeds no binary (a custom action DLL or script payload would run in the install)", b.Key(r))
		}
	}
	// No permission row is reviewed today. installer-allow.txt holds CustomAction Ids and must never vouch
	// for a DACL: MSI keys are per table, so a generated ServiceInstall with a reviewed action's Id would
	// otherwise pass. A future reviewed DACL needs its own pin keyed by (Table, LockObject) with the exact
	// SDDL pinned (security-architect, T-0697).
	for _, name := range []string{"MsiLockPermissionsEx", "LockPermissions"} {
		if lp := t[name]; lp != nil {
			for _, r := range lp.Rows {
				fail("%s row %q: DACL on %s %q (%s) is not reviewed; the installer sets no permissions (a ServiceInstall DACL is the service-control bypass)", name, lp.Key(r), lp.Col(r, "Table"), lp.Col(r, "LockObject"), lp.Col(r, "SDDLText"))
			}
		}
	}
	judgeBehaviourTables(t, fail)
	for _, name := range []string{"Registry", "RemoveRegistry"} {
		if rg := t[name]; rg != nil {
			for _, r := range rg.Rows {
				root, key := rg.Col(r, "Root"), rg.Col(r, "Key")
				if root != "2" && root != "-1" {
					continue
				}
				trim := strings.ToLower(strings.TrimLeft(key, `\/ `))
				if strings.HasPrefix(trim, `system\`) || trim == "system" || dynamic(key) {
					fail("%s row %q: writes HKLM key %q; nothing under HKLM\\SYSTEM (service account, SID type, privileges) and no key built from a property", name, rg.Key(r), key)
				}
			}
		}
	}
	return v
}

func splitPrivs(arg string) []string {
	arg = strings.ReplaceAll(arg, "[~]", "\x00")
	var out []string
	for _, p := range strings.Split(arg, "\x00") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// componentCondition returns the Component.Condition of component id ("" when none or no Component table).
func componentCondition(t map[string]*Table, id string) string {
	ct := t["Component"]
	if ct == nil {
		return ""
	}
	for _, r := range ct.Rows {
		if ct.Col(r, "Component") == id {
			return strings.TrimSpace(ct.Col(r, "Condition"))
		}
	}
	return ""
}

// judgeBehaviourTables fails rows in tables that run code or change service behaviour outside the
// ServiceInstall/MsiServiceConfig model: deny by default, with the agent's own ServiceControl the only
// exception and failure actions limited to none/restart-service.
func judgeBehaviourTables(t map[string]*Table, fail func(string, ...any)) {
	if tb := t["SelfReg"]; tb != nil {
		for _, r := range tb.Rows {
			fail("SelfReg row %q: SelfRegModules calls DllRegisterServer in the elevated installer, an unreviewed custom action by another name", tb.Key(r))
		}
	}
	for _, name := range []string{"MsiEmbeddedChainer", "MsiEmbeddedUI"} {
		if tb := t[name]; tb != nil {
			for _, r := range tb.Rows {
				fail("%s row %q: runs an executable or DLL during install, an unreviewed custom action by another name", name, tb.Key(r))
			}
		}
	}
	if fa := t["MsiServiceConfigFailureActions"]; fa != nil {
		for _, r := range fa.Rows {
			key, cmd, acts := fa.Key(r), fa.Col(r, "Command"), fa.Col(r, "Actions")
			if cmd != "" {
				fail("MsiServiceConfigFailureActions row %q: Command %q would run on service failure", key, cmd)
			}
			if dynamic(strings.ReplaceAll(acts, "[~]", "")) {
				fail("MsiServiceConfigFailureActions row %q: Actions %q is formatted at install time", key, acts)
				continue
			}
			for _, a := range strings.Split(acts, "[~]") {
				if a = strings.TrimSpace(a); a != "" && a != "0" && a != "1" {
					fail("MsiServiceConfigFailureActions row %q: failure action %q (2 reboots the host, 3 runs a command); only none(0) and restart-service(1) are allowed", key, a)
				}
			}
		}
	}
	if sc := t["ServiceControl"]; sc != nil {
		for _, r := range sc.Rows {
			if n := sc.Col(r, "Name"); n != AgentService {
				fail("ServiceControl row %q: controls service %q; only %s may be started, stopped or deleted by this installer", sc.Key(r), n, AgentService)
			}
		}
	}
}
