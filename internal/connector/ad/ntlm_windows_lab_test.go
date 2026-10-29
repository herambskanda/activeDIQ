//go:build lab && windowslab

package ad

import "testing"

// TM-F-NTLM against the Windows DC: same dial-recording proof as the Samba lab. Events 4776 and
// 8001-8004 and the network capture on the attacker host are collected from the lab per
// windows-lab.md §5 (they cannot be read from Go here).
func TestWindowsLabNoSideDialOnPlantedUNC(t *testing.T) {
	env := winEnv(t)
	cfg := winConfig(t, env["WIN_LAB_SVC_PASSWORD"], true)
	roots := cfg.RootCAs
	proveNoSideDial(t, cfg, cfg.Servers[0], "Administrator@win.activediq.test", env["WIN_LAB_ADMIN_PASSWORD"], winBase, roots)
}
