//go:build lab

package read_test

import (
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
	connectorv1 "github.com/skenzeriq/activediq/internal/proto/activediq/connector/v1"
)

// T-1719 AC1: printQueue objects under two server computer objects in two OUs, read through the real
// ScopedSearch handler and mapped. Each stored attribute equals an administrator's own LDAP read, the kind is
// printqueue, and the parent of each queue is its server. Samba proves the LDAP side; it cannot prove that a
// Windows server's own publication or its removal of an unreachable server's entries (a Windows lab ticket).
//
//	make lab-up && go test -tags lab ./internal/connector/read -run TestLabPrinters
func TestLabPrinters(t *testing.T) {
	l := newSearchLab(t)
	root := "OU=printers-" + l.stamp + "," + labDom
	l.add(t, root, map[string][]string{"objectClass": {"organizationalUnit"}})
	t.Cleanup(func() { l.delTree(root) })
	ouA, ouB := "OU=Site A, East "+l.stamp+","+root, "OU=Site B "+l.stamp+","+root
	ouA = strings.Replace(ouA, ", ", "\\, ", 1) // a comma in an OU name
	for _, ou := range []string{ouA, ouB} {
		l.add(t, ou, map[string][]string{"objectClass": {"organizationalUnit"}})
	}
	srvA, srvB := "CN=PRTA"+l.stamp+","+ouA, "CN=PRTB"+l.stamp+","+ouB
	l.add(t, srvA, map[string][]string{"objectClass": {"computer"}, "sAMAccountName": {"PRTA" + l.stamp + "$"}})
	l.add(t, srvB, map[string][]string{"objectClass": {"computer"}, "sAMAccountName": {"PRTB" + l.stamp + "$"}})
	pq := func(srv, name, server string, extra map[string][]string) string {
		dn := "CN=" + name + "," + srv
		a := map[string][]string{"objectClass": {"printQueue"}, "printerName": {name}, "serverName": {server}, "shortServerName": {strings.Split(server, ".")[0]},
			"uNCName": {`\\` + server + `\` + name}, "versionNumber": {"4"}}
		for k, v := range extra {
			a[k] = v
		}
		l.add(t, dn, a)
		return dn
	}
	full := pq(srvA, "Ünï "+l.stamp, "prta.lab.test", map[string][]string{"printShareName": {"unishare"}, "location": {"HQ/2/East"},
		"description": {"Colour laser"}, "driverName": {"HP Universal"}, "printColor": {"TRUE"}, "printDuplexSupported": {"FALSE"}})
	bare := pq(srvB, "bare"+l.stamp, "prtb.lab.test", nil)

	m, err := dirsync.NewMapper(dirsync.Config{NC: inventory.GUID(guidText(t, l.guid(t, labDom)))})
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := rpc(t, l.client, l.request(l.guid(t, root), connectorv1.SearchDepth_SEARCH_DEPTH_SUBTREE, "printQueue", m.Attributes()...))
	if err != nil {
		t.Fatalf("ScopedSearch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("read %d printQueue objects, want 2", len(got))
	}
	srvGUID := map[string]string{strings.ToLower(srvA): guidText(t, l.guid(t, srvA)), strings.ToLower(srvB): guidText(t, l.guid(t, srvB))}
	for _, e := range got {
		mapped, err := m.Map(e)
		if err != nil {
			t.Fatalf("Map %s: %v", e.GetDn().GetDisplayDn(), err)
		}
		o := mapped.Observation
		dn := e.GetDn().GetDisplayDn()
		if o.Kind != inventory.KindPrintQueue {
			t.Errorf("%s kind = %s", dn, o.Kind)
		}
		r, err := l.adm.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)",
			[]string{"printerName", "serverName", "uNCName", "printShareName", "location", "description", "driverName", "printColor", "printDuplexSupported"}, nil))
		if err != nil || len(r.Entries) != 1 {
			t.Fatalf("LDAP read of %s: %v", dn, err)
		}
		ld := r.Entries[0]
		for _, k := range []string{"printerName", "serverName", "uNCName", "printShareName", "location", "description", "driverName"} {
			g, _ := o.Attributes[k].(string)
			if want := ld.GetAttributeValue(k); g != want {
				t.Errorf("%s: %s = %q, LDAP says %q", dn, k, g, want)
			}
		}
		for _, k := range []string{"printColor", "printDuplexSupported"} {
			b, has := o.Attributes[k].(bool)
			ldv := ld.GetAttributeValue(k)
			if has != (ldv != "") || (has && b != strings.EqualFold(ldv, "TRUE")) {
				t.Errorf("%s: %s = %v/%v, LDAP says %q", dn, k, b, has, ldv)
			}
		}
		parent := strings.ToLower(strings.SplitN(dn, ",", 2)[1])
		if !strings.EqualFold(dn, full) && !strings.EqualFold(dn, bare) {
			t.Errorf("unexpected printQueue %s", dn)
		}
		for sdn, g := range srvGUID {
			if strings.EqualFold(parent, sdn) && string(o.Parent) != g {
				t.Errorf("%s parent = %s, want its server %s", dn, o.Parent, g)
			}
		}
	}
}
