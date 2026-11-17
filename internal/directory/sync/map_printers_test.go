package sync_test

import (
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/inventory"
	dirsync "github.com/skenzeriq/activediq/internal/directory/sync"
)

// T-1719: a printQueue is its own kind and its attributes reach the bag; the same attributes on any other class
// (a computer's location) are not read into it; an absent or empty value adds nothing.
func Test_map_printqueue(t *testing.T) {
	m := mapper(dirsync.Config{})
	pq := attrs(nil).classes("top", "leaf", "connectionPoint", "printQueue").
		with("printerName", txt("Floor 2, East")).with("serverName", txt("print1.lab.test")).
		with("uNCName", txt(`\\print1.lab.test\floor2`)).with("printShareName", txt("floor2")).with("location", txt("HQ/2")).
		with("driverName", txt("HP Universal")).with("printColor", boolean(true)).with("printDuplexSupported", boolean(false)).
		with("description", txt("Colour laser"))
	got := mustMap(t, m, entry(90, `CN=print1-Floor 2,CN=PRINT1,OU=People,DC=lab,DC=test`, gid(ouGUID), pq))
	if got.Observation.Kind != inventory.KindPrintQueue || got.Observation.Class != "printQueue" {
		t.Errorf("kind = %s, class = %s", got.Observation.Kind, got.Observation.Class)
	}
	b := got.Observation.Attributes
	for k, want := range map[string]any{"printerName": "Floor 2, East", "serverName": "print1.lab.test", "uNCName": `\\print1.lab.test\floor2`,
		"printShareName": "floor2", "location": "HQ/2", "driverName": "HP Universal", "printColor": true, "printDuplexSupported": false, "description": "Colour laser"} {
		if b[k] != want {
			t.Errorf("%s = %v, want %v", k, b[k], want)
		}
	}
	bare := mustMap(t, m, entry(91, "CN=bare,CN=PRINT1,OU=People,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("printQueue").with("location", txt(""))))
	for _, k := range []string{"printerName", "location", "printColor", "printDuplexSupported", "driverName"} {
		if _, ok := bare.Observation.Attributes[k]; ok {
			t.Errorf("%s is in the bag of an entry with no value", k)
		}
	}
	comp := mustMap(t, m, entry(92, "CN=PC1,OU=People,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("top", "person", "organizationalPerson", "user", "computer").
		with("location", txt("Rack 4")).with("printerName", txt("x"))))
	for _, k := range []string{"location", "printerName"} {
		if _, ok := comp.Observation.Attributes[k]; ok {
			t.Errorf("a computer's %s entered the bag", k)
		}
	}
	// A string where a boolean belongs refuses the entry.
	if _, err := m.Map(entry(93, "CN=odd,CN=PRINT1,OU=People,DC=lab,DC=test", gid(ouGUID), attrs(nil).classes("printQueue").with("printColor", txt("yes")))); err == nil {
		t.Error("a text printColor was accepted")
	}
}

// T-1719 AC4: the closed list gained exactly the printQueue attributes of spec 7.2 (description was on it).
func Test_closed_list_printer_attributes(t *testing.T) {
	have := map[string]bool{}
	for _, a := range dirsync.Attributes() {
		have[strings.ToLower(a)] = true
	}
	for _, a := range []string{"printername", "servername", "uncname", "printsharename", "location", "drivername", "printcolor", "printduplexsupported", "description"} {
		if !have[a] {
			t.Errorf("%s is not on the closed list", a)
		}
	}
}
