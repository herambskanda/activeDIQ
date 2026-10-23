package ad

import (
	"fmt"
	"strings"

	"internal/directory/dn"
)

func send(string) {}

type wrap struct{ v any }

func bad(d dn.DN, p *dn.DN) {
	send(d.String())           // want `reference to dn.DN.String in the connector`
	send(string(d.Render()))   // want `reference to dn.DN.Render in the connector` `conversion of a DNString`
	_ = p.String()             // want `reference to dn.DN.String in the connector`
	_ = fmt.Sprint(d.Render()) // want `reference to dn.DN.Render in the connector`
}

func bypasses(d dn.DN) (any, error) {
	send(fmt.Sprint(d))         // want `converted to an interface`
	send(fmt.Sprintf("%s", &d)) // want `converted to an interface`
	f := d.String               // want `reference to dn.DN.String in the connector`
	send(f())
	g := dn.DN.String // want `reference to dn.DN.String in the connector`
	send(g(d))
	var s fmt.Stringer = d // want `converted to an interface`
	send(s.String())
	_ = fmt.Errorf("%v", d) // want `converted to an interface`
	_ = wrap{v: d}          // want `converted to an interface`
	_ = []any{d}            // want `converted to an interface`
	_ = any(d)              // want `converted to an interface`
	return d, nil           // want `converted to an interface`
}

func dnString(x dn.DNString, ou string) bool {
	send(string(x))                         // want `conversion of a DNString`
	_ = []byte(x)                           // want `conversion of a DNString`
	return strings.HasSuffix(string(x), ou) // want `conversion of a DNString`
}

func good(d dn.DN) error {
	s, err := dn.DNRef(d).ForRequest()
	send(s)
	return err
}

type embed struct {
	dn.DN
	n int
}

type holder struct{ D dn.DN }

func stringify[T fmt.Stringer](t T) string { return t.String() }
func show[T any](t T) string               { return fmt.Sprint(t) }

func more(d dn.DN, ds []dn.DN) {
	send(fmt.Sprint(embed{DN: d}))    // want `converted to an interface`
	var s fmt.Stringer = embed{DN: d} // want `converted to an interface`
	send(s.String())
	send(stringify(d))             // want `converted to an interface`
	send(show(d))                  // want `converted to an interface`
	send(fmt.Sprint(ds))           // want `converted to an interface`
	send(fmt.Sprint(holder{D: d})) // want `converted to an interface`
}
