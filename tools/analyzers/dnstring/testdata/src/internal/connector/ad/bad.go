package ad

import (
	"fmt"

	"internal/directory/dn"
)

func send(string) {}

func bad(d dn.DN, p *dn.DN) {
	send(d.String())           // want `dn.DN.String in the connector`
	send(string(d.Render()))   // want `dn.DN.Render in the connector`
	_ = p.String()             // want `dn.DN.String in the connector`
	_ = fmt.Sprint(d.Render()) // want `dn.DN.Render in the connector`
}

func good(d dn.DN) error {
	s, err := dn.DNRef(d).ForRequest()
	send(s)
	return err
}
